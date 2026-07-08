// Package matcher contains the shared, ecosystem-aware vulnerability-matching
// logic used by BOTH the live OSV API path and the local-DB path.
//
// Extracting this here means the live and local matchers produce IDENTICAL
// findings for the same input — a critical correctness property. The only
// difference between the two paths is where the candidate vuln records come
// from (HTTP API vs Postgres); the range evaluation, CVSS scoring, and finding
// construction are identical and live here.
package matcher

import (
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/osvclient"
	pipparser "github.com/sabeel111/Amparo/internal/parser/pip"
)

// RangeEvent is a neutral version-range event (introduced/fixed/last_affected).
type RangeEvent struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Range is a neutral version range with a type (SEMVER/ECOSYSTEM/GIT).
type Range struct {
	Type   string
	Events []RangeEvent
}

// AffectedPackage is a neutral affected-package entry.
type AffectedPackage struct {
	Name      string
	Ecosystem string
	Ranges    []Range
}

// Record is a neutral vuln record that both the live API and local DB decode
// their records into. This decouples matching from the storage/transport types.
type Record struct {
	ID            string
	Aliases       []string
	Summary       string
	CVSSVectors   []string
	Affected      []AffectedPackage
	FixedVersions []string
}

// FindingsForDependency evaluates which of the candidate Records apply to dep,
// returning a Finding for each match (version in an affected range). This is
// the single source of truth for "is this version vulnerable to this record".
func FindingsForDependency(dep model.Dependency, records []Record) []model.Finding {
	var out []model.Finding
	for _, rec := range records {
		f := buildFinding(dep, rec)
		if f != nil {
			out = append(out, *f)
		}
	}
	return out
}

// DedupeFindings collapses findings that describe the SAME vulnerability for the
// SAME dependency version. OSV aggregates advisories from many sources (GHSA,
// CVE, PYSEC, RUSTSEC…) and these cross-reference each other via aliases — so a
// single real-world vuln often yields 2+ OSV records (one primary, others labeled
// "Duplicate Advisory"). Without dedup the user sees the same issue twice.
//
// Rule: two findings are duplicates if they target the same (ecosystem, name,
// version) AND share any identifier — either their vuln_id or any alias.
// When collapsing, we keep the higher-priority one and merge aliases + fixed
// versions so no information is lost. We prefer the record NOT prefixed with
// "Duplicate Advisory" in its summary (OSV's convention for dupes).
func DedupeFindings(findings []model.Finding) []model.Finding {
	if len(findings) < 2 {
		return findings
	}
	// Group by dependency identity. Findings for different packages are never
	// duplicates of each other.
	groups := map[string][]int{} // dependencyKey -> indices into findings
	for i, f := range findings {
		key := depKey(f.Dependency)
		groups[key] = append(groups[key], i)
	}

	kept := make([]bool, len(findings))
	out := make([]model.Finding, 0, len(findings))
	for _, idxs := range groups {
		// Within a dependency group, collapse by shared identifier.
		var chain []int // indices forming one merged finding
		used := map[int]bool{}

		for _, i := range idxs {
			if used[i] {
				continue
			}
			chain = []int{i}
			used[i] = true
			// Collect all identifiers + summaries known so far in this chain.
			ids := idSet(findings[i])
			summaries := map[string]bool{stripDupPrefix(findings[i].Summary): true}
			// Repeatedly scan for findings that share any id OR summary with the chain.
			// The summary check catches OSV "Duplicate Advisory:" records that lack
			// alias links (a known data quirk) — they only link via matching text.
			changed := true
			for changed {
				changed = false
				for _, j := range idxs {
					if used[j] {
						continue
					}
					match := sharesAny(ids, findings[j])
					if !match {
						// Try summary match against any chain member's summary.
						// Catches OSV "Duplicate Advisory:" records lacking alias links.
						js := stripDupPrefix(findings[j].Summary)
						if js != "" && summaries[js] {
							match = true
						}
					}
					if match {
						chain = append(chain, j)
						used[j] = true
						for k := range idSet(findings[j]) {
							ids[k] = true
						}
						summaries[stripDupPrefix(findings[j].Summary)] = true
						changed = true
					}
				}
			}
			out = append(out, mergeChain(findings, chain))
		}
	}
	_ = kept
	return out
}

// depKey is the grouping identity for a dependency (ecosystem+name+version).
func depKey(d model.Dependency) string {
	return string(d.Ecosystem) + "|" + d.Name + "@" + d.Version
}

// idSet returns the set of all identifiers (vuln_id + aliases) for a finding.
func idSet(f model.Finding) map[string]bool {
	out := map[string]bool{f.VulnID: true}
	for _, a := range f.Aliases {
		out[a] = true
	}
	return out
}

// sharesAny reports whether the finding overlaps the given id set, OR is a
// "Duplicate Advisory" of something already in the chain.
//
// OSV's duplicate-advisory records sometimes carry NO aliases linking them to
// the primary record (a known data quirk) — the only signal is a summary like
// "Duplicate Advisory: <same text as the primary>". So in addition to the
// alias-graph check, we detect dupes by: the finding's summary starts with
// "Duplicate Advisory:" AND its tail content matches a chain member's summary.
func sharesAny(ids map[string]bool, f model.Finding) bool {
	if ids[f.VulnID] {
		return true
	}
	for _, a := range f.Aliases {
		if ids[a] {
			return true
		}
	}
	return false
}

// stripDupPrefix removes OSV's "Duplicate Advisory: " prefix so a duplicate
// record's summary can be compared against the primary's summary text. OSV's
// dup records sometimes lack alias links (a known data quirk), so summary text
// is the only signal tying them to the primary record.
func stripDupPrefix(s string) string {
	const p = "Duplicate Advisory: "
	if strings.HasPrefix(s, p) {
		return strings.TrimSpace(strings.TrimPrefix(s, p))
	}
	return strings.TrimSpace(s)
}

// mergeChain picks the representative finding from a dup chain (highest priority,
// non-"Duplicate Advisory" preferred) and merges aliases + fixed versions in.
func mergeChain(findings []model.Finding, chain []int) model.Finding {
	best := chain[0]
	for _, i := range chain[1:] {
		if prefer(findings[i], findings[best]) {
			best = i
		}
	}
	merged := findings[best]
	seen := idSet(merged)
	for _, i := range chain {
		for _, a := range findings[i].Aliases {
			if !seen[a] {
				seen[a] = true
				merged.Aliases = append(merged.Aliases, a)
			}
		}
		for _, fv := range findings[i].FixedVersions {
			if !contains(merged.FixedVersions, fv) {
				merged.FixedVersions = append(merged.FixedVersions, fv)
			}
		}
	}
	return merged
}

// prefer reports whether a should be the representative over b.
// Higher severity wins; ties broken by preferring the non-"Duplicate Advisory".
func prefer(a, b model.Finding) bool {
	if rank(a.Severity) != rank(b.Severity) {
		return rank(a.Severity) > rank(b.Severity)
	}
	dupA := isDupAdvisory(a.Summary)
	dupB := isDupAdvisory(b.Summary)
	if dupA != dupB {
		return !dupA // prefer the one that's NOT a duplicate
	}
	return false // keep existing on full tie
}

func isDupAdvisory(summary string) bool {
	return strings.HasPrefix(summary, "Duplicate Advisory")
}

func rank(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	}
	return 0
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// buildFinding is the shared finding constructor. Returns nil if the record
// doesn't actually apply to dep (defensive re-check against the range).
func buildFinding(dep model.Dependency, rec Record) *model.Finding {
	matched := false
	var fixedVersions []string

	for _, aff := range rec.Affected {
		if !samePackage(aff.Name, dep.Name) || !sameEcosystem(aff.Ecosystem, string(dep.Ecosystem)) {
			continue
		}
		for _, r := range aff.Ranges {
			if r.Type == "GIT" {
				// Can't evaluate commit-hash ranges against a version string;
				// trust the candidate set and treat as matched.
				matched = true
				continue
			}
			if inRange(dep, r) {
				matched = true
			}
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					fixedVersions = append(fixedVersions, ev.Fixed)
				}
			}
		}
	}
	// Merge in any pre-collected fixed versions (e.g. from a DB column).
	for _, fv := range rec.FixedVersions {
		fixedVersions = append(fixedVersions, fv)
	}

	if !matched {
		return nil
	}

	cvss := osvclient.ScoreFromVectors(rec.CVSSVectors)
	return &model.Finding{
		Dependency:    dep,
		VulnID:        rec.ID,
		Aliases:       rec.Aliases,
		Summary:       rec.Summary,
		CVSS:          cvss,
		Severity:      model.SeverityFromCVSS(cvss),
		FixedVersions: dedupeStrings(fixedVersions),
	}
}

// inRange evaluates whether dep.Version falls in the range's event sequence.
func inRange(dep model.Dependency, r Range) bool {
	if len(r.Events) == 0 {
		return false
	}
	cmp := comparatorFor(dep.Ecosystem)
	var introduced, fixed, lastAffected string
	inSubRange := false

	for _, ev := range r.Events {
		if ev.Introduced != "" {
			introduced = ev.Introduced
			if introduced == "0" {
				introduced = ""
			}
			inSubRange = true
			fixed = ""
			lastAffected = ""
		} else if ev.Fixed != "" {
			fixed = ev.Fixed
			if inSubRange && versionInSubRange(cmp, dep.Version, introduced, fixed, lastAffected) {
				return true
			}
			inSubRange = false
		} else if ev.LastAffected != "" {
			lastAffected = ev.LastAffected
			if inSubRange && versionInSubRange(cmp, dep.Version, introduced, fixed, lastAffected) {
				return true
			}
			inSubRange = false
		}
	}
	if inSubRange && versionInSubRange(cmp, dep.Version, introduced, fixed, lastAffected) {
		return true
	}
	return false
}

func versionInSubRange(cmp func(a, b string) int, version, introduced, fixed, lastAffected string) bool {
	if introduced != "" && cmp(version, introduced) < 0 {
		return false
	}
	if fixed != "" && cmp(version, fixed) >= 0 {
		return false
	}
	if lastAffected != "" && cmp(version, lastAffected) > 0 {
		return false
	}
	return true
}

// comparatorFor returns the version comparator for an ecosystem.
// PipComparator is injected to avoid an import cycle (pip -> model -> matcher
// -> pip would cycle).
var pipComparator = pipparser.ComparePipVersions

func comparatorFor(eco model.Ecosystem) func(a, b string) int {
	switch eco {
	case model.EcosystemPyPI:
		return pipComparator
	case model.EcosystemGo:
		return model.CompareGoVersions
	default:
		// npm, Cargo, Maven use the generic comparator.
		return model.CompareVersions
	}
}

func samePackage(a, b string) bool { return equalFoldASCII(a, b) }

func sameEcosystem(a, b string) bool {
	// Normalize: our model uses "cargo" but OSV uses "crates.io"; "Go" vs "Go".
	// For matching purposes, treat cargo/crates.io as equivalent.
	if equalFoldASCII(a, b) {
		return true
	}
	norm := func(s string) string {
		switch s {
		case "crates.io", "cargo":
			return "cargo"
		}
		return s
	}
	return norm(a) == norm(b)
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func dedupeStrings(s []string) []string {
	seen := map[string]bool{}
	out := s[:0]
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
