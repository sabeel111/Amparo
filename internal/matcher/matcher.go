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
