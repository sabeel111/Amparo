package osvclient

import (
	"context"
	"fmt"

	"github.com/sabeel111/Amparo/internal/model"
)

// MatchDependencies queries OSV for each dependency and returns findings.
//
// Flow:
//  1. Batch-query OSV (up to 1000 per request) to get vuln IDs per dependency.
//  2. Fetch full detail for each unique vuln ID (deduped, bounded concurrency).
//  3. For each (dependency, vuln), confirm the dep's version falls in an
//     affected range AND extract fixed versions — a defensive re-check, since
//     OSV's batch query should already be version-accurate but we want our
//     findings to carry the exact fixed versions for remediation.
func (c *Client) MatchDependencies(ctx context.Context, deps []model.Dependency) ([]model.Finding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// --- 1. Build batch queries (one per dependency). ---
	queries := make([]QueryRequest, len(deps))
	for i, d := range deps {
		queries[i] = QueryRequest{
			Package: OSVPackage{Name: d.Name, Ecosystem: string(d.Ecosystem)},
			Version: d.Version,
		}
	}

	// OSV allows 1000 queries per batch; chunk if needed.
	var allResults QueryBatchResponse
	for start := 0; start < len(queries); start += batchSize {
		end := start + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		resp, err := c.QueryVersions(ctx, queries[start:end])
		if err != nil {
			return nil, fmt.Errorf("batch query (%d:%d): %w", start, end, err)
		}
		allResults.Results = append(allResults.Results, resp.Results...)
	}

	// --- 2. Collect unique vuln IDs and fetch details. ---
	vulnIDSet := map[string]bool{}
	for _, r := range allResults.Results {
		for _, v := range r.Vulns {
			vulnIDSet[v.ID] = true
		}
	}
	ids := make([]string, 0, len(vulnIDSet))
	for id := range vulnIDSet {
		ids = append(ids, id)
	}
	vulns, err := c.GetVulns(ctx, ids)
	if err != nil {
		return nil, err
	}

	// --- 3. Build findings. ---
	var findings []model.Finding
	for i, dep := range deps {
		if i >= len(allResults.Results) {
			break
		}
		for _, vref := range allResults.Results[i].Vulns {
			v, ok := vulns[vref.ID]
			if !ok || v == nil {
				continue
			}
			f := buildFinding(dep, v)
			if f == nil {
				continue // version not actually in range for this package
			}
			findings = append(findings, *f)
		}
	}
	return findings, nil
}

// buildFinding turns an OSV Vulnerability + dependency into a Finding, but only
// if the dependency actually matches an affected range for its package/ecosystem.
// Returns nil if the vulnerability doesn't apply (defensive re-check).
func buildFinding(dep model.Dependency, v *Vulnerability) *model.Finding {
	var fixedVersions []string
	matched := false

	for _, aff := range v.Affected {
		// Match package name (case-insensitive) and ecosystem. Some OSV records
		// use "npm" consistently; we compare against our stored ecosystem string.
		if !samePackage(aff.Package.Name, dep.Name) || !sameEcosystem(aff.Package.Ecosystem, string(dep.Ecosystem)) {
			continue
		}
		// For this affected entry, check ranges and collect fixed versions.
		for _, r := range aff.Ranges {
			// GIT ranges use commit hashes; we can't evaluate those against a
			// version string, so rely on the batch query's version match and
			// skip range verification for GIT.
			if r.Type == "GIT" {
				matched = true
				continue
			}
			// Evaluate introduced/fixed events for SEMVER/ECOSYSTEM ranges.
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

	if !matched {
		return nil
	}

	cvss := ScoreFromVectors(cvssVectorStrings(v.Severity))

	return &model.Finding{
		Dependency:    dep,
		VulnID:        v.ID,
		Aliases:       v.Aliases,
		Summary:       v.Summary,
		CVSS:          cvss,
		Severity:      model.SeverityFromCVSS(cvss),
		FixedVersions: fixedVersions,
	}
}

// cvssVectorStrings extracts the vector strings from the Severity slice.
func cvssVectorStrings(sev []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) []string {
	out := make([]string, 0, len(sev))
	for _, s := range sev {
		out = append(out, s.Score)
	}
	return out
}

// inRange checks whether dep.Version falls inside the range described by a
// sequence of introduced/fixed/last_affected events.
//
// Events define sub-ranges: an "introduced" starts a sub-range, "fixed" ends it
// (exclusive), "last_affected" ends it (inclusive). A version with no preceding
// "introduced" is treated as introduced from "0".
func inRange(dep model.Dependency, r struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced,omitempty"`
		Fixed        string `json:"fixed,omitempty"`
		LastAffected string `json:"last_affected,omitempty"`
	} `json:"events"`
}) bool {
	var introduced, fixed, lastAffected string
	inSubRange := false

	// If no events, can't determine; be conservative (not in range).
	if len(r.Events) == 0 {
		return false
	}

	for _, ev := range r.Events {
		if ev.Introduced != "" {
			introduced = ev.Introduced
			inSubRange = true
			fixed = ""
			lastAffected = ""
			// "0" means from the beginning.
			if introduced == "0" {
				introduced = ""
			}
		} else if ev.Fixed != "" {
			fixed = ev.Fixed
			if inSubRange && versionInSubRange(dep, introduced, fixed, lastAffected) {
				return true
			}
			inSubRange = false
		} else if ev.LastAffected != "" {
			lastAffected = ev.LastAffected
			if inSubRange && versionInSubRange(dep, introduced, fixed, lastAffected) {
				return true
			}
			inSubRange = false
		}
	}
	// Trailing sub-range with introduced but no fixed/last_affected.
	if inSubRange && versionInSubRange(dep, introduced, fixed, lastAffected) {
		return true
	}
	return false
}

// versionInSubRange checks if dep.Version is >= introduced and < fixed and <= lastAffected.
func versionInSubRange(dep model.Dependency, introduced, fixed, lastAffected string) bool {
	cmp := comparatorFor(dep.Ecosystem)
	if introduced != "" {
		if cmp(dep.Version, introduced) < 0 {
			return false
		}
	}
	if fixed != "" {
		if cmp(dep.Version, fixed) >= 0 {
			return false
		}
	}
	if lastAffected != "" {
		if cmp(dep.Version, lastAffected) > 0 {
			return false
		}
	}
	return true
}

// comparatorFor returns the version comparator appropriate for the ecosystem.
//   - PyPI: PEP 440 (registered via SetPipComparator to avoid an import cycle)
//   - Go: CompareGoVersions (handles v-prefixes and pseudo-versions)
//   - npm/Cargo/Maven: generic semver-ish CompareVersions
var comparatorFor = func(eco model.Ecosystem) func(a, b string) int {
	switch eco {
	case model.EcosystemGo:
		return model.CompareGoVersions
	}
	return func(a, b string) int { return model.CompareVersions(a, b) }
}

// SetPipComparator allows the pip package to register its PEP 440 comparator
// without creating an import cycle. Called from init() in the wiring layer.
var pipComparator func(a, b string) int

// SetPipComparator registers the PEP 440 comparator used for PyPI dependencies.
func SetPipComparator(f func(a, b string) int) {
	pipComparator = f
	comparatorFor = func(eco model.Ecosystem) func(a, b string) int {
		switch eco {
		case model.EcosystemPyPI:
			if pipComparator != nil {
				return pipComparator
			}
		case model.EcosystemGo:
			return model.CompareGoVersions
		}
		return model.CompareVersions
	}
}

func samePackage(a, b string) bool {
	return equalFold(a, b)
}

func sameEcosystem(a, b string) bool {
	// OSV uses "npm" and "PyPI"; we store the same strings. Compare case-insensitively.
	return equalFold(a, b)
}

// equalFold is a case-insensitive string compare (ASCII; ecosystems/names are ASCII).
func equalFold(a, b string) bool {
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
