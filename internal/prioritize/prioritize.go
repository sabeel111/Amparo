// Package prioritize turns raw OSV matches into prioritized findings.
//
// This implements the deterministic scoring described in the design doc §8.
// Raw CVSS is why devs ignore SCA tools, so we compute a composite priority
// from CVSS + EPSS + fix-availability, with KEV reserved for when we wire in
// the KEV feed (Phase 1). Every decision is recorded as an auditable "reason"
// string so the UI can explain the score — the same reasons[] the AI layer
// (§8.5) consumes as grounded input.
//
// IMPORTANT: this is pure, deterministic code. No network, no LLM, no randomness.
// Given the same inputs it always produces the same priority.
package prioritize

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
)

// Enrich takes raw findings and fills in Priority, Actionable, and Reasons.
// EPSS values are expected to already be attached (see epss package); a zero
// EPSS value is treated as "unknown" and handled gracefully, not as "no risk".
func Enrich(findings []model.Finding) []model.Finding {
	for i := range findings {
		f := &findings[i]
		priority, reasons := compute(f)
		f.Priority = priority
		f.Reasons = append(reasons, f.Reasons...)
		if hasFixAvailable(f) {
			f.Actionable = model.ActionableNow
		} else {
			f.Actionable = model.ActionableMonitor
		}
	}
	// Sort by priority (critical first), then by EPSS percentile, then CVSS.
	sort.SliceStable(findings, func(i, j int) bool {
		return lessFinding(findings[i], findings[j])
	})
	return findings
}

// compute returns the composite priority band and the auditable reasons.
func compute(f *model.Finding) (model.Severity, []string) {
	var reasons []string

	// --- CVSS band (the floor) ---
	cvssBand := f.Severity
	if f.CVSS > 0 {
		reasons = append(reasons, sprintCVSS(f.CVSS))
	}

	// --- EPSS: exploit probability. High percentile boosts priority. ---
	highEPSS := f.EPSSPercentile >= 0.95
	if f.EPSSPercentile > 0 {
		reasons = append(reasons, sprintEPSS(f.EPSSProbability, f.EPSSPercentile))
	}

	// --- Direct vs transitive: direct deps have higher exposure. ---
	if f.Dependency.IsDirect {
		reasons = append(reasons, "direct dependency (higher exposure than transitive)")
	}

	// --- Composite bucketing (design doc §8.2) ---
	// CRITICAL: high CVSS AND very likely exploited.
	priority := cvssBand
	if f.CVSS >= 9.0 && highEPSS {
		priority = model.SeverityCritical
		reasons = append(reasons, "boosted to CRITICAL: high CVSS + EPSS ≥95th percentile (exploit likely)")
	} else if f.CVSS >= 9.0 {
		// Critical CVSS without strong exploit signal stays critical but we note it.
		priority = model.SeverityCritical
	}

	// HIGH floor if CVSS says so but composite didn't promote.
	if rank(priority) < rank(model.SeverityHigh) && f.CVSS >= 7.0 {
		priority = model.SeverityHigh
	}
	// Never go below the raw CVSS band — don't downrank a genuinely severe CVE.
	if rank(cvssBand) > rank(priority) {
		priority = cvssBand
	}

	if highEPSS && rank(priority) < rank(model.SeverityHigh) {
		priority = model.SeverityHigh
		reasons = append(reasons, "boosted to HIGH: EPSS ≥95th percentile (exploit likely)")
	}

	return priority, reasons
}

// hasFixAvailable reports whether OSV listed any fixed version for this finding.
func hasFixAvailable(f *model.Finding) bool {
	for _, v := range f.FixedVersions {
		if strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
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

// lessFinding is the sort comparator: higher priority first, then higher EPSS,
// then higher CVSS.
func lessFinding(a, b model.Finding) bool {
	if ra, rb := rank(a.Priority), rank(b.Priority); ra != rb {
		return ra > rb
	}
	if a.EPSSPercentile != b.EPSSPercentile {
		return a.EPSSPercentile > b.EPSSPercentile
	}
	if a.CVSS != b.CVSS {
		return a.CVSS > b.CVSS
	}
	if a.Dependency.Name != b.Dependency.Name {
		return a.Dependency.Name < b.Dependency.Name
	}
	return a.VulnID < b.VulnID
}

// sprintCVSS formats the CVSS reason string.
func sprintCVSS(score float64) string {
	return fmt.Sprintf("CVSS %.1f", score)
}

// sprintEPSS formats the EPSS reason string.
func sprintEPSS(prob, pct float64) string {
	return fmt.Sprintf("EPSS %.1f%% exploit probability (%.1f%% percentile)", prob*100, pct*100)
}
