package model

import (
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
)

// CompareVersions compares two versions.
//
// For strict SemVer inputs (npm, Cargo) it delegates to Masterminds/semver — a
// spec-compliant implementation that handles pre-release ordering
// (1.0.0-alpha < 1.0.0-beta < 1.0.0) and ignores build metadata per the SemVer
// spec. For non-SemVer inputs (Maven soft-zero like "1" == "1.0.0", loose
// versions), it falls back to a pragmatic numeric/lexicographic comparator.
//
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareVersions(a, b string) int {
	// Fast path: try strict SemVer for both. This covers npm/Cargo cleanly.
	if va, errA := semver.NewVersion(sanitizeSemver(a)); errA == nil {
		if vb, errB := semver.NewVersion(sanitizeSemver(b)); errB == nil {
			return va.Compare(vb)
		}
	}
	// Fallback: pragmatic comparator for non-semver strings (Maven, loose).
	return comparePragmatic(a, b)
}

// sanitizeSemver strips a leading 'v' (npm often uses v1.2.3) and tolerates the
// "v" prefix Masterminds accepts but doesn't require. We add 'v' tolerance by
// letting Masterminds handle it (it accepts both forms).
func sanitizeSemver(v string) string {
	// Masterminds accepts "1.2.3" and "v1.2.3" natively; no transformation needed.
	return strings.TrimSpace(v)
}

// comparePragmatic is the legacy comparator, retained for non-SemVer version
// strings (Maven "soft zero", loose versions). Handles dotted numeric versions
// and pre-release suffixes; pads to equal length so 1 == 1.0 == 1.0.0.
func comparePragmatic(a, b string) int {
	ra, preA := splitPreRelease(a)
	rb, preB := splitPreRelease(b)
	pa := strings.Split(strings.Trim(ra, "."), ".")
	pb := strings.Split(strings.Trim(rb, "."), ".")

	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		xa, xb := partAt(pa, i), partAt(pb, i)
		// Numeric comparison when both are numbers; otherwise lexicographic.
		na, ea := strconv.Atoi(xa)
		nb, eb := strconv.Atoi(xb)
		if ea == nil && eb == nil {
			if na < nb {
				return -1
			}
			if na > nb {
				return 1
			}
			continue
		}
		if xa < xb {
			return -1
		}
		if xa > xb {
			return 1
		}
	}

	// Equal numeric core → pre-release ordering: a version WITH a pre-release tag
	// is LOWER than the same version WITHOUT one (semver rule).
	if preA == preB {
		return 0
	}
	if preA == "" {
		return 1
	}
	if preB == "" {
		return -1
	}
	return strings.Compare(preA, preB)
}

// partAt returns the i-th dot-separated component, defaulting to "0" so that
// "1.0" and "1.0.0" compare equal (Maven soft-zero / loose-version behavior).
func partAt(parts []string, i int) string {
	if i < len(parts) {
		s := strings.TrimSpace(parts[i])
		if s != "" {
			return s
		}
	}
	return "0"
}

// splitPreRelease separates a core version from its pre-release suffix at the
// first '-' or '+'. Examples: "1.2.3-alpha" -> ("1.2.3","alpha"); "1.0" -> ("1.0","").
func splitPreRelease(v string) (core, pre string) {
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

// SeverityFromCVSS maps a numeric CVSS score to a band.
// SeverityFromCVSS maps a numeric CVSS score to a band.
//
// A score of 0 means "no CVSS vector was provided" (some OSV/GHSA records omit
// it), NOT "not vulnerable." Since this is only called for matched findings, a
// missing CVSS should never produce SeverityNone — that would create a confusing
// "NONE" tier of real vulnerabilities. We floor unknown-CVSS findings at Low so
// they're visible and triageable rather than disappearing into a meaningless band.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	default:
		// Covers score > 0 (Low) AND score == 0 (unknown — floored to Low so a
		// matched vuln with no CVSS vector is still surfaced, never "none").
		return SeverityLow
	}
}
