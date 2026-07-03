package model

import (
	"strconv"
	"strings"
)

// CompareVersions compares two versions using semver-like ordering.
//
// This is a pragmatic comparator for the MVP. It handles dotted numeric versions
// (1.2.3 vs 1.2.4), pre-release tags (1.0.0-alpha < 1.0.0), and the Maven "soft
// zero" rule (1 == 1.0 == 1.0.0) by padding to equal length. It is NOT a full
// implementation of semver, PEP 440, or Maven version ordering — for those,
// ecosystem-specific comparators (see internal/parser/pip for PEP 440) are used.
//
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func CompareVersions(a, b string) int {
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
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}
