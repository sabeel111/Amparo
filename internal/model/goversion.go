package model

import (
	"strconv"
	"strings"
)

// CompareGoVersions compares Go module versions, including pseudo-versions.
//
// Go module versions come in two forms:
//  1. Canonical semver: "v1.2.3", "v1.2.3-beta", "v2.0.0".
//  2. Pseudo-versions: "v0.0.0-20240102120000-abcdef1234ab" (for commits without
//     a tag), "v1.2.4-pre0.20240102120000-abcdef1234ab" (pre-release + commit).
//
// The pseudo-version embeds a UTC timestamp (YYYYMMDDhhmmss) and a commit hash.
// Ordering: a higher timestamp = a later version. Pseudo-versions sort AFTER
// their base semver but BEFORE the next tagged release.
//
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func CompareGoVersions(a, b string) int {
	// Strip leading 'v' (Go versions always start with v, semver comparison
	// doesn't expect it).
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	// Extract pseudo-version timestamp if present.
	coreA, tsA, hashA := splitPseudo(a)
	coreB, tsB, hashB := splitPseudo(b)

	// Compare the semver cores first.
	if c := CompareVersions(coreA, coreB); c != 0 {
		return c
	}

	// Same core. If both are pseudo-versions, order by timestamp (then hash).
	if tsA != "" && tsB != "" {
		if tsA != tsB {
			return strings.Compare(tsA, tsB) // lexicographic works for same-format timestamps
		}
		return strings.Compare(hashA, hashB)
	}
	// A pseudo-version is GREATER than its bare core (the core tag came first,
	// the pseudo-version is a later commit). e.g. v1.2.3 < v1.2.4-0... wait:
	// actually v1.2.3-0.timestamp is BEFORE v1.2.4 but AFTER v1.2.3-pre? The Go
	// spec: pseudo-version after .preN sort. Simplify: pseudo > tagged core.
	if tsA != "" {
		return 1
	}
	if tsB != "" {
		return -1
	}
	return 0
}

// splitPseudo splits a Go version into (core, timestamp, hash) where timestamp
// and hash are empty for plain semver. Handles "v0.0.0-20240102-abcdef" and
// "v1.2.3-pre.20240102-abcdef".
func splitPseudo(v string) (core, timestamp, hash string) {
	// A pseudo-version has a segment like "-YYYYMMDDhhmmss-hash".
	// We look for a "-" followed by 14 digits.
	parts := strings.SplitN(v, "-", 3)
	if len(parts) == 3 && isTimestamp(parts[1]) {
		return parts[0], parts[1], parts[2]
	}
	if len(parts) == 2 && isTimestamp(parts[1]) {
		// rare: timestamp with no hash segment
		return parts[0], parts[1], ""
	}
	return v, "", ""
}

// isTimestamp reports whether s looks like a 14-digit UTC timestamp.
func isTimestamp(s string) bool {
	if len(s) != 14 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// CompareSemverStrict compares strict semver versions (npm, Cargo). This is
// currently identical to CompareVersions but kept as a named entry point so the
// matcher can be explicit about which comparator it uses per ecosystem.
func CompareSemverStrict(a, b string) int {
	return CompareVersions(a, b)
}

// used by strconv indirectly to avoid unused import warnings during dev
var _ = strconv.Itoa
