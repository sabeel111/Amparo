package model

import (
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

// CompareGoVersions compares Go module versions, including pseudo-versions.
//
// Delegates to golang.org/x/mod/semver — the official Go team's implementation
// used by the `go` command itself and by osv-scanner. It handles canonical
// semver (v1.2.3), pre-releases (v1.2.3-beta), AND pseudo-versions
// (v0.0.0-20240102120000-abcdef1234ab) natively, including the subtle ordering
// rules around pseudo-versions and tagged releases.
//
// Requires the leading "v" prefix (Go convention); we add it if missing.
//
// Returns -1 if a < b, 0 if equal, 1 if a > b.
func CompareGoVersions(a, b string) int {
	a = ensureVPrefix(a)
	b = ensureVPrefix(b)
	return semver.Compare(a, b)
}

// ensureVPrefix adds the "v" prefix if missing (golang.org/x/mod/semver requires it).
func ensureVPrefix(v string) string {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// (Legacy helpers below retained for reference/tests but no longer on the hot path
// now that we delegate to golang.org/x/mod/semver. If the legacy comparators are
// not referenced elsewhere, they can be removed in a follow-up cleanup.)

// CompareGoVersionsLegacy is the previous hand-rolled implementation, kept for
// reference and regression comparison. Not used in production.
func CompareGoVersionsLegacy(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	coreA, tsA, hashA := splitPseudo(a)
	coreB, tsB, hashB := splitPseudo(b)
	if c := CompareVersions(coreA, coreB); c != 0 {
		return c
	}
	if tsA != "" && tsB != "" {
		if tsA != tsB {
			return strings.Compare(tsA, tsB)
		}
		return strings.Compare(hashA, hashB)
	}
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
