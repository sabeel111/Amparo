package model

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.0", 1}, // numeric, not lexicographic
		// Maven "soft zero": 1 == 1.0 == 1.0.0
		{"1", "1.0", 0},
		{"1.0", "1.0.0", 0},
		// Pre-release: 1.0.0-alpha < 1.0.0
		{"1.0.0-alpha", "1.0.0", -1},
		{"1.0.0", "1.0.0-alpha", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
	}
	for _, c := range cases {
		got := CompareVersions(c.a, c.b)
		// Normalize to sign for comparison.
		gs, ws := sign(got), sign(c.want)
		if gs != ws {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{9.8, SeverityCritical},
		{9.0, SeverityCritical},
		{8.9, SeverityHigh},
		{7.0, SeverityHigh},
		{6.9, SeverityMedium},
		{4.0, SeverityMedium},
		{3.9, SeverityLow},
		// CVSS 0 = unknown vector; matched findings floor at Low, never None.
		{0, SeverityLow},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("SeverityFromCVSS(%.1f) = %s, want %s", c.score, got, c.want)
		}
	}
}

func sign(n int) int {
	if n < 0 {
		return -1
	}
	if n > 0 {
		return 1
	}
	return 0
}
