package model

import "testing"

func TestCompareGoVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Plain semver
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.4", "v1.2.3", 1},
		{"v1.2.3", "v1.2.3", 0},
		// Pseudo-version ordering by timestamp (newer timestamp > older)
		{"v0.0.0-20240102120000-abcdef", "v0.0.0-20240103120000-fedcba", -1},
		{"v0.0.0-20240103120000-fedcba", "v0.0.0-20240102120000-abcdef", 1},
		// Same timestamp, different hash → ordered by hash
		{"v0.0.0-20240102120000-aaaaaa", "v0.0.0-20240102120000-bbbbbb", -1},
		// 'v' prefix optional on both
		{"1.2.3", "1.2.4", -1},
	}
	for _, c := range cases {
		got := CompareGoVersions(c.a, c.b)
		if sign(got) != sign(c.want) {
			t.Errorf("CompareGoVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
}
