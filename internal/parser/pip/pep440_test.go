package pipparser

import "testing"

func TestComparePipVersions(t *testing.T) {
	// PEP 440 ordering cases that semver gets wrong.
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0", "1.0.0", 0},       // trailing zero equivalence
		{"1.0.1b2", "1.0.1", -1},  // beta < release
		{"1.0a1", "1.0b1", -1},    // alpha < beta
		{"1.0rc1", "1.0", -1},     // rc < release
		{"1.0.post1", "1.0", 1},   // post-release > release
		{"1.0.dev1", "1.0", -1},   // dev < release
		{"2.0", "1.9.9", 1},       // numeric
		{"2018.11", "2018.10", 1}, // calver
		{"1.0.1", "1.0.1", 0},     // equal
		{"1!2.0", "2.0", 1},       // epoch wins
		{"1.0", "1.0.0.0.0", 0},   // extra trailing zeros
	}
	for _, c := range cases {
		got := ComparePipVersions(c.a, c.b)
		if sign(got) != sign(c.want) {
			t.Errorf("ComparePipVersions(%q, %q) = %d, want sign %d", c.a, c.b, got, c.want)
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
