package osvclient

import (
	"math"
	"testing"
)

// TestScoreFromVector verifies our CVSS v3.1 base-score computation against
// known NVD scores. These vectors and their expected scores come from real CVE
// records, so a match means our calculator agrees with FIRST.org/NVD.
func TestScoreFromVector(t *testing.T) {
	cases := []struct {
		name   string
		vector string
		want   float64
	}{
		// CVE-2020-28500 lodash ReDoS — verified 5.3 per NVD.
		{"lodash ReDoS (5.3)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3},
		// CVE-2021-44906 minimist prototype pollution — verified 9.8 per NVD.
		{"minimist proto pollution (9.8)", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		// Scope-changed vector: hand-computed via the v3.1 formula = 4.7.
		{"scope changed (4.7)", "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N", 4.7},
		// Malformed vector returns 0, false.
		{"malformed", "garbage", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := ScoreFromVector(c.vector)
			if c.name == "malformed" {
				if ok {
					t.Error("expected ok=false for malformed vector")
				}
				return
			}
			if !ok {
				t.Fatalf("vector %q failed to parse", c.vector)
			}
			if math.Abs(got-c.want) > 0.05 {
				t.Errorf("score = %.1f, want %.1f", got, c.want)
			}
		})
	}
}

func TestScoreFromVectors_PicksHighest(t *testing.T) {
	vectors := []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", // 3.7
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8
	}
	if got := ScoreFromVectors(vectors); math.Abs(got-9.8) > 0.05 {
		t.Errorf("ScoreFromVectors = %.1f, want 9.8", got)
	}
}
