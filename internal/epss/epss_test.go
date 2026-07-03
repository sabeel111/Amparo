package epss

import (
	"context"
	"testing"
)

func TestFetchScores_RealAPI(t *testing.T) {
	// Integration test — hits the live EPSS API. Skip if offline.
	c := New()
	cves := []string{"CVE-2022-28346", "PYSEC-2022-190", "GHSA-2gwj-7jmv-h26r"}
	scores, err := c.FetchScores(context.Background(), cves)
	if err != nil {
		t.Skipf("EPSS API unavailable: %v", err)
	}
	if len(scores) == 0 {
		t.Fatal("expected at least one score, got none")
	}
	for k, v := range scores {
		t.Logf("  %s: prob=%.4f pct=%.4f", k, v.Probability, v.Percentile)
	}
	// CVE-2022-28346 should have a real score.
	if s, ok := scores["CVE-2022-28346"]; !ok {
		t.Errorf("CVE-2022-28346 missing from results; got keys from %v", keysOf(scores))
	} else if s.Probability <= 0 {
		t.Errorf("CVE-2022-28346 probability = %v, want > 0", s.Probability)
	}
}

func keysOf(m map[string]Score) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
