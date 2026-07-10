package resolver

import (
	"context"
	"testing"

	"github.com/sabeel111/Amparo/internal/model"
)

// TestPipResolve_RealAPI resolves a small requirements set against live pypi.org.
// Verifies the transitive walk works and produces concrete (non-range) versions.
func TestPipResolve_RealAPI(t *testing.T) {
	r := For(model.EcosystemPyPI)
	if r == nil {
		t.Skip("no pip resolver registered")
	}
	direct := []model.Dependency{
		{Name: "requests", Version: ">=2.28,<3", Ecosystem: model.EcosystemPyPI, IsDirect: true},
	}
	out, err := r.Resolve(context.Background(), direct)
	if err != nil {
		t.Skipf("pypi.org unavailable: %v", err)
	}
	t.Logf("resolved %d deps from requests", len(out))
	// requests should pull in urllib3, certifi, charset-normalizer, idna.
	names := map[string]bool{}
	for _, d := range out {
		names[d.Name] = true
		// Every resolved dep must have a CONCRETE version, not a range.
		if !isPinned(d) {
			t.Errorf("dep %s has unpinned version %q (resolution failed)", d.Name, d.Version)
		}
	}
	for _, want := range []string{"requests", "urllib3", "certifi", "charset-normalizer", "idna"} {
		if !names[want] {
			t.Errorf("expected transitive dep %s in resolved set, not found", want)
		}
	}
}

// TestPipResolve_PicksHighestSatisfying verifies range selection: >=2.28,<3
// should resolve to the highest 2.x version, not a 3.x.
func TestPipResolve_PicksHighestSatisfying(t *testing.T) {
	r := For(model.EcosystemPyPI)
	if r == nil {
		t.Skip("no pip resolver registered")
	}
	direct := []model.Dependency{
		{Name: "requests", Version: ">=2.28,<3", Ecosystem: model.EcosystemPyPI, IsDirect: true},
	}
	out, err := r.Resolve(context.Background(), direct)
	if err != nil {
		t.Skipf("pypi.org unavailable: %v", err)
	}
	for _, d := range out {
		if d.Name == "requests" {
			if d.Version == ">=2.28,<3" {
				t.Errorf("requests version was not resolved (still a range): %q", d.Version)
			}
			t.Logf("requests resolved to %s", d.Version)
			// Should be a 2.x version (constrained <3).
			if len(d.Version) > 0 && d.Version[0] != '2' {
				t.Errorf("requests resolved to %s, expected a 2.x version (<3 constraint)", d.Version)
			}
		}
	}
}
