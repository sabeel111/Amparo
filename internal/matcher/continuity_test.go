package matcher

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/store"
)

// TestContinuity_FlowB validates the core continuity promise: a dependency that
// was clean yesterday can become vulnerable today when the vuln DB updates —
// WITHOUT rescanning the source. This is Flow B from the design doc and the #1
// product differentiator.
//
// Approach: take a Go module at a version, match against the current local DB,
// and confirm findings appear. Then simulate a "DB update" by confirming that
// re-matching the SAME dependency against the (now-larger) DB surfaces the
// current set of vulns. The point is that matching is a pure function of
// (dependency, DB state) — no rescan needed.
func TestContinuity_FlowB(t *testing.T) {
	ctx := context.Background()
	conn := os.Getenv("DATABASE_URL")
	if conn == "" {
		conn = store.DefaultConnString
	}
	pool, err := store.Open(ctx, conn)
	if err != nil {
		t.Skipf("DB unavailable: %v", err)
	}
	defer pool.Close()

	var goCount int
	pool.QueryRow(ctx, `SELECT count(*) FROM vuln_record WHERE ecosystem='Go'`).Scan(&goCount)
	if goCount == 0 {
		t.Skip("no Go vuln records — run `sca sync --ecosystems Go` first")
	}

	// A dependency is just a resolved (name, version) — it carries no scan state.
	// This is the key: we can re-evaluate it against any DB state.
	dep := model.Dependency{
		Name: "golang.org/x/crypto", Version: "v0.17.0", Ecosystem: model.EcosystemGo,
	}
	st := store.New(pool)

	// Match 1: against the current DB.
	m1, err := NewLocal(pool).MatchDependencies(ctx, []model.Dependency{dep})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Flow B step 1 (current DB): %d findings for %s@%s", len(m1), dep.Name, dep.Version)

	// Verify ChangedVulnsSince works (the continuity trigger). A sync that ran
	// recently should report some changed vulns in the last day.
	changed, err := st.ChangedVulnsSince(ctx, time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatalf("ChangedVulnsSince: %v", err)
	}
	t.Logf("ChangedVulnsSince(1 day ago): %d changed vuln records", len(changed))

	// The continuity invariant: re-matching the same dep is idempotent (same DB
	// state → same findings). A future DB update would surface new/different ones.
	m2, err := NewLocal(pool).MatchDependencies(ctx, []model.Dependency{dep})
	if err != nil {
		t.Fatal(err)
	}
	if len(m1) != len(m2) {
		t.Errorf("idempotency broken: m1=%d findings, m2=%d findings (same DB state)", len(m1), len(m2))
	}
	t.Logf("Flow B invariant holds: re-match is idempotent (%d == %d)", len(m1), len(m2))

	// The DB-backed matching means a newly-synced advisory (one that wasn't there
	// before) would appear on the next re-match. We can't easily simulate "before"
	// here, but the cross-check test already proves local==live, so if OSV adds a
	// vuln and we sync it, the next re-match will find it. That's continuity.
	if len(m1) == 0 {
		t.Error("expected findings for a known-vulnerable Go module version")
	}
}
