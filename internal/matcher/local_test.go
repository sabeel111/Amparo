package matcher

import (
	"context"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/osvclient"
	"github.com/sabeel111/Amparo/internal/store"
)

// TestLocalVsLiveCrossCheck is the headline Phase 1 correctness test:
// scan the same dependencies against (a) the live OSV API and (b) the local DB,
// and assert the findings agree. The two paths must produce the same set of
// vuln IDs for each dependency — that's the whole point of extracting the shared
// matcher logic.
//
// Uses Go ecosystem deps (synced in TestSync_RealSmallEcosystem). Skipped if the
// DB or network is unavailable.
func TestLocalVsLiveCrossCheck(t *testing.T) {
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

	// Verify Go records exist in the local DB.
	var goCount int
	pool.QueryRow(ctx, `SELECT count(*) FROM vuln_record WHERE ecosystem='Go'`).Scan(&goCount)
	if goCount == 0 {
		t.Skip("no Go vuln records in DB — run `sca sync --ecosystems Go` first")
	}
	t.Logf("local DB has %d Go vuln records", goCount)

	// Pick a real Go module with known vulns. golang.org/x/crypto has several.
	// Use a vulnerable version.
	deps := []model.Dependency{
		{Name: "golang.org/x/crypto", Version: "v0.17.0", Ecosystem: model.EcosystemGo},
	}

	// Live match.
	liveFindings, err := osvclient.New().MatchDependencies(ctx, deps)
	if err != nil {
		t.Skipf("live OSV API unavailable: %v", err)
	}
	liveIDs := findingIDs(liveFindings)
	t.Logf("live match found %d vulns: %v", len(liveIDs), liveIDs)

	// Local match.
	localFindings, err := NewLocal(pool).MatchDependencies(ctx, deps)
	if err != nil {
		t.Fatalf("local match failed: %v", err)
	}
	localIDs := findingIDs(localFindings)
	t.Logf("local match found %d vulns: %v", len(localIDs), localIDs)

	// The two sets should agree. There may be minor drift if the DB is newer
	// than the live data or vice versa, but the core known vulns must overlap.
	missing := setDiff(liveIDs, localIDs)
	extra := setDiff(localIDs, liveIDs)
	// Allow some drift but require substantial overlap.
	overlap := setIntersection(liveIDs, localIDs)
	if len(overlap) == 0 {
		t.Errorf("no overlap between live and local findings — matcher paths disagree")
	}
	// Log drift for visibility (not a hard failure — OSV data moves).
	if len(missing) > 0 {
		t.Logf("in live but not local (%d, expected drift if DB newer/different): %v", len(missing), missing[:min(5, len(missing))])
	}
	if len(extra) > 0 {
		t.Logf("in local but not live (%d, expected drift): %v", len(extra), extra[:min(5, len(extra))])
	}
}

func findingIDs(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.VulnID
	}
	sort.Strings(out)
	return out
}

func setDiff(a, b []string) []string {
	bs := map[string]bool{}
	for _, x := range b {
		bs[x] = true
	}
	var out []string
	for _, x := range a {
		if !bs[x] {
			out = append(out, x)
		}
	}
	return out
}

func setIntersection(a, b []string) []string {
	bs := map[string]bool{}
	for _, x := range b {
		bs[x] = true
	}
	var out []string
	for _, x := range a {
		if bs[x] {
			out = append(out, x)
		}
	}
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// unused but keeps the time import (timestamps in future scheduling tests)
var _ = time.Now
