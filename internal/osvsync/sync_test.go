package osvsync

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/store"
)

func pool(t *testing.T) *pgxpool.Pool {
	conn := os.Getenv("DATABASE_URL")
	if conn == "" {
		conn = store.DefaultConnString
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := store.Open(ctx, conn)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	return pool
}

// Real integration test: sync a SMALL ecosystem (Go is much smaller than npm)
// and verify records land in Postgres. Go's all.zip is ~5-10MB vs npm's ~85MB,
// so this validates the full pipeline without a huge download.
func TestSync_RealSmallEcosystem(t *testing.T) {
	ctx := context.Background()
	pool := pool(t)
	defer pool.Close()

	// Clean any prior test data for a deterministic count.
	pool.Exec(ctx, `DELETE FROM vuln_record WHERE ecosystem='Go'`)

	result := Sync(ctx, pool, []model.Ecosystem{model.EcosystemGo}, true)
	if len(result.Stats) != 1 {
		t.Fatalf("expected 1 stat, got %d", len(result.Stats))
	}
	s := result.Stats[0]
	if s.Err != nil {
		t.Fatalf("sync failed: %v", s.Err)
	}
	t.Logf("Go sync: %d records, %.1f MB in %s", s.Records, float64(s.Bytes)/1e6, s.Duration)
	if s.Records < 100 {
		t.Errorf("expected at least 100 Go vuln records, got %d", s.Records)
	}

	// Verify the records are queryable via the store.
	st := store.New(pool)
	rows, err := st.FindVulnsByPackage(ctx, "Go", "stdlib")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("FindVulnsByPackage(Go, stdlib) returned %d rows", len(rows))
	if len(rows) == 0 {
		t.Error("expected Go stdlib vulns to be present after sync")
	}
}

// Test that a second sync with --force=false SKIPS when unchanged (HEAD-first).
func TestSync_SkipsWhenUnchanged(t *testing.T) {
	ctx := context.Background()
	pool := pool(t)
	defer pool.Close()

	// First run downloads.
	Sync(ctx, pool, []model.Ecosystem{model.EcosystemGo}, true)

	// Inspect what got cached.
	cache := newMetaCache(pool)
	cached, ok := cache.getLastModified(model.EcosystemGo)
	t.Logf("after first run: cached=%q ok=%v", cached, ok)

	// Second run should skip.
	result := Sync(ctx, pool, []model.Ecosystem{model.EcosystemGo}, false)
	s := result.Stats[0]
	if s.Err != nil {
		t.Fatalf("second sync errored: %v", s.Err)
	}
	if !s.Skipped {
		// OSV updates frequently; a genuine change between runs is possible.
		// Log for visibility but only fail if we definitely didn't cache.
		newRemote, _ := headLastModified(context.Background(),
			"https://osv-vulnerabilities.storage.googleapis.com/Go/all.zip")
		t.Logf("second sync re-downloaded: cached=%q remote=%q (may be a real update)", cached, newRemote)
		if !ok {
			t.Error("skipped=false AND cache was empty — store-after-download is broken")
		}
	}
	t.Logf("second sync skipped=%v", s.Skipped)
}
