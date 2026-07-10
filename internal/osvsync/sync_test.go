package osvsync

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/store"
)

type fakeArchiveStore struct {
	bulkErr    error
	reindexErr error
	changed    []string
	bulkCalls  int
	indexCalls int
}

func (s *fakeArchiveStore) BulkUpsertVulns(_ context.Context, _ []store.VulnRow) ([]string, error) {
	s.bulkCalls++
	return s.changed, s.bulkErr
}

func (s *fakeArchiveStore) ReindexVulnPackages(_ context.Context, _ []string) error {
	s.indexCalls++
	return s.reindexErr
}

func testArchive(t *testing.T, entries map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func TestStoreArchive_FailsWhenBulkUpsertFails(t *testing.T) {
	zr := testArchive(t, map[string]string{
		"TEST-1.json": `{"id":"TEST-1","modified":"2026-01-01T00:00:00Z"}`,
	})
	st := &fakeArchiveStore{bulkErr: errors.New("database unavailable")}

	_, _, err := storeArchive(context.Background(), st, model.EcosystemNPM, zr)
	if err == nil {
		t.Fatal("expected sync to fail when a batch cannot be persisted")
	}
	if st.bulkCalls != 1 {
		t.Errorf("bulk upsert calls = %d, want 1", st.bulkCalls)
	}
	if st.indexCalls != 0 {
		t.Errorf("reindex calls = %d, want 0 after failed upsert", st.indexCalls)
	}
}

func TestStoreArchive_FailsWhenReindexFails(t *testing.T) {
	zr := testArchive(t, map[string]string{
		"TEST-2.json": `{"id":"TEST-2","modified":"2026-01-01T00:00:00Z"}`,
	})
	st := &fakeArchiveStore{reindexErr: errors.New("index unavailable")}

	_, _, err := storeArchive(context.Background(), st, model.EcosystemNPM, zr)
	if err == nil {
		t.Fatal("expected sync to fail when package indexing fails")
	}
	if st.bulkCalls != 1 || st.indexCalls != 1 {
		t.Errorf("calls = bulk %d, reindex %d; want one each", st.bulkCalls, st.indexCalls)
	}
}

func TestStoreArchive_FailsOnMalformedAdvisory(t *testing.T) {
	zr := testArchive(t, map[string]string{"broken.json": `{not-json`})
	st := &fakeArchiveStore{}

	_, _, err := storeArchive(context.Background(), st, model.EcosystemNPM, zr)
	if err == nil {
		t.Fatal("expected sync to fail for a malformed advisory record")
	}
	if st.bulkCalls != 0 || st.indexCalls != 0 {
		t.Errorf("persistence was attempted after decode failure: bulk %d, reindex %d", st.bulkCalls, st.indexCalls)
	}
}

func TestStoreArchive_ReturnsExactChangedVulnerabilityIDs(t *testing.T) {
	zr := testArchive(t, map[string]string{
		"TEST-3.json": `{"id":"TEST-3","modified":"2026-01-01T00:00:00Z"}`,
	})
	st := &fakeArchiveStore{changed: []string{"TEST-3"}}

	count, changed, err := storeArchive(context.Background(), st, model.EcosystemNPM, zr)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("processed records = %d, want 1", count)
	}
	if len(changed) != 1 || changed[0] != "TEST-3" {
		t.Errorf("changed IDs = %v, want [TEST-3]", changed)
	}
}

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
