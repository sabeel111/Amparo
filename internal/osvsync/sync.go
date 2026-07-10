package osvsync

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/osvclient"
	"github.com/sabeel111/Amparo/internal/store"
)

const (
	baseURL               = "https://osv-vulnerabilities.storage.googleapis.com"
	httpTimeout           = 10 * time.Minute // zips can be large
	maxArchiveBytes int64 = 1 << 30          // 1 GiB compressed archive safety limit
)

// Status is the terminal state of one ecosystem sync.
type Status string

const (
	StatusComplete Status = "complete"
	StatusSkipped  Status = "skipped"
	StatusFailed   Status = "failed"
)

// Stats reports the outcome of one ecosystem sync.
type Stats struct {
	Ecosystem    model.Ecosystem
	Status       Status
	Records      int      // number of advisory records successfully processed
	ChangedVulns []string // exact IDs inserted or materially changed in this sync
	Skipped      bool     // true if HEAD said unchanged
	Bytes        int64
	Duration     time.Duration
	Err          error
}

// SyncResult aggregates per-ecosystem stats. ChangedVulnIDs is the exact
// handoff from a completed sync to the continuity worker.
type SyncResult struct {
	StartedAt time.Time
	Stats     []Stats
}

// ChangedVulnIDs returns the exact advisory IDs changed by successful
// ecosystems in this sync. It is the handoff contract for continuity.
func (r SyncResult) ChangedVulnIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, stat := range r.Stats {
		if stat.Status != StatusComplete {
			continue
		}
		for _, id := range stat.ChangedVulns {
			if id != "" && !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids
}

// Sync downloads + upserts the OSV data for the given ecosystems.
// For each ecosystem: HEAD to check Last-Modified against the cached value;
// skip if unchanged; otherwise GET the zip, stream-extract, parse, upsert.
func Sync(ctx context.Context, pool *pgxpool.Pool, ecosystems []model.Ecosystem, force bool) SyncResult {
	result := SyncResult{StartedAt: time.Now()}
	st := store.New(pool)
	cache := newMetaCache(pool)

	for _, eco := range ecosystems {
		s := Stats{Ecosystem: eco}
		start := time.Now()

		bucket, ok := bucketEcosystem(eco)
		if !ok {
			s.Err = fmt.Errorf("unsupported ecosystem %s", eco)
			s.Status = StatusFailed
			s.Duration = time.Since(start)
			result.Stats = append(result.Stats, s)
			continue
		}
		url := fmt.Sprintf("%s/%s/all.zip", baseURL, bucket)

		// --- Change detection (HEAD-first). ---
		var remoteLastMod string
		if !force {
			changed, lm, err := checkChanged(ctx, url, cache, eco)
			if err == nil {
				remoteLastMod = lm
				if !changed {
					s.Skipped = true
					s.Status = StatusSkipped
					s.Duration = time.Since(start)
					result.Stats = append(result.Stats, s)
					continue
				}
			}
			// If the HEAD check itself errored, proceed to a full GET — failing
			// open is better than failing the whole sync on a flaky HEAD.
		}

		// --- Download + stream-extract + upsert. ---
		n, changed, bytesN, err := downloadAndStore(ctx, st, eco, url)
		s.Records = n
		s.ChangedVulns = changed
		s.Bytes = bytesN
		s.Duration = time.Since(start)
		s.Err = err
		if err == nil {
			// Record the remote Last-Modified so the next run can skip. If we
			// didn't get it from HEAD (force mode or HEAD failure), fetch it now.
			if remoteLastMod == "" {
				remoteLastMod, _ = headLastModified(ctx, url)
			}
			if remoteLastMod != "" {
				if err := cache.setLastModified(ctx, eco, remoteLastMod); err != nil {
					s.Err = fmt.Errorf("recording sync metadata: %w", err)
				}
			}
		}
		if s.Err != nil {
			s.Status = StatusFailed
		} else {
			s.Status = StatusComplete
		}
		result.Stats = append(result.Stats, s)
	}
	return result
}

// checkChanged returns (changed=true) if the remote Last-Modified differs from
// the cached value (or there's no cache yet).
func checkChanged(ctx context.Context, url string, cache *metaCache, eco model.Ecosystem) (changed bool, remote string, err error) {
	cached, ok := cache.getLastModified(eco)
	remote, err = headLastModified(ctx, url)
	if err != nil {
		return true, "", err // fail open
	}
	if !ok {
		return true, remote, nil
	}
	return remote != cached, remote, nil
}

func headLastModified(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HEAD %s: %d", url, resp.StatusCode)
	}
	return resp.Header.Get("Last-Modified"), nil
}

// syncStore is the persistence contract needed while processing one archive.
// It keeps the archive parser independently testable without a live Postgres DB.
type syncStore interface {
	BulkUpsertVulns(context.Context, []store.VulnRow) ([]string, error)
	ReindexVulnPackages(context.Context, []string) error
}

// downloadAndStore GETs the zip, saves it to a temporary file, parses each OSV
// record, and upserts it into vuln_record. ZIP readers require random access,
// but the archive must not occupy RAM proportional to its size.
func downloadAndStore(ctx context.Context, st *store.Store, eco model.Ecosystem, url string) (int, []string, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, 0, err
	}
	c := &http.Client{Timeout: httpTimeout}
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, nil, 0, fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}

	archive, err := os.CreateTemp("", "amparo-osv-*.zip")
	if err != nil {
		return 0, nil, 0, fmt.Errorf("creating temporary archive: %w", err)
	}
	archivePath := archive.Name()
	defer os.Remove(archivePath)

	bytesN, err := io.Copy(archive, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if closeErr := archive.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return 0, nil, bytesN, fmt.Errorf("saving zip: %w", err)
	}
	if bytesN > maxArchiveBytes {
		return 0, nil, bytesN, fmt.Errorf("zip exceeds compressed size limit of %d bytes", maxArchiveBytes)
	}

	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return 0, nil, bytesN, fmt.Errorf("opening zip: %w", err)
	}
	defer zr.Close()

	count, changed, err := storeArchive(ctx, st, eco, &zr.Reader)
	if err != nil {
		return count, changed, bytesN, err
	}
	return count, changed, bytesN, nil
}

// storeArchive validates and persists every advisory in an archive. A sync is
// complete only if every entry and every persistence batch succeeds.
func storeArchive(ctx context.Context, st syncStore, eco model.Ecosystem, zr *zip.Reader) (int, []string, error) {
	bucket, _ := bucketEcosystem(eco)
	count := 0
	var changedVulns []string
	// Buffer records and flush in batches via bulk COPY for speed. A per-record
	// upsert would take many minutes for large ecosystems (npm has ~40k records).
	const batchSize = 500
	var batch []store.VulnRow
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		// Collect the vuln IDs before consuming the batch for reindexing.
		ids := make([]string, len(batch))
		for i, r := range batch {
			ids[i] = r.OSVID
		}
		changed, err := st.BulkUpsertVulns(ctx, batch)
		if err != nil {
			return err
		}
		changedVulns = append(changedVulns, changed...)
		// Local matching depends on this normalized index. Treat an indexing
		// failure as a sync failure rather than claiming a partial DB is complete.
		if err := st.ReindexVulnPackages(ctx, ids); err != nil {
			return fmt.Errorf("reindexing vuln packages: %w", err)
		}
		count += len(batch)
		batch = batch[:0]
		return nil
	}

	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return count, changedVulns, fmt.Errorf("opening archive entry %q: %w", f.Name, err)
		}
		var vuln osvclient.Vulnerability
		dec := json.NewDecoder(rc)
		decodeErr := dec.Decode(&vuln)
		closeErr := rc.Close()
		if decodeErr != nil {
			return count, changedVulns, fmt.Errorf("decoding archive entry %q: %w", f.Name, decodeErr)
		}
		if closeErr != nil {
			return count, changedVulns, fmt.Errorf("closing archive entry %q: %w", f.Name, closeErr)
		}

		batch = append(batch, vulnToRow(bucket, &vuln))
		if len(batch) >= batchSize {
			if err := flush(); err != nil {
				return count, changedVulns, fmt.Errorf("persisting archive batch: %w", err)
			}
		}
	}
	if err := flush(); err != nil {
		return count, changedVulns, fmt.Errorf("persisting final archive batch: %w", err)
	}
	return count, changedVulns, nil
}

// vulnToRow converts an OSV Vulnerability into a VulnRow for bulk storage.
func vulnToRow(bucket string, v *osvclient.Vulnerability) store.VulnRow {
	cvss := osvclient.ScoreFromVectors(cvssVectorStrings(v.Severity))
	affectedJSON, _ := json.Marshal(v.Affected)
	fixed := collectFixedVersions(v)
	var withdrawn *time.Time
	if v.Withdrawn != "" {
		withdrawn = parseTimePtr(v.Withdrawn)
	}
	return store.VulnRow{
		OSVID:         v.ID,
		Aliases:       v.Aliases,
		Summary:       v.Summary,
		SeverityScore: float32(cvss),
		CVSSVectors:   cvssVectorStrings(v.Severity),
		FixedVersions: fixed,
		Affected:      affectedJSON,
		Ecosystem:     bucket, // store under the OSV bucket name for matching
		Modified:      parseTime(v.Modified),
		Published:     parseTimePtr(v.Published),
		WithdrawnAt:   withdrawn,
	}
}

// collectFixedVersions flattens all fixed events across affected ranges.
func collectFixedVersions(v *osvclient.Vulnerability) []string {
	var out []string
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					out = append(out, ev.Fixed)
				}
			}
		}
	}
	return out
}

// cvssVectorStrings extracts vector strings from the Severity slice.
// (Duplicated from osvclient.match.go to avoid exporting it; small enough.)
func cvssVectorStrings(sev []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) []string {
	out := make([]string, 0, len(sev))
	for _, s := range sev {
		out = append(out, s.Score)
	}
	return out
}

// --- minimal sync-metadata cache (Last-Modified per ecosystem) ---
// Stored in Postgres so it survives restarts. Uses a dedicated table created
// lazily (separate from versioned migrations to keep this self-contained).

type metaCache struct {
	pool *pgxpool.Pool
}

func newMetaCache(pool *pgxpool.Pool) *metaCache {
	return &metaCache{pool: pool}
}

func (m *metaCache) getLastModified(eco model.Ecosystem) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = m.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS osv_sync_meta (
		ecosystem TEXT PRIMARY KEY, last_modified TEXT, synced_at TIMESTAMPTZ)`)
	var lm string
	err := m.pool.QueryRow(ctx,
		`SELECT last_modified FROM osv_sync_meta WHERE ecosystem=$1`, string(eco)).Scan(&lm)
	if err != nil {
		return "", false
	}
	return lm, true
}

func (m *metaCache) setLastModified(ctx context.Context, eco model.Ecosystem, lm string) error {
	_, err := m.pool.Exec(ctx, `
		INSERT INTO osv_sync_meta (ecosystem, last_modified, synced_at)
		VALUES ($1,$2,now())
		ON CONFLICT (ecosystem) DO UPDATE SET last_modified=EXCLUDED.last_modified, synced_at=now()`,
		string(eco), lm)
	return err
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Now()
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Now()
	}
	return t
}

func parseTimePtr(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
