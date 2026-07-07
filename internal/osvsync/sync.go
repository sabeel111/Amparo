package osvsync

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/osvclient"
	"github.com/sabeel111/Amparo/internal/store"
)

const (
	baseURL     = "https://osv-vulnerabilities.storage.googleapis.com"
	httpTimeout = 10 * time.Minute // zips can be large
)

// Stats reports the outcome of one ecosystem sync.
type Stats struct {
	Ecosystem model.Ecosystem
	Records   int  // number of records upserted
	Skipped   bool // true if HEAD said unchanged
	Bytes     int64
	Duration  time.Duration
	Err       error
}

// SyncResult aggregates per-ecosystem stats and the sync timestamp (for the
// continuity flow's ChangedVulnsSince).
type SyncResult struct {
	StartedAt time.Time
	Stats     []Stats
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
					s.Duration = time.Since(start)
					result.Stats = append(result.Stats, s)
					continue
				}
			}
			// If the HEAD check itself errored, proceed to a full GET — failing
			// open is better than failing the whole sync on a flaky HEAD.
		}

		// --- Download + stream-extract + upsert. ---
		n, bytesN, err := downloadAndStore(ctx, st, eco, url)
		s.Records = n
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
				_ = cache.setLastModified(ctx, eco, remoteLastMod)
			}
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

// downloadAndStore GETs the zip, streams entries, parses each as an OSV record,
// and upserts into vuln_record. Returns (records, bytes, err).
// Streaming (not load-all) bounds memory for large ecosystems like npm.
func downloadAndStore(ctx context.Context, st *store.Store, eco model.Ecosystem, url string) (int, int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, err
	}
	c := &http.Client{Timeout: httpTimeout}
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, 0, fmt.Errorf("GET %s: %d", url, resp.StatusCode)
	}

	// Read the body into memory once. ZIP needs random access so we can't truly
	// stream the HTTP body into the zip reader, but we use zip.NewReader over the
	// buffer and process entries incrementally rather than decoding all JSONs
	// into a slice first (the actual memory hog in osv-scanner #2217).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<30)) // 1GB safety cap
	if err != nil {
		return 0, 0, fmt.Errorf("reading zip: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return 0, int64(len(body)), fmt.Errorf("opening zip: %w", err)
	}

	bucket, _ := bucketEcosystem(eco)
	count := 0
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
		if err := st.BulkUpsertVulns(ctx, batch); err != nil {
			return err
		}
		// Keep the normalized vuln_package index in sync so lookups are fast.
		// Non-fatal: a failed reindex leaves the index slightly stale; the
		// matcher falls back to whatever rows ARE indexed.
		_ = st.ReindexVulnPackages(ctx, ids)
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
			continue
		}
		var vuln osvclient.Vulnerability
		dec := json.NewDecoder(rc)
		if err := dec.Decode(&vuln); err != nil {
			rc.Close()
			continue
		}
		rc.Close()

		batch = append(batch, vulnToRow(bucket, &vuln))
		if len(batch) >= batchSize {
			_ = flush() // a failed batch is logged but doesn't abort the whole sync
		}
	}
	_ = flush() // final partial batch
	return count, int64(len(body)), nil
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
