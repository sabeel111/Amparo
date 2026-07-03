package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VulnRow is a vuln_record as stored in the DB, used by the sync worker and the
// local matcher. Affected is kept as raw JSON for range matching at query time.
type VulnRow struct {
	OSVID           string
	Aliases         []string
	Summary         string
	SeverityScore   float32
	CVSSVectors     []string
	FixedVersions   []string
	Affected        json.RawMessage // []Affected — stored raw, decoded by matcher
	Ecosystem       string
	EPSSProbability float32
	EPSSPercentile  float32
	InKEV           bool
	WithdrawnAt     *time.Time
	Published       *time.Time
	Modified        time.Time
}

// FindingRow is a persisted finding.
type FindingRow struct {
	ID                  int64
	ProjectID           int64
	SnapshotID          int64
	DependencyPurl      string
	DependencyName      string
	DependencyVersion   string
	DependencyEcosystem string
	IsDirect            bool
	VulnID              string
	CVSS                float32
	EPSSProbability     float32
	EPSSPercentile      float32
	Priority            string
	Actionable          string
	Status              string
	FirstSeen           time.Time
	LastSeen            time.Time
}

// Store is the persistence interface used by the engine.
type Store struct {
	Pool *pgxpool.Pool
}

// New wraps an existing pool.
func New(pool *pgxpool.Pool) *Store { return &Store{Pool: pool} }

// EnsureProject returns the project id for (orgName, projectName), creating
// org and project if missing. Simplifies Phase 1 where we often have ad-hoc scans.
func (s *Store) EnsureProject(ctx context.Context, orgName, projectName string) (projectID int64, err error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	// Ensure org exists (idempotent). organization.name has a UNIQUE constraint,
	// so ON CONFLICT (name) DO NOTHING won't insert a duplicate.
	var orgID int64
	err = tx.QueryRow(ctx, `
		INSERT INTO organization (name) VALUES ($1)
		ON CONFLICT (name) DO NOTHING
		RETURNING id`, orgName).Scan(&orgID)
	if err == pgx.ErrNoRows {
		// Already existed — fetch its id.
		err = tx.QueryRow(ctx, `SELECT id FROM organization WHERE name=$1`, orgName).Scan(&orgID)
	}
	if err != nil {
		return 0, fmt.Errorf("ensure org: %w", err)
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO project (org_id, name) VALUES ($1, $2)
		ON CONFLICT (org_id, name) DO UPDATE SET name=EXCLUDED.name
		RETURNING id`, orgID, projectName).Scan(&projectID)
	if err != nil {
		return 0, fmt.Errorf("ensure project: %w", err)
	}
	return projectID, tx.Commit(ctx)
}

// CreateSnapshot inserts a snapshot and returns its id.
func (s *Store) CreateSnapshot(ctx context.Context, projectID int64, sha, manifestHash string) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO snapshot (project_id, sha, manifest_hash) VALUES ($1, $2, $3)
		RETURNING id`, projectID, nullable(sha), manifestHash).Scan(&id)
	return id, err
}

// InsertDependencies bulk-inserts dependencies for a snapshot via COPY.
func (s *Store) InsertDependencies(ctx context.Context, snapshotID int64, rows []DepRow) error {
	if len(rows) == 0 {
		return nil
	}
	_, err := s.Pool.CopyFrom(ctx,
		pgx.Identifier{"dependency"},
		[]string{"snapshot_id", "purl", "name", "version", "ecosystem", "scope", "is_direct"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			return []any{snapshotID, r.Purl, r.Name, r.Version, r.Ecosystem, r.Scope, r.IsDirect}, nil
		}))
	return err
}

// DepRow is a row for bulk dependency insert.
type DepRow struct {
	Purl      string
	Name      string
	Version   string
	Ecosystem string
	Scope     string
	IsDirect  bool
}

// UpsertVuln inserts or updates a vuln record (keyed by osv_id).
func (s *Store) UpsertVuln(ctx context.Context, v VulnRow) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO vuln_record (
			osv_id, aliases, summary, severity_score, cvss_vectors,
			fixed_versions, affected, ecosystem,
			epss_probability, epss_percentile, in_kev,
			withdrawn_at, published, modified, synced_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,now())
		ON CONFLICT (osv_id) DO UPDATE SET
			aliases=EXCLUDED.aliases,
			summary=EXCLUDED.summary,
			severity_score=EXCLUDED.severity_score,
			cvss_vectors=EXCLUDED.cvss_vectors,
			fixed_versions=EXCLUDED.fixed_versions,
			affected=EXCLUDED.affected,
			ecosystem=EXCLUDED.ecosystem,
			epss_probability=EXCLUDED.epss_probability,
			epss_percentile=EXCLUDED.epss_percentile,
			in_kev=EXCLUDED.in_kev,
			withdrawn_at=EXCLUDED.withdrawn_at,
			published=EXCLUDED.published,
			modified=EXCLUDED.modified,
			synced_at=now()`,
		v.OSVID, toJson(v.Aliases), v.Summary, v.SeverityScore, toJson(v.CVSSVectors),
		toJson(v.FixedVersions), v.Affected, v.Ecosystem,
		v.EPSSProbability, v.EPSSPercentile, v.InKEV,
		v.WithdrawnAt, v.Published, v.Modified)
	return err
}

// BulkUpsertVulns upserts many vuln records efficiently using COPY into a temp
// table, then a single INSERT...ON CONFLICT. This is orders of magnitude faster
// than per-record UpsertVuln for the OSV sync (which upserts tens of thousands
// of records per ecosystem).
func (s *Store) BulkUpsertVulns(ctx context.Context, rows []VulnRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Create a temp table with explicit columns matching what we COPY. We avoid
	// `LIKE vuln_record INCLUDING DEFAULTS` (some Postgres builds reject the
	// INCLUDING clause placement) by declaring columns directly.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE vuln_tmp (
			osv_id          TEXT,
			aliases         JSONB,
			summary         TEXT,
			severity_score  REAL,
			cvss_vectors    JSONB,
			fixed_versions  JSONB,
			affected        JSONB,
			ecosystem       TEXT,
			epss_probability REAL,
			epss_percentile  REAL,
			in_kev          BOOLEAN,
			withdrawn_at    TIMESTAMPTZ,
			published       TIMESTAMPTZ,
			modified        TIMESTAMPTZ,
			synced_at       TIMESTAMPTZ
		) ON COMMIT DROP`); err != nil {
		return fmt.Errorf("create temp: %w", err)
	}

	_, err = tx.CopyFrom(ctx,
		pgx.Identifier{"vuln_tmp"},
		[]string{"osv_id", "aliases", "summary", "severity_score", "cvss_vectors",
			"fixed_versions", "affected", "ecosystem",
			"epss_probability", "epss_percentile", "in_kev",
			"withdrawn_at", "published", "modified", "synced_at"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			return []any{
				r.OSVID, toJson(r.Aliases), r.Summary, r.SeverityScore, toJson(r.CVSSVectors),
				toJson(r.FixedVersions), r.Affected, r.Ecosystem,
				r.EPSSProbability, r.EPSSPercentile, r.InKEV,
				r.WithdrawnAt, r.Published, r.Modified, time.Now(),
			}, nil
		}))
	if err != nil {
		return fmt.Errorf("copy: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO vuln_record (
			osv_id, aliases, summary, severity_score, cvss_vectors,
			fixed_versions, affected, ecosystem,
			epss_probability, epss_percentile, in_kev,
			withdrawn_at, published, modified, synced_at)
		SELECT osv_id, aliases, summary, severity_score, cvss_vectors,
		       fixed_versions, affected, ecosystem,
		       epss_probability, epss_percentile, in_kev,
		       withdrawn_at, published, modified, synced_at
		FROM vuln_tmp
		ON CONFLICT (osv_id) DO UPDATE SET
			aliases=EXCLUDED.aliases,
			summary=EXCLUDED.summary,
			severity_score=EXCLUDED.severity_score,
			cvss_vectors=EXCLUDED.cvss_vectors,
			fixed_versions=EXCLUDED.fixed_versions,
			affected=EXCLUDED.affected,
			ecosystem=EXCLUDED.ecosystem,
			epss_probability=EXCLUDED.epss_probability,
			epss_percentile=EXCLUDED.epss_percentile,
			in_kev=EXCLUDED.in_kev,
			withdrawn_at=EXCLUDED.withdrawn_at,
			published=EXCLUDED.published,
			modified=EXCLUDED.modified,
			synced_at=now()`)
	if err != nil {
		return fmt.Errorf("upsert: %w", err)
	}
	return tx.Commit(ctx)
}

// FindVulnsByPackage returns all non-withdrawn vulns for an ecosystem+package.
// Used by the local matcher to find candidate records before range-evaluation.
func (s *Store) FindVulnsByPackage(ctx context.Context, ecosystem, name string) ([]VulnRow, error) {
	// affected is a JSON array; we filter with a containment check on the
	// package name. Range evaluation happens in Go (per ecosystem comparator).
	rows, err := s.Pool.Query(ctx, `
		SELECT osv_id, aliases, summary, severity_score, cvss_vectors,
		       fixed_versions, affected, ecosystem,
		       epss_probability, epss_percentile, in_kev,
		       withdrawn_at, published, modified
		FROM vuln_record
		WHERE ecosystem = $1 AND withdrawn_at IS NULL
		  AND affected @> $2::jsonb`,
		ecosystem, fmt.Sprintf(`[{"package":{"name":%q}}]`, name))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectVulns(rows)
}

// ChangedVulnsSince returns vuln_ids whose modified timestamp is after t.
// Used by the continuity flow to know which existing snapshots to re-match.
func (s *Store) ChangedVulnsSince(ctx context.Context, t time.Time) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT osv_id FROM vuln_record WHERE modified > $1`, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// UpsertFinding inserts a finding or, if the (project, purl, version, vuln)
// already exists, bumps last_seen. Returns whether the finding was newly created.
func (s *Store) UpsertFinding(ctx context.Context, f FindingRow) (created bool, err error) {
	var inserted bool
	err = s.Pool.QueryRow(ctx, `
		INSERT INTO finding (
			project_id, snapshot_id, dependency_purl, dependency_name,
			dependency_version, dependency_ecosystem, is_direct,
			vuln_id, cvss, epss_probability, epss_percentile,
			priority, actionable, status, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'new',now(),now())
		ON CONFLICT (project_id, dependency_purl, dependency_version, vuln_id)
		DO UPDATE SET last_seen=now(),
		              snapshot_id=EXCLUDED.snapshot_id,
		              cvss=EXCLUDED.cvss,
		              epss_probability=EXCLUDED.epss_probability,
		              epss_percentile=EXCLUDED.epss_percentile,
		              priority=EXCLUDED.priority,
		              actionable=EXCLUDED.actionable
		RETURNING (xmax = 0)`,
		f.ProjectID, f.SnapshotID, f.DependencyPurl, f.DependencyName,
		f.DependencyVersion, f.DependencyEcosystem, f.IsDirect,
		f.VulnID, f.CVSS, f.EPSSProbability, f.EPSSPercentile,
		f.Priority, f.Actionable).Scan(&inserted)
	if err != nil {
		return false, err
	}
	return inserted, nil
}

// FindingsByProject returns findings for a project, optionally filtered by status.
func (s *Store) FindingsByProject(ctx context.Context, projectID int64, status string) ([]FindingRow, error) {
	q := `SELECT id, project_id, snapshot_id, dependency_purl, dependency_name,
	             dependency_version, dependency_ecosystem, is_direct, vuln_id,
	             cvss, epss_probability, epss_percentile, priority, actionable,
	             status, first_seen, last_seen
	      FROM finding WHERE project_id=$1`
	args := []any{projectID}
	if status != "" {
		q += ` AND status=$2`
		args = append(args, status)
	}
	// Order critical > high > medium > low via a CASE, then most-recent first.
	q += ` ORDER BY CASE priority
			WHEN 'critical' THEN 4 WHEN 'high' THEN 3
			WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
	      last_seen DESC`
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectFindings(rows)
}

// CloseSnapshotFindings marks findings that belonged to a snapshot but are no
// longer present as 'fixed'. Called after a rescan to auto-close resolved issues.
// Phase 1 implementation: closes findings not present in the given snapshot.
func (s *Store) CloseSnapshotFindings(ctx context.Context, projectID, snapshotID int64) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE finding SET status='fixed'
		WHERE project_id=$1 AND status='new'
		  AND id NOT IN (SELECT id FROM finding WHERE snapshot_id=$2)`,
		projectID, snapshotID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// --- helpers ---

func collectVulns(rows pgx.Rows) ([]VulnRow, error) {
	var out []VulnRow
	for rows.Next() {
		var v VulnRow
		if err := rows.Scan(&v.OSVID, &v.Aliases, &v.Summary, &v.SeverityScore,
			&v.CVSSVectors, &v.FixedVersions, &v.Affected, &v.Ecosystem,
			&v.EPSSProbability, &v.EPSSPercentile, &v.InKEV,
			&v.WithdrawnAt, &v.Published, &v.Modified); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func collectFindings(rows pgx.Rows) ([]FindingRow, error) {
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.SnapshotID, &f.DependencyPurl,
			&f.DependencyName, &f.DependencyVersion, &f.DependencyEcosystem,
			&f.IsDirect, &f.VulnID, &f.CVSS, &f.EPSSProbability,
			&f.EPSSPercentile, &f.Priority, &f.Actionable, &f.Status,
			&f.FirstSeen, &f.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func toJson(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
