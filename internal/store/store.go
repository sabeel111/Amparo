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
	if err != nil {
		return err
	}
	// Keep the vuln_package index in sync so FindVulnsByPackage (which reads the
	// index, not the JSONB) returns this record.
	return s.ReindexVulnPackages(ctx, []string{v.OSVID})
}

// BulkUpsertVulns upserts many vuln records efficiently using COPY into a temp
// table, then a single INSERT...ON CONFLICT. It returns exactly the IDs that
// were inserted or materially changed, so callers can trigger continuity
// without inferring change from advisory timestamps.
func (s *Store) BulkUpsertVulns(ctx context.Context, rows []VulnRow) ([]string, error) {
	if len(rows) == 0 {
		return nil, nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("create temp: %w", err)
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
		return nil, fmt.Errorf("copy: %w", err)
	}

	changedRows, err := tx.Query(ctx, `
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
			synced_at=now()
		WHERE vuln_record.aliases IS DISTINCT FROM EXCLUDED.aliases
		   OR vuln_record.summary IS DISTINCT FROM EXCLUDED.summary
		   OR vuln_record.severity_score IS DISTINCT FROM EXCLUDED.severity_score
		   OR vuln_record.cvss_vectors IS DISTINCT FROM EXCLUDED.cvss_vectors
		   OR vuln_record.fixed_versions IS DISTINCT FROM EXCLUDED.fixed_versions
		   OR vuln_record.affected IS DISTINCT FROM EXCLUDED.affected
		   OR vuln_record.ecosystem IS DISTINCT FROM EXCLUDED.ecosystem
		   OR vuln_record.epss_probability IS DISTINCT FROM EXCLUDED.epss_probability
		   OR vuln_record.epss_percentile IS DISTINCT FROM EXCLUDED.epss_percentile
		   OR vuln_record.in_kev IS DISTINCT FROM EXCLUDED.in_kev
		   OR vuln_record.withdrawn_at IS DISTINCT FROM EXCLUDED.withdrawn_at
		   OR vuln_record.published IS DISTINCT FROM EXCLUDED.published
		   OR vuln_record.modified IS DISTINCT FROM EXCLUDED.modified
		RETURNING osv_id`)
	if err != nil {
		return nil, fmt.Errorf("upsert: %w", err)
	}
	defer changedRows.Close()

	var changed []string
	for changedRows.Next() {
		var id string
		if err := changedRows.Scan(&id); err != nil {
			return nil, fmt.Errorf("reading changed vulnerability ID: %w", err)
		}
		changed = append(changed, id)
	}
	if err := changedRows.Err(); err != nil {
		return nil, fmt.Errorf("reading changed vulnerability IDs: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return changed, nil
}

// FindVulnsByPackage returns all non-withdrawn vulns for an ecosystem+package.
// Uses the normalized vuln_package index (migration 003) for an index-backed
// JOIN instead of a JSONB containment scan — the difference between milliseconds
// and a full-table scan at scale.
func (s *Store) FindVulnsByPackage(ctx context.Context, ecosystem, name string) ([]VulnRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT v.osv_id, v.aliases, v.summary, v.severity_score, v.cvss_vectors,
		       v.fixed_versions, v.affected, v.ecosystem,
		       v.epss_probability, v.epss_percentile, v.in_kev,
		       v.withdrawn_at, v.published, v.modified
		FROM vuln_package vp
		JOIN vuln_record v ON v.osv_id = vp.vuln_id
		WHERE vp.ecosystem = $1 AND vp.name = $2 AND v.withdrawn_at IS NULL`,
		ecosystem, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectVulns(rows)
}

// ReindexVulnPackages rebuilds the vuln_package index rows for the given vuln
// IDs. Called by the sync worker after each batch upsert so the index stays in
// sync with the affected[] data without a full rebuild.
func (s *Store) ReindexVulnPackages(ctx context.Context, vulnIDs []string) error {
	if len(vulnIDs) == 0 {
		return nil
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Delete existing index rows for these vulns, then re-insert from affected[].
	// This handles removed/renamed packages correctly on update.
	if _, err := tx.Exec(ctx,
		`DELETE FROM vuln_package WHERE vuln_id = ANY($1)`, vulnIDs); err != nil {
		return fmt.Errorf("reindex delete: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO vuln_package (ecosystem, name, vuln_id)
		SELECT v.ecosystem, aff -> 'package' ->> 'name', v.osv_id
		FROM vuln_record v, jsonb_array_elements(v.affected) AS aff
		WHERE v.osv_id = ANY($1) AND aff -> 'package' ->> 'name' IS NOT NULL
		ON CONFLICT (ecosystem, name, vuln_id) DO NOTHING`, vulnIDs); err != nil {
		return fmt.Errorf("reindex insert: %w", err)
	}
	return tx.Commit(ctx)
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

// DepRowWithProject is a dependency plus its owning project — the shape the
// continuity worker needs to re-match stored deps against changed vulns and
// re-persist findings under the right project/snapshot.
type DepRowWithProject struct {
	DepRow
	ProjectID  int64
	SnapshotID int64
}

// DepsAffectedByVulns returns stored dependencies whose (ecosystem, name) is
// named in ANY of the given vuln IDs' affected packages. This is the continuity
// candidate set: only these deps could newly match a changed vuln, so we avoid
// re-scanning the entire dependency graph.
//
// Joins: vuln_package (changed vulns) → dependency (stored deps) on
// (ecosystem, name). This is index-backed and cheap.
func (s *Store) DepsAffectedByVulns(ctx context.Context, vulnIDs []string) ([]DepRowWithProject, error) {
	if len(vulnIDs) == 0 {
		return nil, nil
	}
	// We normalize ecosystems: deps store internal names (npm, PyPI, Go, cargo);
	// vuln_package stores OSV bucket names (npm, PyPI, Go, crates.io). Cargo is
	// the only mismatch, so we bridge it in the JOIN condition.
	rows, err := s.Pool.Query(ctx, `
		SELECT DISTINCT d.snapshot_id, d.purl, d.name, d.version, d.ecosystem,
		                 d.scope, d.is_direct, snap.project_id
		FROM dependency d
		JOIN snapshot snap ON snap.id = d.snapshot_id
		JOIN vuln_package vp ON
		      (vp.ecosystem = d.ecosystem
		       OR (vp.ecosystem = 'crates.io' AND d.ecosystem = 'cargo'))
		  AND vp.name = d.name
		WHERE vp.vuln_id = ANY($1)`, vulnIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DepRowWithProject
	for rows.Next() {
		var r DepRowWithProject
		if err := rows.Scan(&r.SnapshotID, &r.Purl, &r.Name, &r.Version,
			&r.Ecosystem, &r.Scope, &r.IsDirect, &r.ProjectID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
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

// --- Dashboard queries (used by the HTTP API in internal/server) ---

// ProjectRow is a project with aggregated finding counts, for the project list.
type ProjectRow struct {
	ID            int64
	OrgName       string
	Name          string
	TotalFindings int
	OpenFindings  int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	LastScanned   *time.Time // most recent snapshot.created_at
}

// ListProjects returns all projects with aggregated finding counts. Uses GROUP
// BY aggregation rather than pulling rows in-memory.
func (s *Store) ListProjects(ctx context.Context) ([]ProjectRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT p.id, o.name, p.name,
		       COUNT(f.id) AS total,
		       COUNT(f.id) FILTER (WHERE f.status IN ('new','triaged')) AS open,
		       COUNT(f.id) FILTER (WHERE f.priority='critical' AND f.status IN ('new','triaged')) AS crit,
		       COUNT(f.id) FILTER (WHERE f.priority='high' AND f.status IN ('new','triaged')) AS high,
		       COUNT(f.id) FILTER (WHERE f.priority='medium' AND f.status IN ('new','triaged')) AS med,
		       COUNT(f.id) FILTER (WHERE f.priority='low' AND f.status IN ('new','triaged')) AS low,
		       MAX(snap.created_at) AS last_scanned
		FROM project p
		JOIN organization o ON o.id = p.org_id
		LEFT JOIN finding f ON f.project_id = p.id
		LEFT JOIN snapshot snap ON snap.id = (
		    SELECT id FROM snapshot WHERE project_id = p.id ORDER BY created_at DESC LIMIT 1)
		GROUP BY p.id, o.name, p.name
		ORDER BY (COUNT(f.id) FILTER (WHERE f.status IN ('new','triaged'))) DESC, p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProjectRow
	for rows.Next() {
		var p ProjectRow
		if err := rows.Scan(&p.ID, &p.OrgName, &p.Name, &p.TotalFindings,
			&p.OpenFindings, &p.CriticalCount, &p.HighCount,
			&p.MediumCount, &p.LowCount, &p.LastScanned); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProjectSummaryRow is the severity/status breakdown for one project.
type ProjectSummaryRow struct {
	Total      int
	Critical   int
	High       int
	Medium     int
	Low        int
	Open       int
	Fixed      int
	Direct     int
	Transitive int
	Exploited  int // EPSS percentile >= 0.95 (the "act now" signal)
}

// ProjectSummary computes the dashboard summary for a project via SQL GROUP BY.
// "Open" = status new|triaged (not yet fixed/suppressed).
func (s *Store) ProjectSummary(ctx context.Context, projectID int64) (ProjectSummaryRow, error) {
	var ps ProjectSummaryRow
	err := s.Pool.QueryRow(ctx, `
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE priority='critical'),
		  COUNT(*) FILTER (WHERE priority='high'),
		  COUNT(*) FILTER (WHERE priority='medium'),
		  COUNT(*) FILTER (WHERE priority='low'),
		  COUNT(*) FILTER (WHERE status IN ('new','triaged')),
		  COUNT(*) FILTER (WHERE status='fixed'),
		  COUNT(*) FILTER (WHERE is_direct AND status IN ('new','triaged')),
		  COUNT(*) FILTER (WHERE NOT is_direct AND status IN ('new','triaged')),
		  COUNT(*) FILTER (WHERE epss_percentile >= 0.95 AND status IN ('new','triaged'))
		FROM finding WHERE project_id=$1`, projectID).Scan(
		&ps.Total, &ps.Critical, &ps.High, &ps.Medium, &ps.Low,
		&ps.Open, &ps.Fixed, &ps.Direct, &ps.Transitive, &ps.Exploited)
	return ps, err
}

// FindingFilters controls the findings-list query for the dashboard.
type FindingFilters struct {
	Status    string // "open" (new|triaged), "fixed", "suppressed", "" (all)
	Severity  string // critical|high|medium|low, "" = all
	Ecosystem string // npm|PyPI|Go|cargo, "" = all
	OnlyEPSS  bool   // only EPSS percentile >= 0.95
	Query     string // free-text on package name / vuln id
	Limit     int    // 0 = default 200
}

// DetailedFinding is a FindingRow enriched with the vuln record's summary,
// aliases, and fixed versions — the shape the dashboard needs. Populated via a
// JOIN on vuln_record.
type DetailedFinding struct {
	FindingRow
	Summary       string   `json:"summary"`
	Aliases       []string `json:"aliases"`
	FixedVersions []string `json:"fixed_versions"`
}

// FindingsByProjectDetailed is like FindingsByProject but JOINs vuln_record so
// each finding carries its advisory summary, aliases, and fixed versions.
// Supports the dashboard filters. Index-backed: uses idx_finding_project_status
// and the vuln_record PK.
func (s *Store) FindingsByProjectDetailed(ctx context.Context, projectID int64, f FindingFilters) ([]DetailedFinding, error) {
	q := `
		SELECT f.id, f.project_id, f.snapshot_id, f.dependency_purl,
		       f.dependency_name, f.dependency_version, f.dependency_ecosystem,
		       f.is_direct, f.vuln_id, f.cvss, f.epss_probability, f.epss_percentile,
		       f.priority, f.actionable, f.status, f.first_seen, f.last_seen,
		       COALESCE(v.summary, ''), COALESCE(v.aliases, '[]'), COALESCE(v.fixed_versions, '[]')
		FROM finding f
		LEFT JOIN vuln_record v ON v.osv_id = f.vuln_id
		WHERE f.project_id = $1`
	args := []any{projectID}
	n := 2
	if f.Status == "open" {
		q += fmt.Sprintf(` AND f.status IN ('new','triaged')`)
	} else if f.Status != "" {
		q += fmt.Sprintf(` AND f.status = $%d`, n)
		args = append(args, f.Status)
		n++
	}
	if f.Severity != "" {
		q += fmt.Sprintf(` AND f.priority = $%d`, n)
		args = append(args, f.Severity)
		n++
	}
	if f.Ecosystem != "" {
		q += fmt.Sprintf(` AND f.dependency_ecosystem = $%d`, n)
		args = append(args, normalizeEcosystem(f.Ecosystem))
		n++
	}
	if f.OnlyEPSS {
		q += ` AND f.epss_percentile >= 0.95`
	}
	if f.Query != "" {
		q += fmt.Sprintf(` AND (f.dependency_name ILIKE $%d OR f.vuln_id ILIKE $%d)`, n, n)
		args = append(args, "%"+f.Query+"%")
		n++
	}
	q += ` ORDER BY CASE f.priority WHEN 'critical' THEN 4 WHEN 'high' THEN 3
	          WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC,
	          f.epss_percentile DESC NULLS LAST, f.last_seen DESC`
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	q += fmt.Sprintf(` LIMIT %d`, limit)

	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DetailedFinding
	for rows.Next() {
		var d DetailedFinding
		if err := rows.Scan(&d.ID, &d.ProjectID, &d.SnapshotID, &d.DependencyPurl,
			&d.DependencyName, &d.DependencyVersion, &d.DependencyEcosystem,
			&d.IsDirect, &d.VulnID, &d.CVSS, &d.EPSSProbability, &d.EPSSPercentile,
			&d.Priority, &d.Actionable, &d.Status, &d.FirstSeen, &d.LastSeen,
			&d.Summary, &d.Aliases, &d.FixedVersions); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateFindingStatus sets a finding's status (triage/dismiss). Returns an error
// if the finding doesn't exist.
func (s *Store) UpdateFindingStatus(ctx context.Context, findingID int64, status string) error {
	tag, err := s.Pool.Exec(ctx,
		`UPDATE finding SET status=$1 WHERE id=$2`, status, findingID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finding %d not found", findingID)
	}
	return nil
}

// normalizeEcosystem maps UI-friendly names to the internal DB spellings.
// The UI sends "npm"/"pypi"/"go"/"cargo"; the DB stores "npm"/"PyPI"/"Go"/"cargo".
func normalizeEcosystem(s string) string {
	switch s {
	case "pypi":
		return "PyPI"
	case "go":
		return "Go"
	}
	return s
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
