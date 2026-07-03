-- 001_init.sql — Phase 1 core schema
-- Materialized from design doc §10. Finding lifecycle is keyed by
-- (dependency_purl, dependency_version, vuln_id) so the same issue seen across
-- scans is ONE record with first_seen/last_seen, not duplicates.

-- Organizations / projects / sources (minimal for Phase 1; multi-tenant RBAC later)
CREATE TABLE IF NOT EXISTS organization (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project (
    id          BIGSERIAL PRIMARY KEY,
    org_id      BIGINT NOT NULL REFERENCES organization(id),
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

CREATE TABLE IF NOT EXISTS source (
    id          BIGSERIAL PRIMARY KEY,
    project_id  BIGINT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,            -- 'upload' | 'github' | 'ci' (Phase 1: 'upload')
    config      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Immutable resolved dependency set per scan
CREATE TABLE IF NOT EXISTS snapshot (
    id            BIGSERIAL PRIMARY KEY,
    project_id    BIGINT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    sha           TEXT,                    -- source revision/hash, if known
    manifest_hash TEXT NOT NULL,           -- hash of the parsed lockfiles
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_snapshot_project ON snapshot(project_id, created_at DESC);

-- Resolved dependencies belonging to a snapshot (the dependency graph)
CREATE TABLE IF NOT EXISTS dependency (
    id            BIGSERIAL PRIMARY KEY,
    snapshot_id   BIGINT NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
    purl          TEXT NOT NULL,           -- e.g. pkg:npm/lodash@4.17.20
    name          TEXT NOT NULL,
    version       TEXT NOT NULL,
    ecosystem     TEXT NOT NULL,           -- npm | PyPI | Maven | Go | cargo
    scope         TEXT NOT NULL DEFAULT '',-- runtime | dev | ... (empty if unknown)
    is_direct     BOOLEAN NOT NULL DEFAULT false,
    parent_dependency_id BIGINT REFERENCES dependency(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dependency_snapshot ON dependency(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_dependency_lookup ON dependency(ecosystem, name, version);

-- Local vulnerability DB (synced from OSV via internal/osvsync)
CREATE TABLE IF NOT EXISTS vuln_record (
    osv_id          TEXT PRIMARY KEY,      -- GHSA-... | CVE-... | PYSEC-...
    aliases         JSONB NOT NULL DEFAULT '[]',
    summary         TEXT NOT NULL DEFAULT '',
    severity_score  REAL NOT NULL DEFAULT 0,  -- CVSS base score (computed)
    cvss_vectors    JSONB NOT NULL DEFAULT '[]',
    fixed_versions  JSONB NOT NULL DEFAULT '[]',  -- aggregated per affected package
    affected        JSONB NOT NULL DEFAULT '[]',  -- raw affected[] for range matching
    ecosystem       TEXT NOT NULL DEFAULT '',     -- the synced ecosystem (npm, PyPI, ...)
    epss_probability REAL NOT NULL DEFAULT 0,
    epss_percentile  REAL NOT NULL DEFAULT 0,
    in_kev         BOOLEAN NOT NULL DEFAULT false,
    withdrawn_at    TIMESTAMPTZ,
    published       TIMESTAMPTZ,
    modified        TIMESTAMPTZ NOT NULL DEFAULT now(),
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Lookup: find vulns affecting a given (ecosystem, package)
CREATE INDEX IF NOT EXISTS idx_vuln_ecosystem ON vuln_record(ecosystem);
-- Change detection for sync: which vulns changed since X
CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vuln_record(modified);

-- Findings: a vulnerability match against a specific dependency version.
CREATE TABLE IF NOT EXISTS finding (
    id                  BIGSERIAL PRIMARY KEY,
    project_id          BIGINT NOT NULL REFERENCES project(id) ON DELETE CASCADE,
    snapshot_id         BIGINT NOT NULL REFERENCES snapshot(id) ON DELETE CASCADE,
    dependency_purl     TEXT NOT NULL,
    dependency_name     TEXT NOT NULL,
    dependency_version  TEXT NOT NULL,
    dependency_ecosystem TEXT NOT NULL,
    is_direct           BOOLEAN NOT NULL DEFAULT false,
    vuln_id             TEXT NOT NULL REFERENCES vuln_record(osv_id),
    cvss                REAL NOT NULL DEFAULT 0,
    epss_probability    REAL NOT NULL DEFAULT 0,
    epss_percentile     REAL NOT NULL DEFAULT 0,
    priority            TEXT NOT NULL,     -- critical | high | medium | low
    actionable          TEXT NOT NULL,     -- actionable_now | monitor
    status              TEXT NOT NULL DEFAULT 'new', -- new | triaged | fixed | suppressed
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Finding lifecycle / dedup lookup by (purl+version, vuln_id)
CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_dedup
    ON finding(project_id, dependency_purl, dependency_version, vuln_id);
CREATE INDEX IF NOT EXISTS idx_finding_project_status
    ON finding(project_id, status, priority);
CREATE INDEX IF NOT EXISTS idx_finding_vuln ON finding(vuln_id);
