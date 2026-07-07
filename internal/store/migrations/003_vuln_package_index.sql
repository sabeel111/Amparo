-- 003_vuln_package_index.sql — normalized index for fast package→vuln lookups.
--
-- Problem: FindVulnsByPackage used `affected @> '[{"package":{"name":X}}]'::jsonb`,
-- a JSONB containment scan that's effectively full-table per package. Works in
-- dev (a few hundred deps) but melts Postgres at real scale (1000 deps × 50
-- projects re-matched on every vuln-DB delta).
--
-- Fix: a normalized join table vuln_package(ecosystem, name, vuln_id) populated
-- at sync time from each vuln_record's affected[].package entries. Lookups
-- become a simple indexed JOIN, and the continuity worker can find "which
-- stored dependencies match this changed vuln" without scanning JSONB.

CREATE TABLE IF NOT EXISTS vuln_package (
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    vuln_id     TEXT NOT NULL REFERENCES vuln_record(osv_id) ON DELETE CASCADE,
    -- The bucket ecosystem name (npm, PyPI, Go, crates.io) matches what the
    -- sync worker stores on vuln_record.ecosystem.
    PRIMARY KEY (ecosystem, name, vuln_id)
);

-- Index for the dominant query: "give me all vulns for THIS package".
CREATE INDEX IF NOT EXISTS idx_vuln_package_lookup
    ON vuln_package (ecosystem, name);

-- Backfill the index from existing vuln_record.affected JSONB. Each affected
-- entry has {"package":{"name":..., "ecosystem":...}}. We extract name pairs
-- and emit one vuln_package row per (affected package, vuln).
INSERT INTO vuln_package (ecosystem, name, vuln_id)
SELECT
    v.ecosystem,
    aff -> 'package' ->> 'name' AS name,
    v.osv_id
FROM vuln_record v,
     jsonb_array_elements(v.affected) AS aff
WHERE aff -> 'package' ->> 'name' IS NOT NULL
ON CONFLICT (ecosystem, name, vuln_id) DO NOTHING;
