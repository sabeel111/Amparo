# Amparo — supply chain vulnerability tracker

A dependency vulnerability scanner for **npm, pip, Go, and Cargo** ecosystems
(Maven in Phase 2). It parses lockfiles, matches against a **locally-synced
[OSV.dev](https://osv.dev) database** (or the live API as fallback), enriches
with [EPSS](https://www.first.org/epss/) exploit-probability data, prioritizes by
real risk (not just CVSS), persists findings to **Postgres**, and gives a
concrete remediation path.

> Phase 1 of a larger supply-chain security platform. See
> [`docs/technical-design.md`](docs/technical-design.md) for the full architecture.

## What it does

1. **Parses** lockfiles: `package-lock.json`, `Pipfile.lock`, `poetry.lock`,
   `requirements.txt`, `go.sum`, `go.mod`, `Cargo.lock`.
2. **Matches** against a local OSV DB (synced via `sca sync`) for true continuity,
   or the live OSV.dev API as fallback.
3. **Computes CVSS** base scores from vector strings (deterministic, matches NVD).
4. **Enriches** with EPSS exploit probability + percentile (CVE-based).
5. **Prioritizes** findings by composite risk: CVSS + EPSS + fix-availability +
   direct-vs-transitive. High CVSS + EPSS ≥95th percentile → CRITICAL.
6. **Remediates**: picks the lowest fixed version and classifies the bump
   (patch/minor/major) so you know the risk.
7. **Persists** snapshots + findings to Postgres with finding-lifecycle dedup.
8. **Reports** as human-readable text or JSON.

## The continuity differentiator (Phase 1)

Most SCA tools scan on commit. This one stores the resolved dependency graph
once and **re-matches it against an evolving local vuln DB** — so a CVE that
drops today alerts on code you committed months ago, **without a rescan**.
`sca sync` keeps the local DB fresh; matching is a pure function of
`(dependency, DB state)`.

## Prerequisites

- **Go 1.22+**
- **Postgres 16** (Docker recommended): `docker compose up -d`

## Build

```bash
docker compose up -d          # start Postgres
go build -o bin/amparo ./cmd/amparo
```

## Usage

```bash
# 1. Sync the local vuln DB (one-time / periodic). Downloads OSV per-ecosystem zips.
./bin/amparo sync --ecosystems npm,PyPI,Go,cargo

# 2. Scan against the LOCAL DB (default if synced) and persist to Postgres
./bin/amparo scan --persist --project my-app ./my-project

# 3. List persisted findings
./bin/amparo findings my-app

# Scan against the LIVE OSV API (no local DB needed; Phase 0 behavior)
./bin/amparo scan --match live ./my-project

# JSON output for piping into other tools
./bin/amparo scan --format json ./my-project > report.json

# Skip EPSS (faster; loses exploit-probability signal)
./bin/amparo scan --no-epss ./my-project
```

> Note: flags must precede the path argument (Go's `flag` package stops parsing
> at the first non-flag). Use `scan --format json ./path`, not `scan ./path --format json`.

### Commands

| Command | Description |
|---------|-------------|
| `sync` | Download/update the local OSV vuln DB into Postgres |
| `scan <path>` | Scan a lockfile or directory; match local-or-live, optionally persist |
| `findings <project>` | List persisted findings from Postgres |
| `version` | Print version |

### Scan flags

| Flag | Default | Description |
|------|---------|-------------|
| `--match` | `auto` | Match source: `auto` (local if synced, else live), `local`, `live` |
| `--persist` | `false` | Write snapshot + findings to Postgres |
| `--project` | (path basename) | Project name for persistence |
| `--format` | `text` | Output format: `text` or `json` |
| `--no-epss` | `false` | Skip EPSS enrichment |
| `--timeout` | `120s` | Overall scan timeout |

### Environment

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://sca:sca@localhost:5432/sca?sslmode=disable` | Postgres connection |

## Example output

```
sca: parsed 3 dependencies from 1 lockfile(s); querying OSV...

  SCA Scan Results
  ──────────────────────────────────────────────────
  Dependencies scanned : 3
  Vulnerable findings  : 30  (1 critical, 12 high, 14 medium, 1 low)
  Actionable now        : 30   (no fix / monitor: 0)
  ──────────────────────────────────────────────────

  ┌─ CRITICAL ───────────────────────────────────────
  │ 🔴 minimist@1.2.0
  │   GHSA-xvch-5gv4-984h  Prototype Pollution in minimist
  │   aliases: CVE-2021-44906
  │   CVSS 9.8 · EPSS 90.5%ile · direct dep
  │   fix: upgrade to 1.2.6  (patch bump)
  │   why: CVSS 9.8; EPSS 4.6% exploit probability (90.5% percentile); ...
```

## How prioritization works

Raw CVSS is why devs ignore SCA tools. This scanner computes a **composite
priority** from multiple signals:

- **CVSS** score → base severity band (computed from the vector, not guessed).
- **EPSS percentile** → exploit probability. ≥95th percentile + high CVSS
  promotes a finding to CRITICAL ("exploit likely").
- **Fix availability** → `actionable_now` (a fix exists) vs `monitor` (no fix).
- **Direct vs transitive** → direct deps have higher exposure.

Every finding carries a `reasons[]` list explaining the score — auditable by
design, and the same grounded input the future AI layer will consume.

## Architecture

```
Lockfile → Parser (per-ecosystem) → []Dependency
   → Matcher (local DB OR live OSV API, shared range logic) → []Finding
   → EPSS enrichment (CVE-keyed, degrades gracefully)
   → Prioritizer (composite risk)
   → Remediation engine (lowest fixed version + bump type)
   → [optional] Persist to Postgres (snapshot + deduped findings)
   → Report (text | JSON)

Continuity (Flow B): OSV sync → changed vulns → re-match existing snapshots
                      → new findings, no rescan needed.
```

| Package | Responsibility |
|---------|----------------|
| `internal/model` | Core domain types + version comparators (semver, PEP 440, Go pseudo-versions) |
| `internal/parser` | Lockfile parser registry + auto-detection |
| `internal/parser/{npm,pip,go,cargo}` | Per-ecosystem lockfile parsers |
| `internal/osvclient` | OSV.dev API client (live path) + CVSS v3.1 calculator |
| `internal/osvsync` | Local OSV DB sync worker (per-ecosystem all.zip, HEAD-first) |
| `internal/matcher` | Shared range-matching logic (LocalMatcher + reusable by LiveMatcher) |
| `internal/store` | Postgres persistence (pgx) + embedded migrations + repository layer |
| `internal/epss` | EPSS enrichment (FIRST.org API) |
| `internal/prioritize` | Composite risk scoring |
| `internal/remediate` | Fixed-version selection + bump classification |
| `internal/report` | Text + JSON rendering |
| `cmd/sca` | CLI entry point (sync / scan / findings) |

## Design principles

- **Determinism where it matters.** Version matching, CVSS scoring, and
  remediation are pure functions. Given the same inputs, same output — always.
- **Shared matcher logic.** The live and local matchers use the same range
  evaluation, so they produce identical findings for the same input (verified by
  `TestLocalVsLiveCrossCheck`).
- **Ecosystem-aware versioning.** PyPI uses PEP 440, Go uses pseudo-versions, not
  semver. Each ecosystem uses the correct comparator.
- **Graceful degradation.** EPSS failure doesn't break a scan; if the local DB is
  empty, matching falls back to the live API automatically.
- **Continuity by design.** Matching is a pure function of `(dependency, DB state)`,
  so a DB update can surface new findings on old snapshots without rescanning.

## Tests

```bash
docker compose up -d      # Postgres must be running for integration tests
go test ./...
```

Tests cover the correctness-critical pieces: version comparison (semver, PEP 440,
Go pseudo-versions), CVSS v3.1 scoring (verified against NVD), EPSS batching,
Postgres persistence + finding dedup, the local-vs-live matcher cross-check, and
the real OSV sync (live, skipped if offline).

## Roadmap (from the design doc)

- **Phase 1 (v0.5):** local OSV sync (true continuity), Go + Cargo ecosystems,
  Postgres persistence, Next.js dashboard, GitHub App, KEV feed.
- **Phase 2 (v1):** Maven (effective-POM resolver), reachability, AI layer
  (grounded risk explanations, team worklists), multi-tenant auth, SBOM export.
