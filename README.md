<div align="center">

# 🛡️ Amparo

### Supply chain vulnerability tracker

Continuous software composition analysis across **npm, pip, Go, and Cargo** —
monitor dependencies against a locally-synced [OSV.dev](https://osv.dev)
database, prioritize by real risk (not just CVSS), and get a clear path to
remediation.

*Amparo* (Spanish: *protection, shelter*)

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Postgres](https://img.shields.io/badge/Postgres-16-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/license-TBD-lightgrey)](#license)
[![Status](https://img.shields.io/badge/status-alpha-orange)](#project-status)

</div>

---

## 📖 Table of contents

- [What it does](#-what-it-does)
- [The continuity differentiator](#-the-continuity-differentiator)
- [Quick start](#-quick-start)
- [Usage reference](#-usage-reference)
- [How prioritization works](#-how-prioritization-works)
- [Supported ecosystems](#-supported-ecosystems)
- [Architecture](#-architecture)
- [Data model](#-data-model)
- [Configuration](#-configuration)
- [Development](#-development)
- [Testing](#-testing)
- [Design principles](#-design-principles)
- [Project status & known limitations](#-project-status--known-limitations)
- [Roadmap](#-roadmap)
- [Documentation](#-documentation)
- [License](#-license)

---

## ✨ What it does

Given a lockfile (or a directory of them), Amparo:

1. **Parses** the lockfile into a fully-resolved dependency set (including
   transitive deps where the lockfile provides them).
2. **Matches** each dependency against a locally-synced OSV.dev database — or
   the live OSV API as an automatic fallback.
3. **Scores** each match using CVSS (computed from the vector string, matching
   NVD exactly) enriched with EPSS exploit probability.
4. **Prioritizes** findings into critical/high/medium/low bands using a
   composite model — high CVSS + EPSS ≥95th percentile promotes to CRITICAL.
5. **Remediates** by selecting the lowest fixed version and classifying the bump
   (patch / minor / major).
6. **Persists** (optionally) the snapshot + findings to Postgres, with
   finding-lifecycle dedup so the same issue across rescans is one record.
7. **Reports** as a readable text summary or structured JSON.

> **Note:** Amparo is in **alpha**. The engine is correct and validated against
> real data, but it is not yet a complete product — see
> [Project status](#-project-status--known-limitations).

---

## 🔁 The continuity differentiator

Most SCA tools scan on commit and forget. Amparo is built for **continuity**:

```
  Traditional SCA:                    Amparo continuity (Flow B):
  ─────────────────                   ───────────────────────────
  commit ──▶ scan ──▶ report          OSV DB updates (daily)
         (then forget)                       │
                                              ▼
                                    re-match EXISTING snapshots
                                              │
                                              ▼
                                    new findings, NO rescan
```

Because matching is a **pure function of `(dependency, DB state)`**, a freshly
synced advisory surfaces on previously-scanned code automatically. `amparo sync`
keeps the local DB fresh; the continuity invariant (re-matching is idempotent,
changes are tracked via `ChangedVulnsSince`) is verified by test.

---

## 🚀 Quick start

### Prerequisites

- **Go 1.22+**
- **Docker** (for Postgres) — or a reachable Postgres 16 instance

### 1. Start Postgres

```bash
docker compose up -d
```

This starts a Postgres 16 container on port 5432 with a named volume. Amparo
runs migrations automatically on first connect.

### 2. Build

```bash
go build -o bin/amparo ./cmd/amparo
```

### 3. Sync the vulnerability database

```bash
# Sync a small ecosystem first (Go is ~8k records, ~5 seconds)
./bin/amparo sync --ecosystems Go

# Sync all supported ecosystems (npm is ~220k records, ~15 minutes)
./bin/amparo sync --ecosystems npm,PyPI,Go,cargo
```

### 4. Scan

```bash
# Scan against the local DB (default if synced) and persist to Postgres
./bin/amparo scan --persist --project my-app ./my-project

# Review persisted findings
./bin/amparo findings my-app
```

### 5. (Optional) Scan without a local DB — live API

```bash
./bin/amparo scan --match live ./my-project
```

---

## 📚 Usage reference

> **Flag ordering:** flags must precede the path argument
> (`amparo scan --format json ./path`, not `amparo scan ./path --format json`).
> This is standard Go `flag` behavior.

### Commands

| Command | Description |
|---------|-------------|
| `amparo sync` | Download / update the local OSV vuln DB into Postgres |
| `amparo scan <path>` | Scan a lockfile or directory; match local-or-live |
| `amparo findings <project>` | List persisted findings from Postgres |
| `amparo version` | Print version |
| `amparo help` | Show help |

### `sync` — populate the local vuln DB

```bash
amparo sync [--ecosystems LIST] [--force]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--ecosystems` | `all` | Comma-separated list: `npm,PyPI,Go,cargo,Maven`, or `all` |
| `--force` | `false` | Re-download even if unchanged (bypasses HEAD check) |

Downloads per-ecosystem `all.zip` archives from the OSV.dev GCS bucket, parses
each record, and bulk-upserts into the `vuln_record` table. Uses HTTP `HEAD` +
`Last-Modified` to skip re-downloads when nothing changed.

### `scan` — find vulnerabilities

```bash
amparo scan [flags] <path>
```

| Flag | Default | Description |
|------|---------|-------------|
| `--match` | `auto` | Match source: `auto` (local if synced, else live), `local`, `live` |
| `--persist` | `false` | Write the snapshot + findings to Postgres |
| `--project` | *(path basename)* | Project name (used with `--persist`) |
| `--format` | `text` | Output format: `text` or `json` |
| `--no-epss` | `false` | Skip EPSS enrichment (faster; loses exploit-probability signal) |
| `--timeout` | `120s` | Overall scan timeout |

**`--match` modes:**
- `auto` (default): uses the local DB if it has records, otherwise falls back to
  the live OSV API. Graceful — never hard-fails on a missing DB.
- `local`: match only against Postgres. Errors if the DB is empty/unreachable.
- `live`: match only against the live OSV.dev API (Phase 0 behavior).

### `findings` — query persisted results

```bash
amparo findings [--status S] [--format F] <project>
```

| Flag | Default | Description |
|------|---------|-------------|
| `--status` | *(all)* | Filter: `new`, `fixed`, `triaged`, `suppressed` |
| `--format` | `text` | Output format: `text` or `json` |

---

## 🧮 How prioritization works

Raw CVSS is why developers ignore SCA tools. Amparo computes a **composite
priority** from multiple deterministic signals:

| Signal | Source | Effect |
|--------|--------|--------|
| **CVSS** score | Computed from the vector string (matches NVD) | Base severity band |
| **EPSS percentile** | [FIRST.org](https://www.first.org/epss/) | Boost if ≥95th percentile (exploit likely) |
| **Fix availability** | OSV `fixed_versions` | `actionable_now` vs. `monitor` (no fix) |
| **Direct vs. transitive** | Lockfile structure | Direct deps = higher exposure |

### Composite buckets

```
CRITICAL  ←  high CVSS AND EPSS ≥95th percentile (exploit likely)
HIGH      ←  CVSS ≥ 7.0
MEDIUM    ←  CVSS ≥ 4.0
LOW       ←  otherwise

ACTIONABLE_NOW  ←  a fixed version exists within constraints
MONITOR         ←  no fix published yet
```

Every finding carries a `reasons[]` array explaining the score in plain English:

```
why: CVSS 9.8; EPSS 4.6% exploit probability (90.5% percentile);
     direct dependency (higher exposure than transitive);
     boosted to CRITICAL: high CVSS + EPSS ≥95th percentile (exploit likely)
```

This audit trail is the foundation for the planned **AI layer** (see
[design doc §8.5](docs/technical-design.md)) — the LLM consumes these grounded
signals to produce "why this matters, here, now" explanations, never replacing
the deterministic scoring.

---

## 🌍 Supported ecosystems

| Ecosystem | Manifest | Lockfile(s) | Version scheme | Status |
|-----------|----------|-------------|----------------|--------|
| **npm** | `package.json` | `package-lock.json` (v1/v2/v3), `yarn.lock`, `pnpm-lock.yaml` | semver | ✅ Full |
| **pip** | `requirements.txt`, `pyproject.toml`, `Pipfile` | `Pipfile.lock`, `poetry.lock`, `uv.lock` | PEP 440 | ⚠️ Lockfile-only* |
| **Go** | `go.mod` | `go.sum` | semver + pseudo-versions | ✅ Full |
| **Cargo** | `Cargo.toml` | `Cargo.lock` | semver | ✅ Full |
| **Maven** | `pom.xml` | — | Maven versioning | 🚧 Phase 2 |

> *\* pip: only lockfile-based scanning is fully supported today. `requirements.txt`
> without a lockfile misses transitive dependencies — see
> [known limitations](#-project-status--known-limitations).*

Each ecosystem uses the **correct version comparator** — PyPI uses PEP 440 (not
semver), Go uses a pseudo-version comparator for `v0.0.0-20240102-abcdef` forms.
This prevents a class of false results common in naive SCA tools.

---

## 🏗️ Architecture

```
                        ┌─────────────────────────────────────────────┐
  Lockfile/dir ────────▶│  Parsers (per-ecosystem)                    │
                        │  package-lock.json, poetry.lock, go.sum, ... │
                        └──────────────────────┬──────────────────────┘
                                               │ []Dependency
                        ┌──────────────────────▼──────────────────────┐
                        │  Matcher (shared range logic)                │
                        │  ┌──────────────┐    ┌────────────────────┐ │
                        │  │ LocalMatcher │    │ LiveMatcher (API)  │ │
                        │  │ (Postgres)   │    │ fallback           │ │
                        │  └──────┬───────┘    └─────────┬──────────┘ │
                        └─────────┼──────────────────────┼────────────┘
                                  │ []Finding            │
                        ┌─────────▼──────────────────────▼────────────┐
                        │  EPSS enrichment ─▶ Prioritizer ─▶ Remediate│
                        └──────────────────────┬──────────────────────┘
                                               │
                                  ┌────────────┼────────────┐
                                  ▼            ▼            ▼
                            Postgres        Report      (continuity)
                           (persist)     (text/JSON)   re-match loop
```

### Data flow (two modes)

**Flow A — code change (scan):**
```
new/changed lockfile → parse → new snapshot → match → findings → persist/report
```

**Flow B — vuln DB delta (continuity):**
```
OSV sync → ChangedVulnsSince() → re-match existing snapshots → new findings
```
No rescan required — matching is a pure function of `(dependency, DB state)`.

### Package map

| Package | Responsibility |
|---------|----------------|
| `internal/model` | Domain types + version comparators (semver, PEP 440, Go pseudo-versions) |
| `internal/parser` | Lockfile parser registry + filename auto-detection |
| `internal/parser/{npm,pip,go,cargo}` | Per-ecosystem lockfile parsers |
| `internal/osvclient` | OSV.dev API client (live path) + CVSS v3.1 base-score calculator |
| `internal/osvsync` | Local OSV DB sync worker (per-ecosystem `all.zip`, HEAD-first, bulk upsert) |
| `internal/matcher` | Shared range-matching logic (used by both local and live paths) |
| `internal/store` | Postgres persistence (pgx) + embedded migrations + repository layer |
| `internal/epss` | EPSS exploit-probability enrichment (FIRST.org API) |
| `internal/prioritize` | Composite risk scoring with auditable `reasons[]` |
| `internal/remediate` | Fixed-version selection + bump classification |
| `internal/report` | Text + JSON rendering |
| `cmd/amparo` | CLI entry point (`sync`, `scan`, `findings`) |

---

## 🗄️ Data model

Amparo uses Postgres with embedded, versioned migrations (auto-applied on
connect). Core entities:

```
organization 1──* project 1──* source
                   │
                   └──* snapshot 1──* dependency     (immutable resolved graph)

vuln_record (osv_id PK)                          (local vuln DB, synced from OSV)
  └─ affected JSONB, severity_score, epss_*, fixed_versions

finding (project_id, purl, version, vuln_id)     ← dedup key
  └─ status: new → triaged → fixed, first_seen, last_seen
```

**Finding lifecycle:** keyed by `(project, dependency_purl, version, vuln_id)` so
the same issue seen across rescans is **one record** with `first_seen/last_seen`,
not duplicates. Upserting an existing finding bumps `last_seen` rather than
inserting a new row.

Migrations live in [`internal/store/migrations/`](internal/store/migrations) and
are tracked in a `schema_migrations` table.

---

## ⚙️ Configuration

Amparo is configured via environment variables and CLI flags (no config file yet).

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgres://sca:sca@localhost:5432/sca?sslmode=disable` | Postgres connection string |

The default credentials (`sca:sca`) match the `docker-compose.yml` dev setup.
**Override `DATABASE_URL` for any non-dev deployment.**

---

## 🛠️ Development

### Repository layout

```
.
├── cmd/amparo/              # CLI entry point
├── internal/
│   ├── model/               # Domain types + version comparators
│   ├── parser/              # Lockfile parsers (npm, pip, go, cargo)
│   ├── osvclient/           # OSV API client + CVSS calculator (live path)
│   ├── osvsync/             # OSV DB sync worker (local path)
│   ├── matcher/             # Shared range-matching logic
│   ├── store/               # Postgres persistence + migrations
│   ├── epss/                # EPSS enrichment
│   ├── prioritize/          # Composite risk scoring
│   ├── remediate/           # Remediation engine
│   └── report/              # Output rendering
├── docs/                    # Architecture + engineering docs
├── testdata/                # Fixture lockfiles for tests
├── docker-compose.yml       # Dev Postgres
└── go.mod
```

### Build & run

```bash
go build -o bin/amparo ./cmd/amparo
```

### Formatting & linting

```bash
go fmt ./...
go vet ./...
```

### Dependencies

Amparo deliberately keeps a minimal dependency tree:

| Dependency | Purpose |
|-----------|---------|
| [`github.com/jackc/pgx/v5`](https://github.com/jackc/pgx) | Postgres driver + connection pool |
| [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml) | TOML parsing (poetry.lock, Cargo.lock) |

Everything else (HTTP, JSON, zip, flag, testing) is the Go standard library.

---

## 🧪 Testing

```bash
docker compose up -d      # Postgres must be running for integration tests
go test ./...
```

### What's covered

| Area | Test | Type |
|------|------|------|
| Version comparison (semver, PEP 440, Go pseudo) | `TestCompareVersions`, `TestComparePipVersions`, `TestCompareGoVersions` | Unit |
| CVSS v3.1 scoring (verified vs. NVD) | `TestScoreFromVector` | Unit |
| EPSS batch handling (live API) | `TestFetchScores_RealAPI` | Integration (skipped if offline) |
| Postgres migrations + schema | `TestMigrate_AppliesCleanly` | Integration |
| Snapshot/dependency round-trip | `TestProjectSnapshotDependencyRoundTrip` | Integration |
| Finding dedup lifecycle | `TestUpsertFinding_DedupBumpsLastSeen` | Integration |
| **Live vs. local matcher equivalence** | `TestLocalVsLiveCrossCheck` | Integration |
| **Continuity invariant** | `TestContinuity_FlowB` | Integration |
| OSV sync (real Go ecosystem) | `TestSync_RealSmallEcosystem` | Integration (live) |
| Lockfile parsers (Go, Cargo) | `TestParseGoSum`, `TestParseCargoLock` | Unit |

Integration tests auto-skip if Postgres or the network is unavailable.

### Verified facts

- **CVSS calculator matches NVD** — `TestScoreFromVector` uses real CVE vectors
  with authoritative NVD base scores.
- **Live and local matchers produce identical findings** — `TestLocalVsLiveCrossCheck`
  confirms both paths return the same 22 vulnerabilities for `golang.org/x/crypto v0.17.0`.
- **Continuity holds** — `TestContinuity_FlowB` verifies re-matching is
  idempotent and `ChangedVulnsSince` tracks DB updates.

---

## 💡 Design principles

1. **Determinism where it matters.** Version matching, CVSS scoring, and
   remediation are pure functions. Same inputs → same output, always. No LLM, no
   randomness, no flaky heuristics in the core.
2. **Shared matcher logic.** The live API and local DB paths use the same range
   evaluation, so they produce identical findings. Verified by equivalence test.
3. **Ecosystem-aware versioning.** PyPI uses PEP 440; Go uses pseudo-versions.
   Each ecosystem uses the correct comparator — no false results from treating
   everything as semver.
4. **Graceful degradation.** EPSS failure doesn't break a scan (continues without
   the signal). An empty local DB falls back to the live API automatically. The
   tool never hard-fails when a non-critical dependency is unavailable.
5. **Continuity by design.** Matching is a pure function of `(dependency, DB
   state)`, so a DB update can surface new findings on old snapshots without
   rescanning. This is the product's headline differentiator.
6. **AI enhances, never replaces.** The planned AI layer (§8.5 of the design
   doc) sits *beside* the deterministic engine, reads its signals, and produces
   narrative/patch output — always grounded, always self-hostable. It never
   decides correctness.

---

## ⚠️ Project status & known limitations

Amparo is **alpha** software. The engine is correct and validated, but it is
**not yet a complete product**. The honest gaps (full detail in
[`docs/engineering-status.md`](docs/engineering-status.md)):

### High impact

- **No transitive resolution for pip/Maven.** Lockfile-only scanning means
  `requirements.txt` without a lockfile misses the transitive closure — where
  most real Python vulnerabilities live. Maven is not yet implemented.
- **No intake mechanism.** Every scan is "point CLI at a directory." There's no
  GitHub App, CI integration, or scheduled re-scan — so this is a local dev
  tool, not yet a team product.
- **Continuity is designed but not wired.** The re-match *capability* exists and
  is tested, but there's no background process that runs it automatically. A
  human must trigger re-matching today.
- **Local matcher will scale-cliff.** `FindVulnsByPackage` uses JSONB containment
  scans — fine in dev, but a real org (1000 deps × 50 projects) would need a
  normalized index to perform.

### Medium impact

- **AI layer unbuilt.** The §8.5 design (grounded explanations, team worklists,
  self-host model) is detailed in the design doc but not implemented. The
  `reasons[]` audit trail that would feed it exists.
- **No auth / multi-tenancy.** The schema has orgs/projects but no
  authentication, authorization, or tenant isolation. Fine locally; a
  procurement blocker for hosted use.
- **Thin test coverage on prioritization/remediation.** The composite scoring
  and bump-classification logic — the value-add — lack dedicated unit tests.
- **npm sync is heavy.** ~220k records / ~200MB per full sync; no alias
  deduplication or withdrawn-record pruning yet.

**Bottom line:** a strong, correct engine that needs intake, transitive
resolution, and a running continuity loop to become a product.

---

## 🗺️ Roadmap

Informed by the known limitations above (priority order):

1. **Intake** — GitHub App, CI runner, scheduled scans *(unblocks team use)*
2. **Transitive resolution** — pip `uv` resolve, Maven effective-POM *(correctness)*
3. **Real continuity loop** — background re-match worker *(headline feature)*
4. **Query performance** — normalized `vuln_package` index *(scale)*
5. **AI layer** — grounded risk explanations, team worklists *(differentiator)*
6. **Auth & multi-tenancy** — OIDC + org-scoped RBAC *(hosted readiness)*
7. **Maven** — effective-POM resolver, BOM/dependencyManagement *(ecosystem)*
8. **Reachability** — per-language call-graph analysis *(prioritization depth)*

See [`docs/technical-design.md`](docs/technical-design.md) §14 for the full
phased roadmap.

---

## 📁 Documentation

| Doc | Contents |
|-----|----------|
| [`docs/technical-design.md`](docs/technical-design.md) | Full architecture: components, data model, ecosystem design, vuln pipeline, prioritization model, AI layer (§8.5), tech-stack rationale, roadmap |
| [`docs/engineering-status.md`](docs/engineering-status.md) | Honest retrospective: what's built, what works, the 8 known flaws (with impact + fix directions), bugs caught during the build, recommended priorities |

---

## 📄 License

License TBD. Currently all rights reserved pending a decision on open-core vs.
proprietary. See [Roadmap](#-roadmap) and the design doc for the business-model
discussion.

---

<div align="center">

**Amparo** — *protection for your software supply chain.*

Built with care for correctness. Still early. Feedback welcome.

</div>
