# Engineering Status & Honest Retrospective

**Purpose:** Internal engineering documentation. A faithful record of what we've
built, what works, what doesn't, and where the real gaps are. Not a sales doc —
this is for us to make grounded decisions about what to build next.

**Last updated:** 2026-07-03
**Current state:** Phase 1 complete. Core engine functional, validated against
real OSV data. Not yet a product.

---

## 1. The product vision

Continuous software composition analysis (SCA) across **npm, pip, Maven, Go,
Cargo**. Monitor dependencies against OSV + CVE databases, prioritize by real
risk (not just CVSS), and give a clear remediation path.

We identified three differentiators in a crowded market (Snyk, Dependabot,
Socket, Trivy, Grype, osv-scanner, Dependency-Track):

1. **Prioritization that kills noise** — CVSS alone is useless; layer EPSS, KEV,
   reachability, fix-availability into one auditable signal.
2. **True continuity** — deps rarely change but vulnerabilities do; re-match
   stored dependency graphs against an evolving vuln DB, no rescan required.
3. **A remediation path, not an alert** — minimal bump within constraints,
   breaking-change detection, (future) auto-PR.

A fourth, added later: an **AI layer** that turns correct-but-noisy data into
*focus* (grounded explanations, team worklists, patches) — never replacing the
deterministic engine, always self-hostable.

Full architecture: [`docs/technical-design.md`](technical-design.md).

---

## 2. What we've built (phase by phase)

### Phase 0 — MVP (COMPLETE)

**Goal:** prove matching correctness end-to-end with real OSV data.
**Scope:** npm + pip, live OSV API, CLI only.

| Component | Status | Notes |
|-----------|--------|-------|
| Parsers (package-lock.json, Pipfile.lock, poetry.lock, requirements.txt) | ✅ | npm v1/v2/v3; pip incl. PEP 440 versions |
| OSV.dev live client (batch query + detail fetch) | ✅ | Bounded concurrency, chunked batches |
| CVSS v3.1 base-score calculator | ✅ | Hand-written from FIRST.org spec; verified against NVD |
| EPSS enrichment (FIRST.org API) | ✅ | CVE-only filtering + URL byte-length chunking |
| Prioritization (CVSS + EPSS + fix-availability) | ✅ | Composite buckets, `reasons[]` audit trail |
| Remediation engine | ✅ | Lowest fixed version + bump classification |
| Text + JSON reports | ✅ | Grouped by priority, severity icons |

### Phase 1 — Core engine (COMPLETE)

**Goal:** local vuln DB, persistence, Go + Cargo ecosystems, continuity foundation.
**Scope:** Postgres, local OSV sync, matcher refactor, 4 ecosystems.

| Component | Status | Notes |
|-----------|--------|-------|
| Postgres persistence (`internal/store`) | ✅ | Versioned embedded migrations, full schema, finding-lifecycle dedup |
| Bulk upsert (COPY + temp table) | ✅ | 9x faster than per-record |
| OSV local sync worker (`internal/osvsync`) | ✅ | Per-ecosystem `all.zip`, HEAD-first change detection |
| Matcher refactor (`internal/matcher`) | ✅ | Shared range logic; live + local produce identical findings |
| Go parser (go.sum / go.mod) | ✅ | Pseudo-version comparator |
| Cargo parser (Cargo.lock) | ✅ | Root crate skipped |
| CLI: `sync`, `--match`, `--persist`, `findings` | ✅ | Auto-fallback to live if DB empty |

### Explicitly deferred

- Next.js dashboard, GitHub App / auto-PR, AI layer, Maven, reachability, auth/RBAC.

---

## 3. Current architecture (as built)

```
Lockfile → Parser (per-ecosystem) → []Dependency
   → Matcher (local DB OR live OSV API, shared range logic) → []Finding
   → EPSS enrichment (CVE-keyed, degrades gracefully)
   → Prioritizer (composite risk)
   → Remediation engine (lowest fixed version + bump type)
   → [optional] Persist to Postgres (snapshot + deduped findings)
   → Report (text | JSON)
```

### Package map

| Package | Responsibility | Phase |
|---------|----------------|-------|
| `internal/model` | Domain types + version comparators (semver, PEP 440, Go pseudo) | 0+1 |
| `internal/parser` | Parser registry + auto-detection | 0 |
| `internal/parser/{npm,pip}` | npm + pip lockfile parsers | 0 |
| `internal/parser/{go,cargo}` | Go + Cargo lockfile parsers | 1 |
| `internal/osvclient` | OSV.dev API client (live) + CVSS v3.1 calculator | 0 |
| `internal/osvsync` | Local OSV DB sync (all.zip, HEAD-first, bulk upsert) | 1 |
| `internal/matcher` | Shared range-matching (LocalMatcher) | 1 |
| `internal/store` | Postgres (pgx) + migrations + repository | 1 |
| `internal/epss` | EPSS enrichment | 0 |
| `internal/prioritize` | Composite risk scoring | 0 |
| `internal/remediate` | Fixed-version selection + bump classification | 0 |
| `internal/report` | Text + JSON rendering | 0 |
| `cmd/sca` | CLI (sync / scan / findings) | 0+1 |

### Data model (Postgres)

```
organization 1—* project 1—* source
project 1—* snapshot 1—* dependency          (immutable resolved dep graph)
vuln_record (osv_id PK, synced from OSV)     (the local vuln DB)
finding (project, snapshot, purl, version, vuln_id, status, first/last_seen)
                                                  ↑ dedup key
```

### Verified facts

- CVSS calculator matches NVD authoritative scores (test: `TestScoreFromVector`).
- Live and local matchers return identical findings for the same input
  (test: `TestLocalVsLiveCrossCheck` — 22/22 vulns for golang.org/x/crypto).
- Continuity invariant: re-matching is idempotent; `ChangedVulnsSince` tracks
  DB updates (test: `TestContinuity_FlowB`).
- Finding dedup works across rescans (test: `TestUpsertFinding_DedupBumpsLastSeen`).
- OSV sync: Go = 8,041 records in ~5s; npm = 221,844 records in ~15min.

---

## 4. Honest flaws & gaps (read this before building on top)

This is the important section. The engine is correct, but "correct engine" ≠
"practical product." These are ordered by practical impact.

### FLAW 1 — No transitive resolution for ecosystems that need it [HIGH] — ✅ FIXED (pip)

We **only read lockfiles**. This is fine for npm and Cargo (lockfiles list the
full transitive tree) but was **dangerously incomplete** for:

- **pip with `requirements.txt`** — ✅ FIXED. `internal/resolver` now queries the
  pypi.org JSON API to walk `requires_dist` via BFS, building the full transitive
  closure. Picks the highest version satisfying the declared range (PEP 440),
  skips pre-releases by default, skips optional (extra) deps. The pip parser now
  captures version ranges instead of silently dropping them. Verified: 2 direct
  deps → 9 transitive resolved → 16 findings including transitives urllib3 + idna.
- **Maven** — ❌ still not implemented; effective-POM/BOM resolution is the hardest
  ecosystem (Phase 2).
- **Go** — `go.sum` gives the full closure (works correctly); `go.mod`-only is
  still best-effort (no MVS), but rare in practice since go.sum is standard.

**Remaining:** Maven transitive resolution.
preferred path. See design doc §6.2.

### FLAW 2 — Local matcher will scale-cliff at real volume [HIGH]

`FindVulnsByPackage` does `affected @> '[{"package":{"name":"X"}}]'::jsonb` — a
JSONB containment scan, effectively full-table per package lookup. Works in dev
(221k npm records), but a real org (1000 deps × 50 projects, re-matched on every
vuln-DB delta) would melt Postgres.

**Impact:** "Continuity" becomes "the DB is slow" at any real scale — killing the
headline differentiator.

**Fix direction:** normalized `vuln_package(ecosystem, name, vuln_id)` join table
built at sync time; index-backed lookups instead of JSONB containment.

### FLAW 3 — Continuity is designed but not wired [HIGH]

We built the ingredients (`ChangedVulnsSince`, re-match capability, idempotency
test) but there's **no background process** that runs it. Continuity only works
if a human re-runs `sca scan`. The pitch ("CVE drops today → alerted without
rescan") doesn't happen automatically.

**Impact:** We have a demo of the mechanism, not the feature. The #1 product
promise is unfulfilled at runtime.

**Fix direction:** a scheduler/worker that, after each `sca sync`, takes the
changed vuln IDs, finds affected stored snapshots, re-matches, and emits new
findings + notifications.

### FLAW 4 — No real intake mechanism [HIGH]

Every scan is "point CLI at a directory." There's no GitHub App webhook, no CI
integration, no scheduled re-scan, no UI upload. So this is a **local dev tool**,
not a team product.

**Impact:** Team budgets are where the money is, and we can't serve teams yet.
This is the #1 reason it's not sellable.

**Fix direction:** GitHub App (scan on PR/merge), CI runner, scheduled jobs.

### FLAW 5 — npm sync is heavy and we store too much [MEDIUM]

- 15+ min and 200MB per npm sync (HEAD-detection helps, but a real change = full
  re-download). Too slow for a <30min freshness SLA if blocking.
- We store all records including withdrawn/duplicates; cross-ecosystem aliases
  (one CVE as GHSA + CVE + PYSEC) aren't deduplicated. Storage balloons and
  queries slow.

**Impact:** Operational cost and query degradation over time.

**Fix direction:** delta sync (per-file LastModified enumeration); alias
deduplication at ingest; prune or filter `withdrawn_at` records from matching.

### FLAW 6 — The AI layer is a doc section, not a feature [MEDIUM]

§8.5 of the design doc is detailed (grounded explanations, self-host model,
anti-hallucination contract). The `reasons[]` array that would feed it exists
(good foresight). But **none of the AI is built**. The "focus, not noise" promise
— arguably our sharpest differentiator — is entirely unbuilt.

**Impact:** Today a user gets the same text output as Phase 0. The differentiator
is invisible.

**Fix direction:** Phase 2 — start with grounded risk explanation (§8.5.2 #1),
highest value-per-effort.

### FLAW 7 — No auth, no multi-tenancy, no isolation [MEDIUM]

Schema has `organization`/`project`, but no authentication, authorization, or
tenant isolation in queries. One DB, one `default` org, everything visible to
everyone. Fine locally; instant procurement rejection for SaaS.

**Impact:** Blocks any hosted/team deployment.

**Fix direction:** OIDC (GitHub OAuth) + org-scoped RBAC; query-level tenant
filtering.

### FLAW 8 — Test coverage is thin on the highest-risk logic [MEDIUM]

The cross-check and store tests are good, but:

- **No tests for the prioritization scoring itself** — the composite bucketing
  (our value-add) is untested.
- **No tests for remediation bump-classification edge cases** — major-version
  detection across ecosystems.
- **No regression test for the EPSS URL-length fix** — the bug could return.

**Impact:** The thing we *sell* (better prioritization) has the least coverage.
Regressions would ship silently.

**Fix direction:** table-driven tests for `prioritize.compute` and
`remediate.classifyBump`; an EPSS large-batch regression test.

---

## 5. Bugs we caught during the build (and lessons)

These are worth remembering — each was a real correctness issue a test surfaced.

| Bug | How caught | Lesson |
|-----|-----------|--------|
| CVSS "expected" test values wrong | Test failed; verified against NVD API | The calculator was right; my assumptions were wrong. Trust authoritative sources. |
| EPSS returned empty on large scans | Manual testing showed 0 coverage | Silent failures (empty API response) are as bad as errors. Filter + chunk. |
| Live matcher missed all Go vulns | `TestLocalVsLiveCrossCheck` failed (22 vs 0) | Two code paths doing "the same thing" will diverge. Share logic; test equivalence. |
| Bulk upsert inserted 0 records | Integration test showed 0 records after sync | `LIKE table INCLUDING DEFAULTS` isn't portable. Be explicit with DDL. |
| Duplicate org/project rows | `findings` command returned 0 despite 93 rows in DB | Missing unique constraint breaks `ON CONFLICT` silently. Test the round-trip, not just the insert. |

---

## 6. What's genuinely strong (don't lose this)

- **The deterministic core** — matching, CVSS, version comparison, finding
  lifecycle. The hard parts are done right and provably so.
- **Shared matcher logic** — live and local paths produce identical findings.
- **The continuity design** — matching as a pure function of (dependency, DB
  state) is sound; it just needs to be wired into a running process.
- **Graceful degradation** — EPSS failure, empty local DB: both degrade cleanly
  rather than breaking.
- **Ecosystem-aware versioning** — PEP 440 for pip, pseudo-versions for Go. No
  false results from treating everything as semver.

---

## 7. Recommended next priorities

Ordered by impact, informed by the flaws above:

1. **Intake** (GitHub App / CI) — without this, not usable by a team [FLAW 4]
2. **Transitive resolution** (pip/Maven) — without this, answers are dangerously
   incomplete [FLAW 1]
3. **Real continuity** (wire the background re-match) — our headline feature
   doesn't run [FLAW 3]
4. **Query performance** (normalized index) — or it dies at scale [FLAW 2]
5. **AI layer** — our sharpest differentiator, unbuilt [FLAW 6]
6. **Auth/RBAC** — blocks any hosted deployment [FLAW 7]
7. **Test coverage on prioritization/remediation** — protect what we sell [FLAW 8]

---

## 8. How to reproduce the current state

```bash
docker compose up -d                              # Postgres on :5432
go build -o bin/sca ./cmd/sca
./bin/sca sync --ecosystems Go                    # ~5s, 8k records
./bin/sca scan --persist --project demo ./testdata/npm
./bin/sca findings demo
go test ./...                                     # all green (DB must be up)
```

**Dependencies:** Go 1.22+, Docker (Postgres 16), internet (OSV/EPSS APIs).
