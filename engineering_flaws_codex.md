# Engineering flaws and core-hardening handoff

**Purpose:** Give a follow-on engineering agent a grounded, prioritized backlog
for hardening Amparo, the supply-chain vulnerability tracker. This document
distinguishes completed reliability work from remaining flaws. Do not assume
that a documented capability is production-ready without checking its tests and
the current implementation.

**Status date:** 2026-07-10

## Completed in the current hardening pass

### 1. Local OSV sync could silently return partial data — mitigated

**Previous flaw:** `internal/osvsync` ignored batch-persistence and package-index
errors. A malformed advisory entry was also skipped. The CLI could therefore
say a sync succeeded even though the local advisory database was incomplete.

**Current mitigation:**

- OSV archives are saved to a temporary file rather than loaded fully in RAM.
- Failed advisory decoding, bulk upsert, indexing, and sync-metadata writes now
  fail the ecosystem sync.
- Sync stats now expose `complete`, `skipped`, or `failed`.
- The CLI skips continuity if any requested ecosystem sync fails.
- Offline regression tests cover failed bulk persistence, failed indexing, and
  malformed archive JSON.

**Remaining:** The feed is still a full ecosystem archive after any upstream
change. Add delta ingestion and uncompressed-entry limits later.

### 2. Timestamp-based continuity could miss newly imported advisories — mitigated

**Previous flaw:** Continuity queried `vuln_record.modified > cutoff`. That is
the upstream OSV modification time, not the time Amparo imported the record.
A historical advisory first imported today could be missed entirely.

**Current mitigation:**

- `BulkUpsertVulns` returns only advisory IDs inserted or materially changed.
- `amparo sync` passes those exact IDs to `continuity.RunForVulns`.
- A database regression test proves that an advisory with a 30-day-old upstream
  timestamp still creates a finding when newly imported.

**Remaining:** The standalone `amparo continuity --since` command is still a
timestamp-based maintenance path. It is acceptable for manual use, but sync
must continue to use the exact-ID path.

### 3. Partial scans could look complete — mitigated

**Previous flaw:** A scan logged parsing errors but continued. If at least one
file parsed, a report could look clean despite missing a supported lockfile.

**Current mitigation:**

- Reports now include scan coverage: discovered, parsed, failed, complete, and
  warnings.
- Text output visibly labels incomplete coverage.
- `amparo scan --strict` stops before vulnerability matching if any supported
  discovered lockfile cannot be read or parsed.

**Remaining:** Make strict mode the default for CI/webhook scans after users
have migrated their repositories and automation.

## Remaining flaws, ordered by core risk

## P0 — Version comparison can produce false positives or false negatives

**Where:** `internal/model/version.go`, `internal/model/goversion.go`, and
`internal/parser/pip/pep440.go`.

**Why it matters:** Vulnerability matching is a version-boundary decision. If
`installed < fixed` or `introduced <= installed` is evaluated incorrectly, the
tracker can incorrectly claim a dependency is safe or vulnerable.

**Current issue:**

- The generic comparator is explicitly pragmatic, not full SemVer or Maven.
- Build metadata and complex prerelease ordering are not fully SemVer-correct.
- Go pseudo-version handling does not cover all canonical pseudo-version forms.
- The PEP 440 implementation is intentionally partial and has limited test
  coverage for epochs, local versions, dev/post releases, and compound cases.

**Mitigation plan:**

1. Define a comparator contract per supported ecosystem; do not use one generic
   comparator where semantics differ.
2. Adopt a maintained Go SemVer/Go-module implementation where possible, or
   validate a local implementation against the ecosystem's official corpus.
3. Expand PEP 440 tests using packaging's reference cases and real OSV ranges.
4. Add table-driven boundary tests for every comparator: introduced, fixed,
   last_affected, prerelease, build metadata, pseudo-version, epoch, post, and
   dev release.
5. Add a cross-check corpus: dependency + OSV range + expected result, executed
   by both live and local matchers.

**Acceptance criteria:** Every supported ecosystem has authoritative edge-case
tests, and live/local matcher results remain equal for the same corpus.

## P0 — Continuity does not run the full risk-enrichment pipeline

**Where:** `internal/continuity/continuity.go`.

**Why it matters:** A finding discovered by a normal scan receives EPSS,
priority reasons, remediation, and actionable classification. A continuity
finding currently persists a CVSS-derived priority without EPSS enrichment or
the full prioritizer. The same advisory can therefore have different risk data
depending on how it was discovered.

**Mitigation plan:** Extract a shared post-match enrichment function used by
both `scan.Run` and continuity:

```text
match -> dedupe -> EPSS -> prioritize -> remediate -> persist
```

Batch EPSS requests across continuity candidates, then persist all enriched
fields. Decide and document failure behavior: EPSS failure may degrade the
result, but must set an explicit "EPSS unavailable" state rather than silently
looking like zero risk.

**Acceptance criteria:** A normal scan and exact-ID continuity produce the same
priority, actionable state, remediation, and EPSS data for the same dependency
and advisory.

## P0 — The HTTP service is unsafe outside localhost

**Where:** `internal/server/server.go`, `internal/server/github.go`.

**Why it matters:** The API is unauthenticated, CORS permits every origin, and
PATCH endpoints can alter finding status. GitHub webhook signature verification
is deliberately bypassed when the secret is absent. This is acceptable only for
local development.

**Mitigation plan:**

1. Add an explicit environment mode. Refuse a non-loopback bind without auth,
   allowed origins, and a webhook secret.
2. Authenticate users or service identities; add organization-scoped RBAC.
3. Scope every project and finding query by the authenticated organization.
4. Restrict CORS to configured origins; do not use `*` with a deployed UI.
5. Add request-size limits, structured security logs, and webhook replay/id
   handling.
6. Use a GitHub App installation token rather than embedding a broad PAT in a
   clone URL.

**Acceptance criteria:** An unauthenticated external request cannot read or
change findings, and startup fails safely when production prerequisites are
missing.

## P1 — OSV synchronization remains operationally expensive

**Where:** `internal/osvsync/sync.go`.

**Current state:** Archive RAM usage and silent errors were fixed, but npm and
other ecosystems still require a full archive download when `Last-Modified`
changes. The archive is then fully reprocessed.

**Mitigation plan:** Investigate OSV's per-file/delta metadata. Persist
per-record source version or last-modified metadata, fetch only changed records,
and retain exact changed-ID handoff. Add per-entry uncompressed-size and total
extraction limits to protect against malicious or corrupted archives.

**Acceptance criteria:** A small upstream delta does not require processing the
entire npm corpus, and sync metrics expose bytes downloaded, records processed,
records changed, and duration.

## P1 — Parser support and documentation overstate coverage

**Where:** `internal/parser`, `README.md`.

**Current issue:** The parser registry supports `package-lock.json`, Pipfile,
Poetry, requirements, Go files, and Cargo lockfiles. It does not currently
parse Yarn or pnpm lockfiles even though historical documentation has suggested
broader npm lockfile support. `go.mod`-only scanning is best-effort and Maven is
not implemented.

**Mitigation plan:** Make the supported-file list in documentation match the
registry exactly. Either add parsers plus fixtures/tests for Yarn/pnpm/Maven, or
explicitly reject those files with a clear coverage warning.

## P1 — Python resolution is approximate, not a reproducible lock resolver

**Where:** `internal/resolver/pip.go`.

**Why it matters:** For unpinned requirements, the resolver selects current
registry releases and approximates PEP 440 constraints. It skips extras and
does not fully evaluate environment markers. The result can differ from what a
real target environment installs.

**Mitigation plan:** Prefer lockfiles. For requirements-based scans, either use
a resolver faithful to pip's target platform/environment semantics or label the
dependency graph as resolved approximation. Include Python version, platform,
and extras in the resolver contract.

## P1 — Webhook reliability and repository intake need hardening

**Where:** `internal/server/github.go`.

**Current issue:** Scans run in an in-process goroutine with no durable queue,
retry policy, idempotency key, concurrency control, or status tracking. Malformed
payload fields such as too-short SHAs can cause slicing panics. Pull-request
privacy handling is also not based on an explicit `private` field.

**Mitigation plan:** Validate payload schema and SHA length before use. Persist
webhook deliveries and scan jobs, use a bounded worker queue, dedupe by
repository/commit/event, record status, and retry transient clone/network
failures. Move to a GitHub App for credentials and installation isolation.

## P1 — Finding lifecycle lacks audit data

**Where:** `internal/server/server.go`, `internal/store/store.go`, dashboard
components.

**Current issue:** The API accepts a triage/suppression reason but does not
persist it. There is no actor or timestamped status-history record.

**Mitigation plan:** Add a `finding_event` or status-history table with finding
ID, previous/new status, reason, actor, source, and timestamp. Require a reason
for suppression in deployed modes. Return that history through the API.

## P2 — API behavior and query efficiency need cleanup

**Where:** `internal/server/server.go`, `internal/store/store.go`.

**Issues:**

- GET project-by-name currently uses `EnsureProject`, so a read of an unknown
  project creates database rows.
- GET finding-by-ID first finds the project and then loads up to 1,000 project
  findings to locate one row; this is inefficient and can miss results beyond
  that limit.
- The dashboard's cross-project findings page is a project list, not a true
  global findings query.

**Mitigation plan:** Add read-only `ProjectByName` and `FindingByIDDetailed`
store methods and a paginated global-findings endpoint. Ensure GET endpoints do
not mutate state.

## P2 — Test and delivery discipline need improvement

**Current issue:** Some high-value logic has little or no unit coverage:
prioritization buckets, remediation bump classification, full comparator edge
cases, report coverage, and webhook behavior. Several tests hit live external
services, which makes `go test ./...` slow and environment-dependent. The web
lint currently reports a React effect rule violation.

**Mitigation plan:**

- Mark live tests as integration tests and skip them under `-short`; make unit
  tests deterministic and offline.
- Add table-driven tests for priority, remediation, range matching, and report
  coverage metadata.
- Add CI stages: format, unit tests, DB integration tests, frontend lint,
  frontend build, and optional live smoke tests.
- Fix the existing frontend lint issue in
  `web/src/app/projects/[name]/page.tsx` before treating frontend CI as green.

## Recommended next-agent order

1. Make continuity use the full enrichment/prioritization/remediation pipeline.
2. Harden version comparison and add authoritative boundary corpora.
3. Add production-service safety checks, authentication, and tenant scoping.
4. Stabilize webhook/job processing and finding audit history.
5. Improve delta OSV sync and operational metrics.
6. Close parser/documentation coverage gaps.

## Non-negotiable regression gates

- Preserve the exact-ID sync-to-continuity handoff; do not revert to a timestamp
  cutoff for normal syncs.
- Preserve explicit failed sync status; never ignore persistence or index errors.
- Preserve scan coverage metadata and `--strict` behavior.
- Keep `go test ./...` compiling; separate live integration tests from fast,
  deterministic unit tests rather than weakening existing correctness checks.
