# Codex changes

This document records implementation changes made to strengthen Amparo's
trustworthiness. Entries state what changed, how it was verified, and what is
still intentionally out of scope.

## 2026-07-10 — Reliable local OSV archive ingestion

### Goal

Establish the first trustworthiness guarantee: an ecosystem sync must never be
reported as complete after a failed advisory decode, vulnerability upsert, or
package-index update.

### Changes made

- Reworked `internal/osvsync` archive handling to download OSV ZIP files to a
  temporary file before opening them. ZIP requires random access, but retaining
  the complete archive in memory was unnecessary and risky for the npm feed.
- Added a 1 GiB compressed-archive safety limit and temporary-file cleanup.
- Added explicit per-ecosystem sync statuses: `complete`, `skipped`, and
  `failed`.
- Made advisory archive processing fail on malformed JSON, archive-entry read
  failures, vulnerability bulk-upsert failures, and `vuln_package` reindexing
  failures. Previously those paths could be ignored while the command returned
  a misleading success result.
- Made failure to record sync metadata fail the ecosystem result as well, so a
  successful status always represents a fully recorded operation.
- Prevented the CLI from running continuity after any requested ecosystem sync
  fails. This favors delayed freshness over re-matching against a known
  incomplete local database.
- Added offline regression tests for failed bulk persistence, failed indexing,
  and malformed OSV advisory JSON.
- Added the public trustworthiness guarantees to `README.md`.

### Verification

- `go test ./internal/osvsync -run '^TestStoreArchive' -count=1` (passes)
- `go test ./... -run '^$'` compile-only check (passes)

The repository's unfiltered test suite includes live OSV integration tests.
The full `go test ./...` run exceeded the local 60-second command limit while
those network-backed tests were running; this is an existing test-runtime
constraint, not a failure from the new offline regression tests.

### Remaining work

- The sync still uses a whole-ecosystem archive when OSV reports a change;
  delta-feed ingestion is a later performance improvement.

## 2026-07-10 — Exact changed-advisory continuity handoff

### Goal

Ensure continuity does not miss advisories that are newly imported into the
local cache but have an old OSV `modified` timestamp.

### Changes made

- Changed `BulkUpsertVulns` to return the exact OSV IDs inserted or materially
  changed. Unchanged records no longer update `synced_at` or trigger work.
- Added a material-change comparison across advisory data used by matching and
  prioritization, including ranges, fixed versions, withdrawal state, and
  upstream modification timestamp.
- Propagated those IDs through `osvsync.SyncResult`.
- Added `continuity.RunForVulns`, which re-matches only the exact IDs supplied
  by sync. The standalone `continuity --since` command still supports the
  timestamp-based maintenance path.
- Updated `amparo sync` to use the exact-ID handoff automatically.
- Added a regression test proving that a newly imported advisory with an old
  upstream timestamp still creates a finding for an existing snapshot.

### Verification

- `go test ./internal/osvsync -run '^TestStoreArchive' -count=1`
- `go test ./internal/continuity -run '^TestContinuity_SurfacesNewFindingWithoutRescan' -count=1`
- `go test ./... -run '^$'`

## 2026-07-10 — Scan coverage disclosure and strict mode

### Goal

Prevent a partially parsed repository from being presented as a clean or
complete security result.

### Changes made

- Added scan coverage to text and JSON reports: discovered, parsed, failed,
  complete, and warning details.
- A non-strict scan continues after an individual supported lockfile failure,
  but the report now visibly says `INCOMPLETE` and names the failures.
- Added `amparo scan --strict`, which stops before vulnerability matching if
  any supported discovered lockfile cannot be read or parsed. This is suitable
  for CI and automation.
- Added an offline regression test for an invalid `package-lock.json` in strict
  mode.

### Verification

- `go test ./internal/scan -run '^TestRun_StrictFailsWhenSupportedLockfileCannotParse$' -count=1`
- `go test ./... -run '^$'`

## Handoff status

Feature work was intentionally stopped after the three reliability guarantees
above were implemented. The next recommended core-hardening work is version
comparison correctness, identical prioritization for continuity findings, and
production API security. See `engineering_flaws_codex.md` for the prioritized
engineering backlog and detailed mitigation guidance.
