# Technical Design Document — Continuous SCA Platform

**Codename:** (TBD)
**Status:** Draft v0.1 — blueprint
**Author:** Engineering
**Last updated:** 2026-07-02

> Continuous Software Composition Analysis across **npm, pip, Maven, Go, Cargo** —
> monitor dependencies against OSV + CVE/NVD, prioritize by real risk, and give a
> clear remediation path.

---

## 1. Executive summary

We are building a **continuous** software composition analysis (SCA) product. The
differentiator is not "scan a manifest and list CVEs" (commoditized — Dependabot,
Trivy, Grype, Snyk all do this). The differentiator is three things:

1. **Prioritization that kills noise.** CVSS alone is useless. We combine
   **CVSS + EPSS + CISA KEV + reachability + fix-availability + direct/transitive +
   runtime/build context** into one actionable signal.
2. **True continuity.** Deps rarely change; *vulnerabilities do*. We store the
   resolved dependency graph once and **re-match it against an evolving vuln DB**,
   so a CVE that drops today alerts on code you committed months ago — without a
   rescan.
3. **A remediation path, not an alert.** Minimal bump that satisfies manifest
   constraints, breaking-change detection, and an auto-generated PR.
4. **Focus, not noise — with an AI layer that earns trust.** Every team is drowning
   in SCA alerts. We use an LLM to turn correct-but-noisy data into *what actually
   matters to this team right now* — grounded explanations, ranked worklists, and
   real patches. The LLM never decides correctness; it sits beside the engine,
   always grounded in deterministic signals, always available self-hosted.

This doc is the blueprint: architecture, data model, the hard correctness problems
(version matching, Maven resolution, reachability), the vuln-intelligence pipeline,
the **AI layer** (how we use an LLM to genuinely enhance — not replace — the
deterministic engine), tech stack with rationale, and a phased roadmap.

---

## 2. Goals & non-goals

### Goals
- Ingest manifests + lockfiles for npm, pip, Maven, Go, Cargo.
- Resolve the full dependency graph (incl. transitive) per ecosystem.
- Match every dependency against OSV (which aggregates CVE/NVD, GHSA, PyPA,
  RustSec, Go vuln DB) and enrich with EPSS + KEV.
- Produce a prioritized, de-duplicated finding list with a concrete remediation.
- Support **two event flows**: code-change scans *and* vuln-DB-delta re-matches.
- First-class API, dashboard, and CI/GitHub integration.

### Non-goals (for now)
- License compliance analysis (v2).
- Malware/heuristic package scoring like Socket (v2 — different problem class).
- Container/OS-package scanning (e.g., debian/apk) — ecosystem-only for v1.
- Static analysis (SAST) of first-party code.

---

## 3. The hard problems (read these first)

These four are where SCA projects silently lose correctness. Each gets a section:

| # | Problem | Why it's hard | Where it bites |
|---|---------|---------------|----------------|
| 1 | **Version-range matching** | Every ecosystem has its own version scheme & range syntax | False negatives/positives in findings |
| 2 | **Transitive resolution** | Lockfiles solve most; **Maven** has none and needs effective-POM | Missing/invisible deps |
| 3 | **Advisory de-duplication** | One CVE → NVD + GHSA + ecosystem record, all cross-referenced | Duplicate noise |
| 4 | **Reachability** | Needs per-language call-graph analysis | Prioritization quality |

OSV.dev is the keystone: it already aggregates all the ecosystem feeds, gives
every record stable IDs, and uses a normalized `affected.range` model. **We treat
OSV as the source of truth for "what's vulnerable" and add EPSS/KEV on top.**

---

## 4. High-level architecture

```
                 ┌──────────────────────────────────────────────────────────────┐
   Code change   │  INGESTION                                                   │
   ─────────────▶│  GitHub App │ CI runner │ CLI │ manifest upload              │
                 │     │                                                         │
                 │     ▼                                                         │
                 │  Parsers (per-ecosystem) ──▶ Snapshot (resolved dep graph)    │
                 └───────────────────────────────┬──────────────────────────────┘
                                                 │ store (immutable)
                 ┌───────────────────────────────▼──────────────────────────────┐
                 │  CORE (deterministic)                                        │
                 │  ┌──────────────┐   ┌────────────────┐   ┌────────────────┐  │
                 │  │ Matcher      │◀──│ Vuln DB (local)│   │ Prioritizer    │  │
                 │  │ (purl×ver    │   │ OSV+EPSS+KEV   │──▶│ (risk scoring) │  │
                 │  │  vs ranges)  │   └───────▲────────┘   └───────┬────────┘  │
                 │  └──────┬───────┘           │                    │           │
                 │         │ findings          │                    ▼           │
                 │         ▼                   │            ┌────────────────┐  │
                 │  ┌──────────────┐           │            │ Findings store │  │
                 │  │ Remediation  │◀──────────────────────│ (Postgres)     │  │
                 │  │ (min bump)   │                        └────────────────┘  │
                 │  └──────┬───────┘                                                │
                 │         │ deterministic signals                                    │
                 │         ▼                                                          │
                 │  ┌───────────────────────────────────────────┐                  │
                 │  │ AI LAYER (grounded · opt-in · self-host)  │                  │
                 │  │  • Why-it-matters explanation             │                  │
                 │  │  • Team worklist / "what matters now"     │                  │
                 │  │  • Remediation patch (when no clean bump) │                  │
                 │  │  • NL → structured query                  │                  │
                 │  │  reads deterministic signals only ────────▶ NO decisions     │
                 │  └───────────────────────┬───────────────────┘                  │
                 └───────────────────────────┼──────────────────────────────────────┘
                                                 │
                 ┌───────────────────────────────▼──────────────────────────────┐
                 │  SERVING                                                     │
                 │  REST API │ Dashboard (Next.js) │ Webhooks │ GitHub PRs      │
                 └──────────────────────────────────────────────────────────────┘

  Vuln-DB-delta flow (continuity): OSV/EPSS/KEV update ──▶ re-match existing
  snapshots ──▶ emit new/closed findings ──▶ notify. No rescan required.
```

Two event flows, one matcher:
- **Flow A (code change):** new/updated manifest → ingest → new snapshot → match → findings.
- **Flow B (vuln delta):** vuln DB updated → re-match *existing* snapshots → delta findings → notify.

Because a snapshot is immutable and matching is a pure function of `(snapshot, vulnDB-state)`,
Flow B is cheap: no parsing, no registry calls — just re-run the matcher.

---

## 5. Component breakdown

### 5.1 Ingestion service
- Accepts a source: GitHub App webhook, CI job artifact, CLI push, or file upload.
- Fetches relevant manifest + lockfile(s).
- Hands off to the **parser registry** (per ecosystem).

### 5.2 Parser registry (ecosystem abstraction)
Each ecosystem plugs in via a common interface:

```
interface EcosystemParser {
  ecosystem: "npm" | "pypi" | "maven" | "golang" | "cargo"
  manifests: string[]            // e.g. ["package.json"]
  lockfiles: string[]            // e.g. ["package-lock.json", "yarn.lock"]
  parseLockfile(bytes): ResolvedDependency[]
  resolveTransitive(manifest): ResolvedDependency[]   // when no lockfile
  toPurl(name, version): Purl
  parseVersion(v): Version       // ecosystem-specific
  satisfiesRange(v, range): bool
}
```

### 5.3 Matcher
Pure function: `(ResolvedDependency, [VulnRecord]) -> [Finding]`.
For each dep, find OSV records whose `affected[].package.ecosystem` matches and
whose `affected[].ranges[]` include the dep's version.

### 5.4 Vuln-DB sync worker
Pulls OSV (GCS bucket / API), EPSS (CSV, daily), KEV (CSV, as published),
optionally GHSA direct. Stores normalized records. Emits a "DB delta" event on update.

### 5.5 Prioritizer
Takes raw matches → attaches enrichment (EPSS %, KEV flag, fix availability,
direct/transitive, reachability) → outputs a composite `priority` + `actionability`.

### 5.6 Remediation engine
Given a finding, computes the **minimal satisfying version** that (a) is outside the
vuln range and (b) respects the manifest's existing version constraints. Detects
major-version bumps (potential breaking changes). Produces a PR-ready diff.
When no clean bump exists, it hands off to the AI layer (§8.5.2 #3) for patch drafting.

### 5.7 AI service (grounded, opt-in, self-hostable — see §8.5)
A standalone service bracketed by validators: reads **only** deterministic signals
from the findings store + advisory text, produces explanations / worklists /
patches / NL-query results, validates output against the source data, and stores
results linked to `finding_id`. Never participates in matching or scoring. Runs
against either a self-hosted local model (default for code/manifest context) or an
opt-in cloud model for non-sensitive work.

### 5.8 API + dashboard + integrations
REST API, Next.js dashboard, webhook emitter, GitHub App for PR creation.

---

## 6. Ecosystem design details (correctness lives here)

| Ecosystem | Manifest | Lockfile(s) | Version scheme | purl type | Registry API | Transitive via |
|-----------|----------|-------------|----------------|-----------|--------------|----------------|
| **npm** | `package.json` | `package-lock.json` (v2/v3), `yarn.lock`, `pnpm-lock.yaml` | semver | `pkg:npm` | registry.npmjs.org | lockfile |
| **pip** | `requirements.txt`, `pyproject.toml`, `Pipfile`, `setup.py` | `poetry.lock`, `Pipfile.lock`, `uv.lock` | **PEP 440** (not semver!) | `pkg:pypi` | pypi.org/pypi/*/json | lockfile (if present) |
| **Maven** | `pom.xml` | *(none standard)* | loose / "soft 0" (1.0 = 1.0.0) | `pkg:maven` | search.maven.org, repo1.maven.org | **effective-POM resolution** |
| **Go** | `go.mod` | `go.sum` | semver + pseudo-versions | `pkg:golang` | proxy.golang.org | lockfile |
| **Cargo** | `Cargo.toml` | `Cargo.lock` | semver | `pkg:cargo` | crates.io/api/v1/crates/* | lockfile |

### 6.1 Version matching rules
- **npm/Cargo/Go:** use strict semver comparison. Go pseudo-versions (`v0.0.0-20240102120000-abcdef1234ab`) need a dedicated comparator that orders by the embedded timestamp/commit.
- **pip:** MUST use a PEP 440 implementation (e.g., reuse `packaging.version` logic). Treating pip versions as semver is a classic source of false results.
- **Maven:** Maven versions have "soft zeroes" — `1`, `1.0`, `1.0.0` are equal; also handles qualifiers (`1.0-alpha1 < 1.0-beta < 1.0`). Use a Maven-aware comparator (`maven-artifact` logic).
- **Range evaluation:** OSV records use `range` strings in the native ecosystem syntax (e.g., npm `>=1.0.0 <2.0.0`, Maven `[1.0,2.0)`). Each parser's `satisfiesRange` must handle its native syntax.

### 6.2 Transitive resolution strategy
- **Lockfile present (npm/pip-with-lock/Cargo/Go):** parse it — it already lists every transitive dep at a pinned version. This is authoritative and cheap. **Prefer this path.**
- **No lockfile (common for pip `requirements.txt`, Maven):** resolve transitively:
  - pip: invoke `pip`/`uv` resolve or query the registry DAG.
  - Maven: compute the **effective POM** — apply `dependencyManagement` / BOMs, resolve `properties`, apply mediation rules (nearest-wins, scope, optional). This is genuinely hard; budget for it.
- **Recommendation:** push users toward lockfiles; treat lockfile-less resolution as a degraded-but-supported path.

### 6.3 Build vs. the parser on existing tooling
Strongly consider **reusing battle-tested parsers** rather than hand-rolling:
- Google's **osv-scanner** (Go) ships a `lockfile` parse package supporting all five ecosystems — Apache-2.0.
- **packageurl-go** for purl handling.
- govulncheck patterns for Go reachability.

> **Decision point (open):** build the scanner core in Go to reuse osv-scanner's parsers, or re-implement in our backend language for full control? See §11.

---

## 7. Vulnerability intelligence pipeline

### 7.1 Sources
| Source | What it gives | Freshness | License |
|--------|---------------|-----------|---------|
| **OSV.dev** | Authoritative aggregate: CVE/NVD, GHSA, PyPA, RustSec, Go vuln DB, etc. | Continuous | Apache-2.0 / CC0-ish |
| **NVD** | CVSS vector/score (authoritative), CPE | ~daily | public |
| **First.org EPSS** | Exploit probability + percentile | daily CSV | free |
| **CISA KEV** | Known-Exploited-Vulnerabilities catalog | as published | public |
| **GHSA** | Advisory text, CWE, patched releases | continuous | CC-BY-4.0 |

OSV already aliases records across these (e.g., `CVE-2024-XXXX` ↔ `GHSA-…`). **De-duplication is therefore mostly handled by OSV aliases**; we group on the OSV record id and surface aliases as one finding.

### 7.2 Local sync vs. live query
- **MVP:** call the **OSV.dev batch query API** live (`POST /v1/querybatch`). No DB-sync infra. Fast to build, but adds a runtime dependency and rate limits.
- **v1:** **sync OSV locally** (data is published as a downloadable set; or stream the API). Matcher runs against the local copy. This is what enables true continuity (Flow B) and offline/self-host.
- EPSS and KEV are small CSVs — always sync locally.

### 7.3 Normalized vuln record
```
VulnRecord {
  id            // OSV id (primary key), e.g. "GHSA-..." or "CVE-..."
  aliases       // ["CVE-2024-1234"]
  summary, details
  severity      // CVSS vector + score (max across provided)
  affected[]    // { ecosystem, package, ranges[], fixed_versions[] }
  epss          { probability, percentile }
  in_kev        // bool
  published, modified
}
```

---

## 8. Prioritization model

Raw CVSS is why devs ignore SCA tools. We compute a composite `priority`.

### 8.1 Signals
| Signal | Source | Effect |
|--------|--------|--------|
| CVSS score | NVD/OSV | Base 0–10 |
| EPSS percentile | First.org | Boost if high (>0.9 → exploit likely) |
| CISA KEV membership | KEV | **Forces top tier** — known exploited in the wild |
| Reachability | call-graph (per-lang, v1+) | Boost if reachable; dampen if dead code |
| Fix available | OSV `fixed_versions` | "Actionable now" vs "no fix yet" |
| Direct vs transitive | snapshot | Direct = higher exposure |
| Runtime vs build/test dep | manifest scope | Runtime = higher |

### 8.2 Composite buckets
```
CRITICAL  ← KEV present, OR (CVSS≥9 AND EPSS percentile≥0.95)
HIGH      ← CVSS≥7 AND (reachable OR direct OR runtime)
MEDIUM    ← CVSS≥4
LOW       ← else

ACTIONABLE_NOW  ← fix available within manifest constraints
MONITOR         ← no fix / breaking bump required
```
Output each finding as `{ priority, actionable, risk_score, reasons[] }` so the UI can *explain* the score (devs trust what they can audit). **The `reasons[]` array is also the grounded input the AI layer consumes — see §8.5.**

---

## 8.5 AI layer — focus, not noise (and never the engine)

Supply-chain volume is the real enemy: a single repo can surface hundreds of
"matches," most irrelevant. The deterministic engine (§7–§8) is the source of
truth for *what is vulnerable*. The AI layer's entire job is to turn that correct
but noisy data into **focus** so a team acts on what matters — nothing more.

### 8.5.1 The inviolable rule
> **The LLM never decides correctness.** It does not decide whether a version is
> in a vuln range, generate scores, or invent advisories. It **reads deterministic
> signals and produces narrative/structured/enhancement output.** Every AI output
> is grounded in and traceable to non-AI data. If a finding is wrong, it's a bug
> we fix in code, not a model artifact.

This is the line that separates a *trustworthy* product from "slap-an-LLM."
Security buyers reject the latter on sight; they buy the former.

### 8.5.2 What the AI layer does (by value)

| # | Capability | Grounded in | Why it matters |
|---|------------|-------------|----------------|
| 1 | **"Why this matters, here, now"** explanation per finding | `reasons[]`, EPSS, KEV, reachability hit, usage site (e.g. `auth.ts:42`), advisory text | Devs ignore generic "Critical CVE" alerts. One honest, *specific* sentence gets action and builds trust. |
| 2 | **Team worklist / "what to fix first this week"** | full finding set + policy + team ownership + fix-availability | The single most valuable artifact: a short, ranked, *explainable* worklist instead of a 500-row table. |
| 3 | **Remediation patch when no clean bump exists** | vulnerable code pattern + usage + advisory + (no patched release OR breaking major) | When a fix isn't a version bump, the deterministic engine can't help. The LLM drafts an actual patch (pin range, swap deprecated API, backport). |
| 4 | **Advisory triage at intake** | raw GHSA/CVE prose | Normalizes messy ecosystem prose into structured fields (vuln function, precondition, safe versions) — grounded in the OSV record, never invented. Speeds #1 and #3. |
| 5 | **Natural-language query layer** | our own structured API | "Show me critical runtime vulns in prod with no fix, grouped by team" → structured query. Pure UX, low risk. |
| 6 | **Reachability reasoning (hybrid, later)** | static call-graph (source of truth) + LLM refinement | "Does this reachable path actually exercise the vulnerable branch?" Refinement signal only; static analysis stays authoritative. |

### 8.5.3 What the AI layer never does
- Decide version-in-range or any matching/score.
- Author advisory/CVE data of record.
- Replace the matcher, resolver, or prioritizer.
- Operate without deterministic grounding (no free-form "analyze my code" without
  structured evidence attached).

### 8.5.4 The constraint that defines the architecture — self-hostable & private
Our buyers are supply-chain-paranoid. **Sending their manifests, usage sites, or
code context to an external LLM API is a dealbreaker** for the exact audience we
target. Therefore:

- **Every AI capability has a self-hosted / local-model path.** The deterministic
  product works fully offline; the AI layer is a *progressive enhancement*.
- **Two model tiers, capability-mapped:**
  - *Local/self-hosted model* (small open model the customer runs) — mandatory for
    anything touching code/manifest/usage context (#3, #6, parts of #1/#4).
  - *Cloud model, opt-in only* — for lightweight, non-sensitive work (#5 query
    layer, advisory summaries of public data) with explicit data-handling guarantees.
- **No exfiltration by default.** Code/manifest context never leaves the tenant
  boundary unless the customer explicitly enables a cloud path. This is a
  procurement gate, not a preference.

### 8.5.5 Grounding & anti-hallucination contract
Every AI output carries its evidence so it's auditable — the mirror image of
§8's "devs trust what they can audit":

```
AIExplanation {
  finding_id           // links back to the deterministic finding
  summary              // the "why it matters" sentence
  evidence[]           // [{ signal: "KEV", value: true, source: "CISA 2026-06-30" }, ...]
  model_id             // which model produced this (for audit + reproducibility)
  generated_at
  confidence           // derived from how much of summary is backed by evidence
  flags                // ["ungrounded_claim"] — surfaced to UI if the model went off-script
}
```

Grounding rules, enforced in code (not prompt-hoped):
1. Every claim in `summary` must map to a `reasons[]` entry; claims with no
   matching signal are dropped or flagged `ungrounded_claim`.
2. Version numbers, CVE IDs, and file paths in output are **validated against the
   finding record** — if the model emits a CVE id that isn't in `aliases`, it's
   stripped. (Models hallucinate these reliably; we catch it deterministically.)
3. Output is **regenerated on finding change** and **versioned by vuln-DB state**,
  so explanations stay consistent with the deterministic truth (same reproducibility
  principle as §13).

### 8.5.6 Data flow (where the LLM sits)
```
Findings store (deterministic) ──┐
                                 ├──▶ Grounding validator ──▶ LLM ──▶ Post-validator
Advisory text (OSV record) ──────┘            (assembles        (strips/flags
                                              grounded prompt)   ungrounded claims)
                                                                       │
                                                                       ▼
                                                            AI explanation store
                                                            (linked to finding_id)
```
The LLM is bracketed by validators on both sides: input is assembled *from*
deterministic data, output is checked *against* deterministic data. The model is
sandwiched in a correctness sandwich.

### 8.5.7 Phasing (mapped to §14)
- **MVP (Phase 0):** *No LLM.* Earn trust with correct matching + prioritization +
  deterministic remediation first. (Adds cost/latency/privacy surface for zero
  value until the core is right.)
- **v0.5:** **Grounded risk explanation (#1)** + **advisory triage (#4)** — highest
  value-per-effort, opt-in, works on advisory text + our own signals, no code
  exfiltration.
- **v1 product:** **Team worklist (#2)** + **NL query (#5)** + **self-host model
  option** wired in.
- **v1+:** **Remediation patch generation (#3)** (needs usage context → local model
  required) and **reachability reasoning (#6)** once static analysis exists.

---

## 9. Remediation engine

Given finding `(dep, vuln, currentVersion, manifestConstraint)`:
1. From OSV `fixed_versions` pick the **lowest** fixed version.
2. Check it satisfies the manifest's declared range; if not, find the nearest version that both (a) is fixed and (b) is allowed, or report a **constraint conflict**.
3. Classify the bump: patch / minor (safe) vs major (potentially breaking) using semver delta where applicable.
4. Emit remediation:
   ```
   { target_version, change_type: "patch"|"minor"|"major"|"none",
     within_constraints: bool, breaking_risk: low|med|high,
     changelog_url, pr_diff }
   ```
5. (v1) Open a PR via the GitHub App with the lockfile/manifest updated.

---

## 10. Data model (Postgres — core entities)

```
organization  (id, name, plan)
project       (id, org_id, name, default_branch)
source        (id, project_id, type, config)          // github|ci|upload
snapshot      (id, project_id, source_id, created_at, sha, manifest_hash)
              // immutable resolved dep set
dependency    (id, snapshot_id, purl, name, version, ecosystem,
               scope, is_direct, parent_dependency_id)  // the graph edges
vuln_record   (id, osv_id, severity_score, epss_p, in_kev, fixed_versions_jsonb,
               affected_jsonb, modified_at)
finding       (id, snapshot_id, dependency_id, vuln_id, priority, actionable,
               status: new|triaged|fixed|suppressed, first_seen, last_seen)
remediation   (finding_id, target_version, change_type, breaking_risk, pr_url)
policy        (org_id, rules_jsonb)                    // suppressions, thresholds
ai_explanation (finding_id, kind, summary, evidence_jsonb,
               model_id, vuln_db_version, confidence, flags_jsonb, generated_at)
              // kind: "why_it_matters"|"worklist_entry"|"patch"|"advisory_triage"
              // always linked to a finding; vuln_db_version ties it to deterministic
              // truth so it can be invalidated/regenerated on vuln-DB change.
```
- **Finding lifecycle:** keyed by `(dependency_purl+version, vuln_id)` so the same issue across scans is one record with `first_seen/last_seen`, not duplicates. Status moves `new → triaged → fixed` automatically when a snapshot no longer contains the vulnerable version.
- **Graph storage:** parent edges on `dependency` suffice for most reachability workloads; if call-graph reachability needs deep traversal, materialize an adjacency table or use a graph layer later.

---

## 11. Tech stack (recommendation + rationale)

| Layer | Choice | Why |
|-------|--------|-----|
| **Scanner + matcher core** | **Go** | Reuse **osv-scanner** parsers (all 5 ecosystems), **packageurl-go**, govulncheck patterns. Concurrency + perf for matching 10k+ deps. Reference impls are Go. |
| **API + services** | **Go** (single backend lang) *or* **Node/TS** | Go everywhere = simplest ops, share code with scanner. TS = faster product-layer iteration. **Recommendation: Go monolith backend** to share the matching core directly. |
| **Dashboard** | **Next.js (React/TS) + Tailwind** | Industry standard, great DX, SSR, fast. |
| **Database** | **PostgreSQL** | Relational core (orgs/projects/findings), JSONB for vuln `affected` payloads, strong indexing. |
| **Cache / queue** | **Redis** (+ a durable job runner) | Vuln-sync jobs, re-match fan-out, rate limiting. |
| **Object storage** | **S3-compatible** | Raw manifests/lockfiles, generated SBOMs, PR diffs. |
| **Vuln DB sync** | Scheduled workers pulling OSV (bulk) + EPSS/KEV CSVs | §7. |
| **AI service** | Go micro-service + pluggable model backend (local open model **or** opt-in cloud API); validator-bracketed | §8.5. Local-default keeps code/manifest context in-tenant; cloud is opt-in for non-sensitive work. |
| **Auth / multi-tenancy** | OIDC (GitHub OAuth) + org-scoped RBAC | SaaS + self-host. |
| **Deployment** | Docker images; self-host (single binary + Postgres) and managed SaaS | Supply-chain buyers demand self-host option. |

> **Key call:** a **Go backend + Next.js frontend** lets us directly embed osv-scanner's parsers instead of re-implementing them — saving months of correctness work and de-risking §3 problems #1 and #2. This is the single most leveraged decision in the doc.

---

## 12. API surface (v1 sketch)

```
POST   /v1/scans                 // start scan (source id or upload)
GET    /v1/scans/:id             // status + summary
GET    /v1/projects/:id/findings // filter/sort: priority, ecosystem, actionable
GET    /v1/findings/:id          // detail incl. remediation
POST   /v1/findings/:id/suppress // policy-based suppress
POST   /v1/hooks                 // register webhook
GET    /v1/projects/:id/sbom     // export CycloneDX/SPDX
GET    /v1/findings/:id/explain  // grounded AI "why it matters" (§8.5 #1)
GET    /v1/projects/:id/worklist // AI-ranked team worklist (§8.5 #2)
POST   /v1/query                 // NL → structured findings query (§8.5 #5)
GET    /healthz  /metrics
```
Plus GitHub App endpoints (webhook receiver, PR callbacks).

---

## 13. Non-functional requirements

- **Freshness SLA:** OSV re-matched within *X* minutes of a new advisory (target: <30 min). EPSS/KEV refreshed daily.
- **Performance:** matching a 10k-dep snapshot in seconds; incremental matching on vuln deltas.
- **Privacy:** manifests are often proprietary. SaaS path must not exfiltrate package lists; document a **self-host / on-prem** path from day one. Treat uploaded manifests as tenant-scoped, encrypted-at-rest, retained per policy.
- **Reliability:** external registry/OSV-API failures must degrade gracefully (cached vuln DB, queued retries).
- **Auditability:** every prioritization decision must be reproducible (snapshot id + vuln DB version).
- **AI privacy (hard gate):** code, manifest, and usage-site context never leaves the tenant boundary unless the customer explicitly enables a cloud-model path. Self-host/local-model is the default for sensitive context; the deterministic product is fully functional with the AI layer disabled.
- **AI grounding:** every AI output is linked to a finding and carries `evidence[]`; claims not backed by deterministic signals are dropped or flagged `ungrounded_claim`. CVE IDs / versions / paths in AI output are validated against the finding record.

---

## 14. Phased roadmap

### Phase 0 — MVP (weeks)
- Ecosystems: **npm + pip**.
- Lockfile ingestion only.
- **Live OSV.dev batch query** (no local sync).
- Prioritization: **CVSS + EPSS + fix-availability**.
- Output: CLI + JSON/text report + remediation suggestion (target version).
- *Goal: prove matching correctness end-to-end, demo-able.*

### Phase 1 — v0.5
- **Local OSV sync** + EPSS/KEV (enables Flow B continuity).
- Postgres persistence, finding lifecycle, dedup.
- Next.js dashboard.
- GitHub App: source from repo, PR-based remediation.
- Add **Go + Cargo**.
- **AI layer begins (opt-in):** grounded "why it matters" explanation (§8.5 #1) + advisory triage (#4). Self-host/local-model first.

### Phase 2 — v1 (the real product)
- **Maven** (effective-POM resolver).
- **Reachability** (per-language, start with one: JS or Go).
- KEV enforcement, policies/suppressions, multi-tenant auth.
- SBOM export (CycloneDX/SPDX) for compliance.
- **AI:** team worklist ranking (#2) + NL query layer (#5); self-host model option fully wired.

### Phase 3 — v2
- Reachability expansion across languages.
- CI gating / break-glass policies.
- IDE plugin, compliance reporting (EU CRA, US EO 14028).
- License analysis, malware heuristics (separate pipeline).
- **AI:** remediation patch generation when no clean bump exists (§8.5 #3, needs usage context → local model) + reachability reasoning refinement (#6).

---

## 15. Risks & open questions

| Risk / question | Mitigation / next step |
|-----------------|------------------------|
| Maven transitive resolution correctness & cost | Timebox a spike on effective-POM; consider reusing a Maven resolver lib; push lockfile adoption. |
| Reachability cost per language | Treat as v1+; pick one language first; make it optional/opt-in. |
| Reuse osv-scanner vs reimplement | **Spike:** embed its Go parsers; confirm licensing (Apache-2.0) and coverage of lockfile-less cases. |
| OSV freshness vs. local-sync latency | Decide sync cadence + live-query fallback. |
| Advisory quality / false positives | Surface EPSS + reachability prominently; let users suppress with audit trail. |
| Differentiation vs Snyk/Socket/Dependabot | Win on **prioritization clarity + true continuity + remediation + grounded AI focus**; open-core self-host as a wedge into enterprises. |
| Business model (open-core? SaaS?) | Decide before v1: open-core scanner + paid SaaS dashboard is the common pattern. |
| **AI hallucination undermining trust** | Hard grounding contract (§8.5.5): validator brackets the model, CVE IDs/versions/paths validated against the finding record, ungrounded claims dropped/flagged. |
| **AI privacy blocking procurement** | Self-host/local-model default; cloud opt-in only; deterministic core works with AI disabled (§8.5.4). |
| **AI cost/latency at scale** | Generate explanations async + cache by `finding_id × vuln_db_version`; only regen on change. |
| Naming, licensing of the product itself | TBD. |

---

## 16. Next decisions to make (before coding)

1. **Backend language:** Go (reuse osv-scanner) vs TS (product speed)? *Recommend Go.*
2. **MVP scope:** confirm npm + pip, lockfile-only, live OSV. *(This doc's Phase 0.)*
3. **Deployment model first:** self-host single-binary vs SaaS-first? Affects auth/multitenancy now.
4. **Repository parser strategy:** embed osv-scanner parsers (spike to validate) — yes/no?
5. **AI model strategy:** which local/self-host model (e.g., a small open model via Ollama/vLLM) for sensitive context, and which cloud model (if any) for opt-in non-sensitive work? Decide before Phase 1 so the service interface is model-agnostic from day one.

---

*Appendices (to write): A) OSV record schema reference, B) purl spec, C) EPSS/KEV field maps, D) per-ecosystem lockfile parser compatibility matrix.*
