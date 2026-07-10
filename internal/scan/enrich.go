// Package scan — shared post-match enrichment.
//
// This file contains the enrichment pipeline that runs AFTER matching produces
// raw findings, transforming them into the final, prioritized, remediated form.
// It is called by BOTH the normal scan path (scan.Run) AND the continuity
// re-match path (continuity.runForVulns), so a finding discovered by either
// route receives identical treatment: dedup → EPSS → prioritize → remediate.
//
// This fixes the continuity-parity bug: previously, continuity-discovered
// findings got a CVSS-only priority with no EPSS, no composite scoring, and no
// remediation — so the SAME advisory could show different risk data depending
// on how it was discovered. Now both paths are identical.
package scan

import (
	"context"
	"fmt"
	"io"

	"github.com/sabeel111/Amparo/internal/matcher"
	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/prioritize"
	"github.com/sabeel111/Amparo/internal/remediate"
)

// EnrichFindings runs the full post-match enrichment pipeline on raw findings:
//
//	dedup → EPSS → prioritize → remediate
//
// This is the single shared path used by both scan.Run and continuity. EPSS
// failure is non-fatal (findings are still prioritized at the CVSS floor) —
// matching Codex's hardening principle that EPSS unavailability must degrade
// gracefully, not silently look like zero risk.
//
// log receives progress/warning lines (stderr for CLI, log.Writer for webhooks).
func EnrichFindings(ctx context.Context, log io.Writer, findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return findings
	}

	// 1. Dedup cross-source advisory duplicates.
	if before := len(findings); before > 0 {
		findings = matcher.DedupeFindings(findings)
		if d := before - len(findings); d > 0 {
			fmt.Fprintf(log, "amparo: deduplicated %d cross-source finding(s)\n", d)
		}
	}

	// 2. EPSS enrichment (non-fatal on failure).
	enrichEPSS(ctx, log, findings)

	// 3. Prioritize (composite risk: CVSS + EPSS + fix-availability + direct/transitive).
	findings = prioritize.Enrich(findings)

	// 4. Remediate (lowest fixed version + bump classification).
	for i := range findings {
		findings[i].Remediation = remediate.For(findings[i])
	}

	return findings
}
