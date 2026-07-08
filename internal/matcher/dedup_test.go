package matcher

import (
	"testing"

	"github.com/sabeel111/Amparo/internal/model"
)

// TestDedupeFindings_CollapsesSharedCVE reproduces the real-world bug from
// scanning geo-news-mobile: uuid@7.0.3 surfaced two findings — GHSA-w5hq (real)
// and GHSA-qmq6 (labeled "Duplicate Advisory"), both aliasing CVE-2026-41907.
// They should collapse into one finding, keeping the non-duplicate.
func TestDedupeFindings_CollapsesSharedCVE(t *testing.T) {
	dep := model.Dependency{Name: "uuid", Version: "7.0.3", Ecosystem: model.EcosystemNPM}
	findings := []model.Finding{
		{
			Dependency: dep, VulnID: "GHSA-w5hq-g745-h8pq",
			Aliases: []string{"CVE-2026-41907"}, Summary: "uuid: Missing buffer bounds check",
			Severity: model.SeverityHigh, CVSS: 7.5, FixedVersions: []string{"11.1.1"},
		},
		{
			Dependency: dep, VulnID: "GHSA-qmq6-f8pr-cx5x",
			Aliases: []string{"CVE-2026-41907"}, Summary: "Duplicate Advisory: uuid: Missing buffer bounds check",
			Severity: model.SeverityLow, CVSS: 3.2, FixedVersions: []string{"14.0.0"},
		},
	}

	out := DedupeFindings(findings)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped finding, got %d: %+v", len(out), out)
	}
	// Should keep the higher-severity, non-duplicate one.
	if out[0].VulnID != "GHSA-w5hq-g745-h8pq" {
		t.Errorf("kept wrong representative: %s (want GHSA-w5hq-g745-h8pq)", out[0].VulnID)
	}
	// Merged aliases + fixed versions from both.
	if len(out[0].FixedVersions) != 2 {
		t.Errorf("expected 2 merged fixed versions, got %d: %v", len(out[0].FixedVersions), out[0].FixedVersions)
	}
}

// TestDedupeFindings_KeepsDistinctVulns confirms that two findings for the same
// package+version but DIFFERENT CVEs are NOT collapsed.
func TestDedupeFindings_KeepsDistinctVulns(t *testing.T) {
	dep := model.Dependency{Name: "ws", Version: "7.5.10", Ecosystem: model.EcosystemNPM}
	findings := []model.Finding{
		{Dependency: dep, VulnID: "GHSA-96hv", Aliases: []string{"CVE-2026-48779"}, Severity: model.SeverityHigh},
		{Dependency: dep, VulnID: "GHSA-58qx", Aliases: []string{"CVE-2026-45736"}, Severity: model.SeverityMedium},
	}
	out := DedupeFindings(findings)
	if len(out) != 2 {
		t.Errorf("expected 2 distinct findings (different CVEs), got %d", len(out))
	}
}

// TestDedupeFindings_DupAdvisoryWithoutAliases reproduces the harder real-world
// case: the OSV "Duplicate Advisory" record carries NO aliases linking it to the
// primary (a known OSV data quirk). The only signal is the "Duplicate Advisory:"
// summary prefix + matching text. Dedup must still collapse them.
func TestDedupeFindings_DupAdvisoryWithoutAliases(t *testing.T) {
	dep := model.Dependency{Name: "uuid", Version: "7.0.3", Ecosystem: model.EcosystemNPM}
	primary := "uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided"
	findings := []model.Finding{
		{Dependency: dep, VulnID: "GHSA-w5hq-g745-h8pq", Aliases: []string{"CVE-2026-41907"},
			Summary: primary, Severity: model.SeverityHigh, CVSS: 7.5},
		{Dependency: dep, VulnID: "GHSA-qmq6-f8pr-cx5x", Aliases: nil, // no aliases!
			Summary: "Duplicate Advisory: " + primary, Severity: model.SeverityLow, CVSS: 3.2},
	}
	out := DedupeFindings(findings)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped finding (summary match), got %d: %+v", len(out), out)
	}
	if out[0].VulnID != "GHSA-w5hq-g745-h8pq" {
		t.Errorf("kept the duplicate instead of the primary: %s", out[0].VulnID)
	}
}

// TestDedupeFindings_DifferentVersionsNotCollapsed ensures dedup respects the
// version dimension — ws@7.5.10 and ws@8.19.0 are separate even if same vuln.
func TestDedupeFindings_DifferentVersionsNotCollapsed(t *testing.T) {
	findings := []model.Finding{
		{Dependency: model.Dependency{Name: "ws", Version: "7.5.10", Ecosystem: model.EcosystemNPM},
			VulnID: "GHSA-96hv", Aliases: []string{"CVE-2026-48779"}, Severity: model.SeverityHigh},
		{Dependency: model.Dependency{Name: "ws", Version: "8.19.0", Ecosystem: model.EcosystemNPM},
			VulnID: "GHSA-96hv", Aliases: []string{"CVE-2026-48779"}, Severity: model.SeverityHigh},
	}
	out := DedupeFindings(findings)
	if len(out) != 2 {
		t.Errorf("expected 2 findings (different versions), got %d", len(out))
	}
}
