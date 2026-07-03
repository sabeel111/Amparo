// Package report renders findings as human-readable text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
)

// Report is the full output of a scan.
type Report struct {
	Summary  Summary         `json:"summary"`
	Findings []model.Finding `json:"findings"`
}

// Summary aggregates finding counts by priority.
type Summary struct {
	Total        int `json:"total"`
	Critical     int `json:"critical"`
	High         int `json:"high"`
	Medium       int `json:"medium"`
	Low          int `json:"low"`
	Actionable   int `json:"actionable"`
	NoFix        int `json:"no_fix"`
	Direct       int `json:"direct"`
	Transitive   int `json:"transitive"`
	Dependencies int `json:"dependencies"`
}

// Build computes the summary from findings.
func Build(findings []model.Finding, depCount int) Report {
	var s Summary
	s.Dependencies = depCount
	s.Total = len(findings)
	for _, f := range findings {
		switch f.Priority {
		case model.SeverityCritical:
			s.Critical++
		case model.SeverityHigh:
			s.High++
		case model.SeverityMedium:
			s.Medium++
		case model.SeverityLow:
			s.Low++
		}
		if f.Actionable == model.ActionableNow {
			s.Actionable++
		} else {
			s.NoFix++
		}
		if f.Dependency.IsDirect {
			s.Direct++
		} else {
			s.Transitive++
		}
	}
	// Sort findings by priority for stable output.
	sort.SliceStable(findings, func(i, j int) bool {
		return rankP(findings[i].Priority) > rankP(findings[j].Priority)
	})
	return Report{Summary: s, Findings: findings}
}

func rankP(s model.Severity) int {
	switch s {
	case model.SeverityCritical:
		return 4
	case model.SeverityHigh:
		return 3
	case model.SeverityMedium:
		return 2
	case model.SeverityLow:
		return 1
	}
	return 0
}

// WriteJSON writes the report as pretty-printed JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes a human-readable report with a summary header and a table of
// findings grouped by priority.
func WriteText(w io.Writer, r Report) error {
	s := r.Summary
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  SCA Scan Results\n")
	fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 50))
	fmt.Fprintf(w, "  Dependencies scanned : %d\n", s.Dependencies)
	fmt.Fprintf(w, "  Vulnerable findings  : %d", s.Total)
	if s.Total > 0 {
		fmt.Fprintf(w, "  (")
		parts := []string{}
		if s.Critical > 0 {
			parts = append(parts, fmt.Sprintf("%d critical", s.Critical))
		}
		if s.High > 0 {
			parts = append(parts, fmt.Sprintf("%d high", s.High))
		}
		if s.Medium > 0 {
			parts = append(parts, fmt.Sprintf("%d medium", s.Medium))
		}
		if s.Low > 0 {
			parts = append(parts, fmt.Sprintf("%d low", s.Low))
		}
		fmt.Fprintf(w, "%s", strings.Join(parts, ", "))
		fmt.Fprintf(w, ")")
	}
	fmt.Fprintf(w, "\n")
	fmt.Fprintf(w, "  Actionable now        : %d   (no fix / monitor: %d)\n", s.Actionable, s.NoFix)
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("─", 50))

	if len(r.Findings) == 0 {
		fmt.Fprintf(w, "  No vulnerabilities found. ✅\n\n")
		return nil
	}

	currentBand := ""
	for _, f := range r.Findings {
		band := labelFor(f.Priority)
		if band != currentBand {
			currentBand = band
			fmt.Fprintf(w, "\n  ┌─ %s ───────────────────────────────────────\n", strings.ToUpper(band))
		}
		writeFindingText(w, f)
	}
	fmt.Fprintf(w, "\n")
	return nil
}

func writeFindingText(w io.Writer, f model.Finding) {
	d := f.Dependency
	fmt.Fprintf(w, "  │ %s %s@%s\n", severityIcon(f.Priority), d.Name, d.Version)
	fmt.Fprintf(w, "  │   %s  %s\n", f.VulnID, firstNonEmpty(f.Summary, "(no summary)"))
	if len(f.Aliases) > 0 {
		fmt.Fprintf(w, "  │   aliases: %s\n", strings.Join(f.Aliases, ", "))
	}
	fmt.Fprintf(w, "  │   CVSS %.1f · EPSS %s · %s\n", f.CVSS, epssLabel(f), directLabel(d.IsDirect))
	if f.Remediation != nil {
		fmt.Fprintf(w, "  │   fix: %s\n", remediationLabel(f.Remediation))
	}
	if len(f.Reasons) > 0 {
		fmt.Fprintf(w, "  │   why: %s\n", strings.Join(f.Reasons, "; "))
	}
	fmt.Fprintf(w, "  │\n")
}

func severityIcon(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "🔴"
	case model.SeverityHigh:
		return "🟠"
	case model.SeverityMedium:
		return "🟡"
	case model.SeverityLow:
		return "🔵"
	}
	return "⚪"
}

func labelFor(s model.Severity) string {
	switch s {
	case model.SeverityCritical:
		return "critical"
	case model.SeverityHigh:
		return "high"
	case model.SeverityMedium:
		return "medium"
	case model.SeverityLow:
		return "low"
	}
	return "none"
}

func epssLabel(f model.Finding) string {
	if f.EPSSPercentile <= 0 {
		return "unknown"
	}
	return fmt.Sprintf("%.1f%%ile", f.EPSSPercentile*100)
}

func directLabel(isDirect bool) string {
	if isDirect {
		return "direct dep"
	}
	return "transitive"
}

func remediationLabel(r *model.Remediation) string {
	if r == nil {
		return "n/a"
	}
	switch r.ChangeType {
	case model.ChangeNoFix:
		return "no fixed version yet — monitor"
	case model.ChangeNone:
		return r.Note
	case model.ChangeMajor:
		return fmt.Sprintf("upgrade to %s  ⚠ major bump (potentially breaking)", r.TargetVersion)
	case model.ChangeMinor:
		return fmt.Sprintf("upgrade to %s  (minor bump)", r.TargetVersion)
	case model.ChangePatch:
		return fmt.Sprintf("upgrade to %s  (patch bump)", r.TargetVersion)
	case model.ChangeUnknown:
		return fmt.Sprintf("upgrade to %s  (version change)", r.TargetVersion)
	}
	return r.Note
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
