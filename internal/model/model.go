// Package model defines the core domain types shared across the SCA engine.
//
// The data flow is: Parser -> []Dependency -> OSV matcher -> []Finding ->
// Prioritizer -> Remediation -> Report. These types are the contracts between
// those stages and are intentionally ecosystem-agnostic.
package model

// Ecosystem is the package ecosystem a dependency belongs to.
// Values mirror the OSV / package-url ecosystem identifiers so they can be
// used directly in OSV queries without translation.
type Ecosystem string

const (
	EcosystemNPM   Ecosystem = "npm"
	EcosystemPyPI  Ecosystem = "PyPI"
	EcosystemMaven Ecosystem = "Maven"
	EcosystemGo    Ecosystem = "Go"
	EcosystemCargo Ecosystem = "cargo"
)

// Dependency is a resolved package at a concrete version.
// A Dependency is always pinned (no ranges) — transitive resolution, if any,
// happens in the parser before this type is produced.
type Dependency struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Ecosystem Ecosystem `json:"ecosystem"`

	// IsDirect is true for top-level dependencies declared in the manifest;
	// false for transitive dependencies resolved from a lockfile.
	IsDirect bool `json:"is_direct"`

	// Source is the file the dependency was read from (manifest or lockfile),
	// used for reporting provenance.
	Source string `json:"source,omitempty"`
}

// Severity is the CVSS severity band, derived from the numeric score.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityNone     Severity = "none"
)

// Actionable classifies whether a finding can be fixed right now.
type Actionable string

const (
	ActionableNow     Actionable = "actionable_now" // a fixed version exists
	ActionableMonitor Actionable = "monitor"        // no fix / breaking bump required
)

// Finding is a vulnerability match for a specific dependency.
// It is produced by the matcher and enriched by the prioritizer.
type Finding struct {
	Dependency Dependency `json:"dependency"`

	// OSV vulnerability identifier (e.g. "GHSA-..." or "CVE-...").
	VulnID  string   `json:"vuln_id"`
	Aliases []string `json:"aliases,omitempty"`
	Summary string   `json:"summary,omitempty"`

	// CVSS score (highest across the provided vectors) and derived band.
	CVSS     float64  `json:"cvss"`
	Severity Severity `json:"severity"`

	// EPSS enrichment. Probability is in [0,1]; Percentile in [0,1].
	// Zero values mean "unknown" (EPSS unavailable), NOT "no risk".
	EPSSProbability float64 `json:"epss_probability"`
	EPSSPercentile  float64 `json:"epss_percentile"`

	// Versions reported by OSV as fixing the vulnerability, per ecosystem range.
	FixedVersions []string `json:"fixed_versions,omitempty"`

	// Prioritizer output.
	Priority   Severity   `json:"priority"` // composite, may differ from CVSS band
	Actionable Actionable `json:"actionable"`
	Reasons    []string   `json:"reasons,omitempty"` // human-readable, auditable scoring factors

	// Remediation output (filled by the remediation engine, may be empty).
	Remediation *Remediation `json:"remediation,omitempty"`
}

// Remediation is the suggested path to fix a finding.
type Remediation struct {
	// TargetVersion is the version to upgrade to, if one was determined.
	// Empty when no fixed version is available.
	TargetVersion string `json:"target_version,omitempty"`

	// ChangeType classifies the version delta from the current version.
	ChangeType ChangeType `json:"change_type"`

	// WithinConstraints is true if TargetVersion satisfies the manifest's
	// declared version range (always true in the MVP since we read lockfiles,
	// which contain no range constraints to check against).
	WithinConstraints bool `json:"within_constraints"`

	// Note carries guidance, e.g. why no target was chosen.
	Note string `json:"note,omitempty"`
}

// ChangeType describes the kind of version bump a remediation requires.
type ChangeType string

const (
	ChangeNone    ChangeType = "none"    // already fixed / not applicable
	ChangePatch   ChangeType = "patch"   // safe, low risk
	ChangeMinor   ChangeType = "minor"   // generally safe
	ChangeMajor   ChangeType = "major"   // potentially breaking
	ChangeUnknown ChangeType = "unknown" // version cannot be compared
	ChangeNoFix   ChangeType = "no_fix"  // no fixed version published
)
