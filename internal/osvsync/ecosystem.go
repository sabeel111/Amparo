// Package osvsync downloads the OSV.dev vulnerability database locally and keeps
// it in sync with Postgres.
//
// Mechanism (mirrors google/osv-scanner's proven approach):
//   - Each ecosystem's full record set is published as a single ZIP at
//     https://osv-vulnerabilities.storage.googleapis.com/<ECO>/all.zip
//     (plain HTTP GET, no auth, no API keys). E.g. npm/all.zip is ~85MB.
//   - Change detection: HTTP HEAD, compare Last-Modified against the cached copy;
//     skip re-download when unchanged (cheap polling).
//   - The ZIP contains one <VULN_ID>.json per record (OSV schema). We stream-extract
//     it (NOT load-all-then-parse) to bound memory per osv-scanner issue #2217,
//     parse each record, and bulk-upsert into vuln_record.
//
// After a sync, ChangedVulnsSince() lets the matcher re-evaluate existing
// snapshots — this is what makes the product genuinely continuous (Flow B):
// a CVE that drops today alerts on code committed months ago, no rescan needed.
package osvsync

import "github.com/sabeel111/Amparo/internal/model"

// bucketEcosystem maps our internal model.Ecosystem values to the OSV bucket
// directory names, which are case-sensitive and exact (e.g. "PyPI", not "pypi";
// "crates.io", not "cargo"). This is the gotcha from the sync research.
func bucketEcosystem(eco model.Ecosystem) (bucket string, ok bool) {
	switch eco {
	case model.EcosystemNPM:
		return "npm", true
	case model.EcosystemPyPI:
		return "PyPI", true
	case model.EcosystemMaven:
		return "Maven", true
	case model.EcosystemGo:
		return "Go", true
	case model.EcosystemCargo:
		return "crates.io", true // internal "cargo" -> OSV bucket "crates.io"
	}
	return "", false
}

// SupportedEcosystems returns the ecosystems Phase 1 syncs.
func SupportedEcosystems() []model.Ecosystem {
	return []model.Ecosystem{
		model.EcosystemNPM,
		model.EcosystemPyPI,
		model.EcosystemGo,
		model.EcosystemCargo,
		// Maven deferred to Phase 2 (effective-POM resolver).
	}
}

// ParseEcosystemFlag parses a comma-separated --ecosystems flag like "npm,PyPI"
// into model.Ecosystem values. Unknown values are ignored with their names
// returned for error reporting.
func ParseEcosystemFlag(s string) ([]model.Ecosystem, []string) {
	if s == "" || s == "all" {
		return SupportedEcosystems(), nil
	}
	var out []model.Ecosystem
	var unknown []string
	// Map both bucket names and internal names back to model values.
	known := map[string]model.Ecosystem{
		"npm": model.EcosystemNPM, "NPM": model.EcosystemNPM,
		"PyPI": model.EcosystemPyPI, "pypi": model.EcosystemPyPI, "pip": model.EcosystemPyPI,
		"Go": model.EcosystemGo, "go": model.EcosystemGo, "golang": model.EcosystemGo,
		"crates.io": model.EcosystemCargo, "cargo": model.EcosystemCargo, "Cargo": model.EcosystemCargo,
		"Maven": model.EcosystemMaven, "maven": model.EcosystemMaven,
	}
	for _, raw := range splitComma(s) {
		if eco, ok := known[raw]; ok {
			out = append(out, eco)
		} else {
			unknown = append(unknown, raw)
		}
	}
	return out, unknown
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == ',' {
			if cur != "" {
				out = append(out, cur)
			}
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
