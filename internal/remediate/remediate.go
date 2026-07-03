// Package remediate computes the remediation path for each finding.
//
// Given a finding with a set of fixed versions (from OSV), pick the LOWEST
// fixed version that is strictly greater than the current vulnerable version,
// and classify the bump (patch/minor/major) so the user understands the risk.
// This is deterministic version arithmetic — no LLM, no network.
package remediate

import (
	"github.com/sabeel111/Amparo/internal/model"
	pipparser "github.com/sabeel111/Amparo/internal/parser/pip"
)

// For computes the remediation for a single finding.
func For(f model.Finding) *model.Remediation {
	r := &model.Remediation{WithinConstraints: true}

	if len(f.FixedVersions) == 0 {
		r.ChangeType = model.ChangeNoFix
		r.Note = "no fixed version published yet; monitor the advisory"
		return r
	}

	current := f.Dependency.Version
	target := pickLowestFixed(current, f.FixedVersions, f.Dependency.Ecosystem)
	if target == "" {
		// None of the fixed versions are above the current version (e.g. all
		// fixed versions listed are older than what's installed). This can mean
		// the user is already on a fixed line, or the data is inconsistent.
		r.ChangeType = model.ChangeNone
		r.Note = "installed version is not below any listed fixed version; may already be fixed"
		return r
	}

	r.TargetVersion = target
	r.ChangeType = classifyBump(current, target, f.Dependency.Ecosystem)
	return r
}

// pickLowestFixed returns the lowest fixed version strictly greater than current.
// Uses the ecosystem-appropriate comparator so PyPI versions are compared with
// PEP 440 and others with the generic semver comparator.
func pickLowestFixed(current string, fixedVersions []string, eco model.Ecosystem) string {
	cmp := comparatorFor(eco)
	var best string
	for _, fv := range fixedVersions {
		if cmp(fv, current) <= 0 {
			continue // not above current; skip
		}
		if best == "" || cmp(fv, best) < 0 {
			best = fv
		}
	}
	return best
}

// classifyBump determines patch/minor/major by comparing the version components.
func classifyBump(current, target string, eco model.Ecosystem) model.ChangeType {
	cmp := comparatorFor(eco)
	if cmp(current, target) >= 0 {
		return model.ChangeNone
	}
	maj, min, _, ok := splitMajorMinor(target)
	if !ok {
		return model.ChangeUnknown
	}
	curMaj, curMin, _, ok := splitMajorMinor(current)
	if !ok {
		return model.ChangeUnknown
	}
	if maj > curMaj {
		return model.ChangeMajor
	}
	if min > curMin {
		return model.ChangeMinor
	}
	return model.ChangePatch
}

// splitMajorMinor extracts major.minor.patch as ints from a version string.
// Returns ok=false if the leading components aren't numeric.
func splitMajorMinor(v string) (maj, min, pat int, ok bool) {
	core := v
	for i := 0; i < len(core); i++ {
		c := core[i]
		if !(c >= '0' && c <= '9') && c != '.' {
			core = core[:i]
			break
		}
	}
	parts := splitDot(core)
	if len(parts) == 0 {
		return 0, 0, 0, false
	}
	maj, ok = atoiSafe(parts[0])
	if !ok {
		return 0, 0, 0, false
	}
	if len(parts) > 1 {
		min, _ = atoiSafe(parts[1])
	}
	if len(parts) > 2 {
		pat, _ = atoiSafe(parts[2])
	}
	return maj, min, pat, true
}

func splitDot(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	cur := ""
	for _, c := range s {
		if c == '.' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	out = append(out, cur)
	return out
}

func atoiSafe(s string) (int, bool) {
	if s == "" {
		return 0, true // missing component = 0
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

// comparatorFor returns the right version comparator per ecosystem.
func comparatorFor(eco model.Ecosystem) func(a, b string) int {
	if eco == model.EcosystemPyPI {
		return pipparser.ComparePipVersions
	}
	return model.CompareVersions
}
