// Package pipparser parses Python dependency lockfiles (Pipfile.lock, poetry.lock,
// and pip's requirements.txt) into resolved PyPI dependencies.
//
// MVP supports:
//   - Pipfile.lock  (JSON; authoritative resolved versions)
//   - poetry.lock   (TOML; authoritative resolved versions)
//   - requirements.txt with "pkg==version" (best-effort; no transitive closure)
//
// PEP 440 version comparison is handled by a dedicated comparator in pep440.go,
// NOT the generic model.CompareVersions, because PyPI versions (e.g. "1.0.1b2",
// "1!2.0", "1.0.post1") are not semver.
package pipparser

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
)

// pipfileLock mirrors the Pipfile.lock JSON structure.
type pipfileLock struct {
	Meta struct {
		Hash struct {
			Sha256 string `json:"sha256"`
		} `json:"hash"`
	} `json:"_meta"`
	Default map[string]struct {
		Version string `json:"version"`
	} `json:"default"`
	Develop map[string]struct {
		Version string `json:"version"`
	} `json:"develop"`
}

// ParsePipfileLock parses a Pipfile.lock (JSON) into PyPI dependencies.
func ParsePipfileLock(filename string, content []byte) ([]model.Dependency, error) {
	var pl pipfileLock
	if err := json.Unmarshal(content, &pl); err != nil {
		return nil, fmt.Errorf("pip: parsing %s: %w", filename, err)
	}
	var deps []model.Dependency
	// "default" = production deps, "develop" = dev/test deps. All are direct
	// from the Pipfile's perspective (Pipfile.lock does not record the full
	// transitive closure in a structured way).
	for name, info := range pl.Default {
		if v := cleanPipVersion(info.Version); v != "" {
			deps = append(deps, model.Dependency{
				Name: name, Version: v, Ecosystem: model.EcosystemPyPI,
				IsDirect: true, Source: filename,
			})
		}
	}
	for name, info := range pl.Develop {
		if v := cleanPipVersion(info.Version); v != "" {
			deps = append(deps, model.Dependency{
				Name: name, Version: v, Ecosystem: model.EcosystemPyPI,
				IsDirect: true, Source: filename,
			})
		}
	}
	return deps, nil
}

// cleanPipVersion strips surrounding quotes that Pipfile.lock uses for versions
// (e.g. "\"1.2.3\"" -> "1.2.3") and any "==" prefix.
func cleanPipVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, "\"'")
	v = strings.TrimPrefix(v, "==")
	return strings.TrimSpace(v)
}

// ParseRequirements parses a pip requirements.txt.
//
// Captures BOTH exact pins (name==1.2.3) AND version ranges (name>=1.0,<2.0,
// name~=1.2, bare names). Pinned deps get their concrete version in Version
// (usable directly for OSV matching). Range/bare deps get the raw specifier
// string in Version and are left for the resolver to expand into a concrete
// version via the PyPI API.
//
// Lines starting with "-" (flags like -r, -e, --index-url), comments, and
// environment-marker-only specs are skipped. VCS URLs (git+https://...) and
// local paths (-e .) are skipped — they can't be matched against OSV.
func ParseRequirements(filename string, content []byte) ([]model.Dependency, error) {
	var deps []model.Dependency
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Skip VCS URLs and local editable installs — not matchable against OSV.
		if strings.Contains(line, "://") || strings.HasPrefix(line, ".") {
			continue
		}
		// Strip inline comments and environment markers ("; python_version >= '3.6'").
		if i := strings.IndexAny(line, ";#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Also strip trailing whitespace-separated extras like "[ssl]".
		name, spec := splitNameSpec(line)
		name = normalizePipName(name)
		if name == "" {
			continue
		}
		// Extract the version portion from the specifier.
		ver := extractVersion(spec)
		deps = append(deps, model.Dependency{
			Name: name, Version: ver, Ecosystem: model.EcosystemPyPI,
			IsDirect: true, Source: filename,
		})
	}
	return deps, sc.Err()
}

// splitNameSpec splits "package-name>=1.0,<2.0[extra]" into (name, spec).
// The name is everything up to the first operator char or bracket.
func splitNameSpec(line string) (name, spec string) {
	// Strip extras like "package[ssl]" — keep only the package name.
	for i, c := range line {
		if c == '[' || isOperatorStart(line, i) {
			return strings.TrimSpace(line[:i]), strings.TrimSpace(line[i:])
		}
	}
	return strings.TrimSpace(line), ""
}

// isOperatorStart reports whether position i begins a version operator.
func isOperatorStart(s string, i int) bool {
	switch s[i] {
	case '=', '!', '<', '>', '~':
		return true
	}
	return false
}

// extractVersion pulls the version string out of a PEP 440 specifier.
// For a pin "==1.2.3" → "1.2.3". For a range ">=1.0,<2.0" → ">=1.0,<2.0"
// (kept whole; the resolver interprets it). For a bare name (no spec) → "".
// The resolver treats empty-version deps as "latest" and resolves them.
func extractVersion(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	// Exact pin: ==X.Y.Z (the common, directly-matchable case).
	if strings.HasPrefix(spec, "==") {
		v := strings.TrimPrefix(spec, "==")
		// Drop "===" strict equality operator's extra form if present.
		v = strings.TrimPrefix(v, "=")
		return strings.TrimSpace(v)
	}
	// Range / other operator: keep the whole specifier for the resolver.
	return spec
}

// normalizePipName applies PEP 503 normalization (lowercase + dashes).
// "Django_Header" -> "django-header". OSV and PyPA both use this canonical form.
func normalizePipName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
