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

// ParseRequirements parses a pip requirements.txt (best-effort). Each non-comment,
// non-empty line of the form "name==version" or "name>=version" yields a dep.
// Only pinned (==) lines produce a concrete version; others are skipped to avoid
// reporting a false version to OSV.
func ParseRequirements(filename string, content []byte) ([]model.Dependency, error) {
	var deps []model.Dependency
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments and environment markers.
		if i := strings.IndexAny(line, " \t#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Only accept exact pins: name==version.
		if !strings.Contains(line, "==") {
			continue
		}
		parts := strings.SplitN(line, "==", 2)
		name := normalizePipName(strings.TrimSpace(parts[0]))
		ver := strings.TrimSpace(parts[1])
		if name == "" || ver == "" {
			continue
		}
		deps = append(deps, model.Dependency{
			Name: name, Version: ver, Ecosystem: model.EcosystemPyPI,
			IsDirect: true, Source: filename,
		})
	}
	return deps, sc.Err()
}

// normalizePipName applies PEP 503 normalization (lowercase + dashes).
// "Django_Header" -> "django-header". OSV and PyPA both use this canonical form.
func normalizePipName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
