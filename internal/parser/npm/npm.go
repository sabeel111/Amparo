// Package npmparser parses npm lockfiles (package-lock.json v1/v2/v3) into
// resolved dependencies.
//
// npm lockfile versions:
//
//	lockfileVersion 1: flat "dependencies" map (legacy).
//	lockfileVersion 2/3: "packages" map keyed by node_modules path, plus a
//	legacy "dependencies" mirror. The "packages" map is authoritative.
//
// Keys in "packages" look like "node_modules/foo" (direct) or
// "node_modules/foo/node_modules/bar" (nested/deduped). The root project itself
// is keyed by the empty string "" and is skipped.
package npmparser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
)

type lockfile struct {
	LockfileVersion int `json:"lockfileVersion"`
	Packages        map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"packages"`
	// v1 legacy
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

const rootKey = "" // the project's own package is keyed by empty string

// Parse parses package-lock.json bytes into npm dependencies.
func Parse(filename string, content []byte) ([]model.Dependency, error) {
	var lf lockfile
	if err := json.Unmarshal(content, &lf); err != nil {
		return nil, fmt.Errorf("npm: parsing %s: %w", filename, err)
	}

	var deps []model.Dependency
	seen := map[string]bool{} // dedupe by name@version

	// Prefer "packages" (v2/v3). Each key's last path segment is the package name.
	for key, pkg := range lf.Packages {
		if key == rootKey {
			continue // the project root
		}
		name := nameFromKey(key)
		if name == "" || pkg.Version == "" {
			continue
		}
		if strings.HasPrefix(name, "@") && strings.Contains(strings.TrimPrefix(key, "node_modules/"), "/") {
			// Scoped packages under node_modules: "@scope/name" -> keep full scoped name.
			name = scopedNameFromKey(key)
		}
		id := name + "@" + pkg.Version
		if seen[id] {
			continue
		}
		seen[id] = true
		deps = append(deps, model.Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: model.EcosystemNPM,
			IsDirect:  isDirect(key),
			Source:    filename,
		})
	}

	// Fallback to v1 "dependencies" if packages was empty.
	if len(deps) == 0 {
		for name, dep := range lf.Dependencies {
			if dep.Version == "" {
				continue
			}
			id := name + "@" + dep.Version
			if seen[id] {
				continue
			}
			seen[id] = true
			// v1 doesn't distinguish direct/transitive reliably; assume direct.
			deps = append(deps, model.Dependency{
				Name: name, Version: dep.Version, Ecosystem: model.EcosystemNPM,
				IsDirect: true, Source: filename,
			})
		}
	}

	return deps, nil
}

// nameFromKey extracts the package name from a "packages" key.
// "node_modules/lodash" -> "lodash"
// "node_modules/@babel/core" -> "@babel/core"
// "node_modules/a/node_modules/b" -> "b" (nested copy; npm dedupes to top-level)
func nameFromKey(key string) string {
	const nm = "node_modules/"
	if !strings.HasPrefix(key, nm) {
		return ""
	}
	rest := strings.TrimPrefix(key, nm)
	// For nested installs the relevant package is after the LAST node_modules/.
	if i := strings.LastIndex(rest, "/"+nm); i >= 0 {
		rest = rest[i+len("/"+nm):]
	} else if strings.Contains(rest, "/") && !strings.HasPrefix(rest, "@") {
		// Unscoped nested: take last segment.
		if i := strings.LastIndex(rest, "/"); i >= 0 {
			rest = rest[i+1:]
		}
	}
	return rest
}

// scopedNameFromKey handles "@scope/name" keys precisely.
func scopedNameFromKey(key string) string {
	const nm = "node_modules/"
	rest := strings.TrimPrefix(key, nm)
	// Find the start of "@scope/name" — the segment beginning with "@".
	if i := strings.LastIndex(rest, "/@"); i >= 0 {
		return rest[i+1:]
	}
	return rest
}

// isDirect returns true for top-level packages (key has no nested node_modules).
func isDirect(key string) bool {
	const nm = "node_modules/"
	rest := strings.TrimPrefix(key, nm)
	// A direct dep has exactly one node_modules prefix and no nested one.
	return !strings.Contains(rest, "/"+nm)
}
