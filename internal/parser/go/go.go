// Package goparser parses Go module files (go.sum, go.mod) into resolved dependencies.
//
// go.sum is the authoritative source: it lists every module fetched (direct +
// transitive) with two lines per module:
//
//	golang.org/x/crypto v0.17.0 h1:aaaa...
//	golang.org/x/crypto v0.17.0/go.mod h1:bbbb...
//
// We extract (module, version) from both line forms. go.sum gives the full
// resolved transitive set. Versions include Go pseudo-versions
// (v0.0.0-20240102120000-abcdef1234ab) which are handled by the Go comparator.
//
// The OSV ecosystem for Go modules is "Go"; advisories live in the Go vuln DB.
package goparser

import (
	"bufio"
	"fmt"
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
)

// Parse parses a go.sum (preferred) or go.mod into Go module dependencies.
// Detection is by filename: go.sum → full parse; go.mod → best-effort require
// directives (no transitive closure, versions may be ranges).
func Parse(filename string, content []byte) ([]model.Dependency, error) {
	base := strings.ToLower(baseName(filename))
	switch {
	case strings.HasSuffix(base, "go.sum"):
		return parseGoSum(filename, content)
	case strings.HasSuffix(base, "go.mod"):
		return parseGoMod(filename, content)
	default:
		// If the content looks like a go.sum (has h1: hashes), parse as go.sum.
		if strings.Contains(string(content), "h1:") {
			return parseGoSum(filename, content)
		}
		return parseGoMod(filename, content)
	}
}

// parseGoSum extracts (module, version) pairs. go.sum has two line variants:
//
//	<module> <version> h1:<hash>
//	<module> <version>/go.mod h1:<hash>
//
// We take the version from both but dedupe on (module, version).
func parseGoSum(filename string, content []byte) ([]model.Dependency, error) {
	seen := map[string]bool{}
	var deps []model.Dependency
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Format: "module version [more]". The first two fields are module+version.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		module := fields[0]
		version := fields[1]
		// Skip the "/go.mod" form's variant marker — keep the base version.
		version = strings.TrimSuffix(version, "/go.mod")
		if module == "" || version == "" {
			continue
		}
		key := module + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, model.Dependency{
			Name:      module,
			Version:   version,
			Ecosystem: model.EcosystemGo,
			// go.sum doesn't distinguish direct/transitive.
			IsDirect: false,
			Source:   filename,
		})
	}
	return deps, sc.Err()
}

// parseGoMod extracts dependencies from go.mod "require" blocks. go.mod versions
// may be ranges (e.g. "v1.2.3" is a minimum); only exact pins produce a useful
// version for OSV matching. This is best-effort — go.sum is preferred.
func parseGoMod(filename string, content []byte) ([]model.Dependency, error) {
	var deps []model.Dependency
	sc := bufio.NewScanner(strings.NewReader(string(content)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	inRequire := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// Single-line require: require module version
		if strings.HasPrefix(line, "require ") {
			if dep, ok := parseRequireLine(strings.TrimPrefix(line, "require ")); ok {
				deps = append(deps, dep)
			}
			continue
		}
		// Block require: require ( ... )
		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
			if dep, ok := parseRequireLine(line); ok {
				dep.Source = filename
				deps = append(deps, dep)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("go: parsing %s: %w", filename, err)
	}
	return deps, nil
}

// parseRequireLine parses "module version [// comment]" into a dependency.
// go.mod versions are minimums (semver), not exact pins, so we keep them but
// mark IsDirect=true (require directives are top-level direct deps).
func parseRequireLine(line string) (model.Dependency, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return model.Dependency{}, false
	}
	module := fields[0]
	version := fields[1]
	if module == "" || version == "" {
		return model.Dependency{}, false
	}
	return model.Dependency{
		Name:      module,
		Version:   version,
		Ecosystem: model.EcosystemGo,
		IsDirect:  true,
	}, true
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return path
}
