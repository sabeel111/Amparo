package pipparser

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/sabeel111/Amparo/internal/model"
)

// poetryLock mirrors the relevant parts of a poetry.lock file.
// Each [[package]] table has name, version, and an optional "category"
// ("main" = production, "dev" = test).
type poetryLock struct {
	Packages []struct {
		Name     string `toml:"name"`
		Version  string `toml:"version"`
		Category string `toml:"category"`
	} `toml:"package"`
}

// ParsePoetryLock parses a poetry.lock (TOML) into PyPI dependencies.
// Poetry records the full resolved set (including transitive deps), so these
// are marked IsDirect=false unless we can tell otherwise — poetry.lock v1/2
// doesn't reliably tag direct vs transitive, so we conservatively mark all as
// transitive (IsDirect=false). Direct-vs-transitive is a prioritization signal,
// not a correctness one, so being conservative here biases slightly low.
func ParsePoetryLock(filename string, content []byte) ([]model.Dependency, error) {
	var pl poetryLock
	if _, err := toml.Decode(string(content), &pl); err != nil {
		return nil, fmt.Errorf("pip: parsing %s: %w", filename, err)
	}
	var deps []model.Dependency
	for _, pkg := range pl.Packages {
		v := cleanPipVersion(pkg.Version)
		if pkg.Name == "" || v == "" {
			continue
		}
		deps = append(deps, model.Dependency{
			Name:      normalizePipName(pkg.Name),
			Version:   v,
			Ecosystem: model.EcosystemPyPI,
			IsDirect:  false, // conservative; see docstring
			Source:    filename,
		})
	}
	return deps, nil
}
