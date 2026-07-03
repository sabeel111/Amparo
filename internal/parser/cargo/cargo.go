// Package cargoparser parses Rust Cargo.lock files into resolved dependencies.
//
// Cargo.lock is TOML with [[package]] tables:
//
//	[[package]]
//	name = "serde"
//	version = "1.0.197"
//	source = "registry+https://github.com/rust-lang/crates.io-index"
//
// It lists the full resolved dependency set (including transitive deps), so it's
// authoritative for SCA. The "source" field distinguishes registry packages
// (crates.io) from path/git packages; only registry packages have CVE/advisory
// coverage via RustSec/OSV, but we emit all of them and let matching decide.
package cargoparser

import (
	"fmt"

	"github.com/BurntSushi/toml"

	"github.com/sabeel111/Amparo/internal/model"
)

type cargoLock struct {
	Packages []struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
		Source  string `toml:"source"`
	} `toml:"package"`
}

// Parse parses Cargo.lock bytes into cargo dependencies.
func Parse(filename string, content []byte) ([]model.Dependency, error) {
	var cl cargoLock
	if _, err := toml.Decode(string(content), &cl); err != nil {
		return nil, fmt.Errorf("cargo: parsing %s: %w", filename, err)
	}
	var deps []model.Dependency
	for _, pkg := range cl.Packages {
		if pkg.Name == "" || pkg.Version == "" {
			continue
		}
		// The root package has no "source" (it's the local crate); skip it since
		// you can't be vulnerable to yourself via a registry advisory.
		if pkg.Source == "" {
			continue
		}
		deps = append(deps, model.Dependency{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: model.EcosystemCargo,
			// Cargo.lock doesn't mark direct vs transitive; conservatively mark
			// all as transitive (IsDirect=false) — same approach as poetry.lock.
			IsDirect: false,
			Source:   filename,
		})
	}
	return deps, nil
}
