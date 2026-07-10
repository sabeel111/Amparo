// Package resolver expands a set of direct dependencies into a full transitive
// closure by querying package registry APIs.
//
// This fixes FLAW 1: lockfile-less projects (pip requirements.txt without a
// poetry.lock/Pipfile.lock) only expose direct deps to the matcher, missing the
// transitive closure where most real vulnerabilities live. The resolver walks
// the dependency graph via the registry API (pypi.org for PyPI) and produces a
// concrete, pinned dependency set.
//
// Design: resolution is a separate pipeline stage from parsing (parsers stay
// pure — they emit what's in the file; the resolver expands it). The Resolver
// interface mirrors the existing Client patterns (osvclient, epss): an HTTP
// client with a BaseURL and ctx-aware methods.
package resolver

import (
	"context"
	"sync"

	"github.com/sabeel111/Amparo/internal/model"
)

// Resolver expands a set of (possibly ranged) direct dependencies into a full
// transitive closure of pinned dependencies.
type Resolver interface {
	// Ecosystem is the ecosystem this resolver handles.
	Ecosystem() model.Ecosystem
	// Resolve returns the full dependency set (direct + transitive) with concrete
	// versions. Direct deps keep IsDirect=true; transitives are IsDirect=false.
	Resolve(ctx context.Context, direct []model.Dependency) ([]model.Dependency, error)
}

// NeedsResolution reports whether a dependency set has unpinned (ranged/bare)
// entries that require resolution. A fully-pinned set (e.g. from a lockfile)
// returns false — no resolution needed.
func NeedsResolution(deps []model.Dependency) bool {
	for _, d := range deps {
		if !IsPinnedExported(d) {
			return true
		}
	}
	return false
}

// IsPinnedExported reports whether a dependency has a concrete version (no range
// operators). Used to decide whether resolution is necessary. Exported so the
// CLI wiring layer can check individual deps.
func IsPinnedExported(d model.Dependency) bool {
	return isPinned(d)
}

// isPinned reports whether a dependency has a concrete version (no range
// operators). Used to decide whether resolution is necessary.
func isPinned(d model.Dependency) bool {
	v := d.Version
	if v == "" {
		return false // bare name, needs resolution
	}
	for _, op := range []string{">=", "<=", "!=", "~=", ">", "<"} {
		if contains(v, op) {
			return false
		}
	}
	// "==" prefix already stripped by the parser; a plain version is pinned.
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// registry of resolvers by ecosystem.
var (
	mu        sync.RWMutex
	resolvers = map[model.Ecosystem]Resolver{}
)

// Register adds a resolver. Called from init() in each resolver implementation.
func Register(r Resolver) {
	mu.Lock()
	defer mu.Unlock()
	resolvers[r.Ecosystem()] = r
}

// For returns the resolver for an ecosystem, or nil if none registered.
func For(eco model.Ecosystem) Resolver {
	mu.RLock()
	defer mu.RUnlock()
	return resolvers[eco]
}
