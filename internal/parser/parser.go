// Package parser turns manifest/lockfile contents into resolved []model.Dependency.
//
// Each ecosystem registers a Parser keyed by the filenames it understands. The
// registry auto-detects the right parser from a filename, so callers just hand
// over (filename, bytes) pairs and get back dependencies. MVP supports npm and
// pip; the interface is designed so Maven/Go/Cargo plug in identically.
package parser

import (
	"fmt"
	"strings"

	"github.com/sabeel111/Amparo/internal/model"
)

// Parser parses a single lockfile/manifest into resolved dependencies.
// Implementations must be safe for concurrent use.
type Parser interface {
	// Names returns the filenames this parser handles (lowercase, basename).
	Names() []string

	// Parse reads the file content and returns resolved dependencies.
	// Returns an error if the content is malformed.
	Parse(filename string, content []byte) ([]model.Dependency, error)
}

// Registry maps filenames to parsers.
type Registry struct {
	byName map[string]Parser
}

// NewRegistry returns a registry pre-loaded with the built-in parsers.
func NewRegistry() *Registry {
	r := &Registry{byName: map[string]Parser{}}
	r.Register(newNPM())
	r.Register(newPip())
	r.Register(newGo())
	r.Register(newCargo())
	return r
}

// Register adds a parser. Later registrations win on name collisions.
func (r *Registry) Register(p Parser) {
	for _, name := range p.Names() {
		r.byName[strings.ToLower(name)] = p
	}
}

// Lookup returns the parser for a filename, or nil if none matches.
func (r *Registry) Lookup(filename string) Parser {
	base := lowerBase(filename)
	// Exact basename match first (handles "package-lock.json", "poetry.lock").
	if p, ok := r.byName[base]; ok {
		return p
	}
	return nil
}

// ParseFile is a convenience that looks up the parser for filename and parses.
func (r *Registry) ParseFile(filename string, content []byte) ([]model.Dependency, error) {
	p := r.Lookup(filename)
	if p == nil {
		return nil, fmt.Errorf("no parser for file %q (supported: %s)", filename, supportedFiles(r))
	}
	return p.Parse(filename, content)
}

func lowerBase(path string) string {
	// Handle both / and \ separators.
	path = strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		path = path[i+1:]
	}
	return strings.ToLower(path)
}

func supportedFiles(r *Registry) string {
	var names []string
	for name := range r.byName {
		names = append(names, name)
	}
	return strings.Join(names, ", ")
}
