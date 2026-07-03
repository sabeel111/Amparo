package parser

import (
	"github.com/sabeel111/Amparo/internal/model"
	cargoparser "github.com/sabeel111/Amparo/internal/parser/cargo"
	goparser "github.com/sabeel111/Amparo/internal/parser/go"
	npmparser "github.com/sabeel111/Amparo/internal/parser/npm"
	pipparser "github.com/sabeel111/Amparo/internal/parser/pip"
)

// npmParser adapts the npmparser.Parse function to the Parser interface.
type npmParser struct{}

func newNPM() Parser { return npmParser{} }

func (npmParser) Names() []string { return []string{"package-lock.json"} }
func (npmParser) Parse(filename string, content []byte) ([]model.Dependency, error) {
	return npmparser.Parse(filename, content)
}

// goParser adapts the goparser.Parse function to the Parser interface.
type goParser struct{}

func newGo() Parser { return goParser{} }

func (goParser) Names() []string { return []string{"go.sum", "go.mod"} }
func (goParser) Parse(filename string, content []byte) ([]model.Dependency, error) {
	return goparser.Parse(filename, content)
}

// cargoParser adapts the cargoparser.Parse function to the Parser interface.
type cargoParser struct{}

func newCargo() Parser { return cargoParser{} }

func (cargoParser) Names() []string { return []string{"cargo.lock"} }
func (cargoParser) Parse(filename string, content []byte) ([]model.Dependency, error) {
	return cargoparser.Parse(filename, content)
}

// pipParser adapts the pip parsers. Multiple filenames route to different
// parse functions but share the PyPI ecosystem.
type pipParser struct{}

func newPip() Parser { return pipParser{} }

func (pipParser) Names() []string {
	return []string{"pipfile.lock", "poetry.lock", "requirements.txt"}
}

func (pipParser) Parse(filename string, content []byte) ([]model.Dependency, error) {
	// Dispatch on the lowercase basename.
	switch lowerBase(filename) {
	case "pipfile.lock":
		return pipparser.ParsePipfileLock(filename, content)
	case "poetry.lock":
		return pipparser.ParsePoetryLock(filename, content)
	case "requirements.txt":
		return pipparser.ParseRequirements(filename, content)
	default:
		return pipparser.ParseRequirements(filename, content)
	}
}
