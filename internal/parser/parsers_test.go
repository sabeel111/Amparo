package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sabeel111/Amparo/internal/model"
)

// TestParseGoSum verifies the go.sum parser extracts modules and dedupes the
// two line forms (h1: and /go.mod).
func TestParseGoSum(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "go", "go.sum"))
	if err != nil {
		t.Skip("go.sum fixture missing")
	}
	deps, err := NewRegistry().ParseFile("go.sum", content)
	if err != nil {
		t.Fatal(err)
	}
	// 4 unique modules in the fixture (crypto appears twice, deduped).
	if len(deps) != 4 {
		t.Fatalf("expected 4 deps, got %d: %+v", len(deps), deps)
	}
	names := map[string]bool{}
	for _, d := range deps {
		if d.Ecosystem != model.EcosystemGo {
			t.Errorf("dep %s has ecosystem %s, want Go", d.Name, d.Ecosystem)
		}
		names[d.Name] = true
	}
	for _, want := range []string{"golang.org/x/crypto", "golang.org/x/net", "github.com/gin-gonic/gin", "gopkg.in/yaml.v3"} {
		if !names[want] {
			t.Errorf("expected module %s in results", want)
		}
	}
}

// TestParseCargoLock verifies the Cargo.lock parser skips the root crate (no
// source) and emits registry packages.
func TestParseCargoLock(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cargo", "Cargo.lock"))
	if err != nil {
		t.Skip("Cargo.lock fixture missing")
	}
	deps, err := NewRegistry().ParseFile("Cargo.lock", content)
	if err != nil {
		t.Fatal(err)
	}
	// test-crate has no source and must be skipped; the 3 registry packages remain.
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps (root crate skipped), got %d: %+v", len(deps), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != model.EcosystemCargo {
			t.Errorf("dep %s ecosystem = %s, want cargo", d.Name, d.Ecosystem)
		}
		if d.Name == "test-crate" {
			t.Error("root crate (no source) should be skipped")
		}
	}
}
