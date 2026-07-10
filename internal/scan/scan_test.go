package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_StrictFailsWhenSupportedLockfileCannotParse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(path, []byte(`{not valid JSON`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), nil, Options{Path: dir, MatchMode: "live", Strict: true})
	if err == nil {
		t.Fatal("expected strict scan to fail when a supported lockfile cannot parse")
	}
	if !strings.Contains(err.Error(), "coverage incomplete") {
		t.Errorf("error = %q, want coverage-incomplete error", err)
	}
}
