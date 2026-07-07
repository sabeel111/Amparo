package continuity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sabeel111/Amparo/internal/store"
)

// TestContinuity_SurfacesNewFindingWithoutRescan is THE test for the continuity
// differentiator. It proves: a vulnerability published AFTER a snapshot was taken
// produces a new finding on that stored snapshot, with NO source rescan.
//
// Scenario:
//  1. Persist a snapshot containing dep "fakepkg@1.0.0".
//  2. Confirm no findings exist for it yet.
//  3. Inject a vuln_record + vuln_package row for fakepkg, modified=NOW (simulating
//     a freshly-synced advisory).
//  4. Run continuity.
//  5. Assert a new finding was created for the stored snapshot — without any
//     re-parsing of source.
func TestContinuity_SurfacesNewFindingWithoutRescan(t *testing.T) {
	ctx := context.Background()
	conn := os.Getenv("DATABASE_URL")
	if conn == "" {
		conn = store.DefaultConnString
	}
	pool, err := store.Open(ctx, conn)
	if err != nil {
		t.Skipf("DB unavailable: %v", err)
	}
	defer pool.Close()
	st := store.New(pool)

	uid := fmt.Sprintf("%d", time.Now().UnixNano())
	pkgName := "continuity-fakepkg-" + uid
	vulnID := "CONTINUITY-TEST-" + uid

	// 1. Persist a snapshot containing the fake dep.
	pid, err := st.EnsureProject(ctx, "test-org", "cont-proj-"+uid)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := st.CreateSnapshot(ctx, pid, "", "cont-test-"+uid)
	if err != nil {
		t.Fatal(err)
	}
	deps := []store.DepRow{{
		Purl: "pkg:npm/" + pkgName + "@1.0.0", Name: pkgName,
		Version: "1.0.0", Ecosystem: "npm", IsDirect: true,
	}}
	if err := st.InsertDependencies(ctx, snap, deps); err != nil {
		t.Fatal(err)
	}

	// 2. Inject a "freshly published" vuln affecting fakepkg@1.0.0.
	//    The affected range covers 1.0.0 (introduced 0, fixed 2.0.0).
	affected, _ := json.Marshal([]map[string]any{{
		"package": map[string]string{"name": pkgName, "ecosystem": "npm"},
		"ranges": []map[string]any{{
			"type": "SEMVER",
			"events": []map[string]string{{"introduced": "0"}, {"fixed": "2.0.0"}},
		}},
	}})
	vuln := store.VulnRow{
		OSVID:         vulnID,
		Summary:       "continuity test vuln",
		SeverityScore: 9.0,
		CVSSVectors:   []string{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		FixedVersions: []string{"2.0.0"},
		Affected:      affected,
		Ecosystem:     "npm",
		Modified:      time.Now().UTC(), // NOW → counts as "changed since cutoff"
	}
	if err := st.UpsertVuln(ctx, vuln); err != nil {
		t.Fatal(err)
	}
	if err := st.ReindexVulnPackages(ctx, []string{vulnID}); err != nil {
		t.Fatal(err)
	}
	// Cleanup on test exit.
	defer func() {
		pool.Exec(ctx, `DELETE FROM finding WHERE vuln_id=$1`, vulnID)
		pool.Exec(ctx, `DELETE FROM vuln_package WHERE vuln_id=$1`, vulnID)
		pool.Exec(ctx, `DELETE FROM vuln_record WHERE osv_id=$1`, vulnID)
		pool.Exec(ctx, `DELETE FROM dependency WHERE snapshot_id=$1`, snap)
		pool.Exec(ctx, `DELETE FROM snapshot WHERE id=$1`, snap)
	}()

	// Sanity: no findings exist yet.
	existing, _ := st.FindingsByProject(ctx, pid, "")
	if len(existing) > 0 {
		t.Fatalf("expected 0 findings before continuity, got %d", len(existing))
	}

	// 4. Run continuity with a cutoff 1 minute ago (so our just-injected vuln counts).
	res, err := RunSince(ctx, pool, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatalf("continuity.RunSince: %v", err)
	}
	t.Logf("continuity result: %+v", res)

	// 5. Assert a new finding was created for the stored snapshot.
	if res.NewFindings == 0 {
		t.Error("expected continuity to create >=1 new finding, got 0")
	}
	after, _ := st.FindingsByProject(ctx, pid, "")
	found := false
	for _, f := range after {
		if f.VulnID == vulnID {
			found = true
			if f.Status != "new" {
				t.Errorf("finding status = %s, want 'new'", f.Status)
			}
		}
	}
	if !found {
		t.Error("continuity did not create a finding for the newly-synced vuln")
	}
}
