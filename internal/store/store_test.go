package store

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/sabeel111/Amparo/internal/model"
)

// Integration tests against the Dockerized Postgres. Skipped if DATABASE_URL is
// unset, so these don't fail in CI without a DB.
func dbConn(t *testing.T) *Store {
	conn := os.Getenv("DATABASE_URL")
	if conn == "" {
		conn = DefaultConnString
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := Open(ctx, conn)
	if err != nil {
		t.Skipf("Postgres unavailable: %v", err)
	}
	return New(pool)
}

func TestMigrate_AppliesCleanly(t *testing.T) {
	ctx := context.Background()
	s := dbConn(t)
	defer s.Pool.Close()
	// Migrations run as part of Open; just verify tables exist.
	var n int
	err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema='public' AND table_name IN
		   ('organization','project','source','snapshot','dependency',
		    'vuln_record','finding','schema_migrations')`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if want := 8; n != want {
		t.Errorf("expected %d core tables, got %d", want, n)
	}
}

func TestProjectSnapshotDependencyRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := dbConn(t)
	defer s.Pool.Close()

	pid, err := s.EnsureProject(ctx, "test-org", "proj-"+t.Name())
	if err != nil {
		t.Fatal(err)
	}
	snap, err := s.CreateSnapshot(ctx, pid, "", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	deps := []DepRow{
		{Purl: "pkg:npm/lodash@4.17.20", Name: "lodash", Version: "4.17.20",
			Ecosystem: string(model.EcosystemNPM), IsDirect: true},
		{Purl: "pkg:npm/axios@0.21.0", Name: "axios", Version: "0.21.0",
			Ecosystem: string(model.EcosystemNPM)},
	}
	if err := s.InsertDependencies(ctx, snap, deps); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM dependency WHERE snapshot_id=$1`, snap).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != len(deps) {
		t.Errorf("dependency count = %d, want %d", count, len(deps))
	}
}

func TestUpsertVulnAndFindByPackage(t *testing.T) {
	ctx := context.Background()
	s := dbConn(t)
	defer s.Pool.Close()

	affected := `[{"package":{"name":"lodash","ecosystem":"npm"},
	               "ranges":[{"type":"SEMVER","events":[{"introduced":"4.0.0"},{"fixed":"4.17.21"}]}]}]`
	v := VulnRow{
		OSVID:         "TEST-GHSA-" + t.Name(),
		Aliases:       []string{"TEST-CVE-9999"},
		Summary:       "test vuln",
		SeverityScore: 7.5,
		FixedVersions: []string{"4.17.21"},
		Affected:      []byte(affected),
		Ecosystem:     "npm",
		Modified:      time.Now(),
	}
	if err := s.UpsertVuln(ctx, v); err != nil {
		t.Fatal(err)
	}
	// Upsert again (idempotency).
	if err := s.UpsertVuln(ctx, v); err != nil {
		t.Fatal(err)
	}

	got, err := s.FindVulnsByPackage(ctx, "npm", "lodash")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range got {
		if r.OSVID == v.OSVID {
			found = true
		}
	}
	if !found {
		t.Errorf("FindVulnsByPackage didn't return the inserted vuln; got %d rows", len(got))
	}

	// Cleanup the test vuln.
	s.Pool.Exec(ctx, `DELETE FROM vuln_record WHERE osv_id=$1`, v.OSVID)
}

func TestBulkUpsertVulns_ReturnsOnlyInsertedOrMateriallyChangedIDs(t *testing.T) {
	ctx := context.Background()
	s := dbConn(t)
	defer s.Pool.Close()

	uid := fmt.Sprintf("%d", time.Now().UnixNano())
	v := VulnRow{
		OSVID: "TEST-BULK-VULN-" + uid, Summary: "original summary",
		Affected: []byte(`[]`), Ecosystem: "npm", Modified: time.Now().UTC().Add(-time.Hour),
	}
	defer s.Pool.Exec(ctx, `DELETE FROM vuln_record WHERE osv_id=$1`, v.OSVID)

	changed, err := s.BulkUpsertVulns(ctx, []VulnRow{v})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != v.OSVID {
		t.Fatalf("first bulk upsert changed IDs = %v, want [%s]", changed, v.OSVID)
	}

	changed, err = s.BulkUpsertVulns(ctx, []VulnRow{v})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 0 {
		t.Errorf("unchanged bulk upsert returned %v, want no changed IDs", changed)
	}

	v.Summary = "materially changed summary"
	changed, err = s.BulkUpsertVulns(ctx, []VulnRow{v})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != v.OSVID {
		t.Errorf("changed bulk upsert IDs = %v, want [%s]", changed, v.OSVID)
	}
}

func TestUpsertFinding_DedupBumpsLastSeen(t *testing.T) {
	ctx := context.Background()
	s := dbConn(t)
	defer s.Pool.Close()

	// Need a vuln_record to satisfy FK.
	// Use a unique vuln id + purl per run so the test is self-contained and
	// doesn't depend on prior test state in the shared dev DB.
	uid := fmt.Sprintf("%d", time.Now().UnixNano())
	vuln := VulnRow{
		OSVID: "TEST-FINDING-VULN-" + uid, Summary: "x", SeverityScore: 5,
		Affected: []byte(`[]`), Ecosystem: "npm", Modified: time.Now(),
	}
	if err := s.UpsertVuln(ctx, vuln); err != nil {
		t.Fatal(err)
	}
	defer s.Pool.Exec(ctx, `DELETE FROM vuln_record WHERE osv_id=$1`, vuln.OSVID)

	pid, _ := s.EnsureProject(ctx, "test-org", "finding-proj-"+uid)
	snap, _ := s.CreateSnapshot(ctx, pid, "", "h1")
	f := FindingRow{
		ProjectID: pid, SnapshotID: snap,
		DependencyPurl: "pkg:npm/foo@" + uid, DependencyName: "foo",
		DependencyVersion: "1.0.0", DependencyEcosystem: "npm",
		VulnID: vuln.OSVID, CVSS: 7.5, Priority: "high", Actionable: "actionable_now",
	}
	created, err := s.UpsertFinding(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Error("first insert should report created=true")
	}
	// Insert again — should NOT create, just bump last_seen.
	created2, err := s.UpsertFinding(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	if created2 {
		t.Error("second insert should report created=false (dedup)")
	}
	// Verify only one row.
	var n int
	s.Pool.QueryRow(ctx,
		`SELECT count(*) FROM finding WHERE project_id=$1 AND dependency_purl=$2 AND vuln_id=$3`,
		pid, f.DependencyPurl, f.VulnID).Scan(&n)
	if n != 1 {
		t.Errorf("expected 1 deduped finding, got %d", n)
	}
}
