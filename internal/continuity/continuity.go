// Package continuity implements the re-match loop that makes Amparo genuinely
// continuous (design doc Flow B).
//
// The promise: a vulnerability that drops today alerts on code committed months
// ago, WITHOUT rescanning. This works because matching is a pure function of
// (dependency, DB state):
//
//	sync updates vuln_record
//	  → ChangedVulnsSince() finds what changed
//	  → DepsAffectedByVulns() finds stored deps whose packages are affected
//	  → re-run the matcher on those deps against the (now-updated) local DB
//	  → upsert any newly-matched findings
//
// No source rescan, no re-parse, no registry calls. The candidate set is
// bounded by what changed, not by the full dependency graph.
package continuity

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/matcher"
	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/store"
)

// Result reports what the continuity loop did.
type Result struct {
	ChangedVulns   int // vuln records that changed since the cutoff
	CandidateDeps  int // stored deps potentially affected by those changes
	NewFindings    int // findings newly created by this re-match
	UpdatedFindings int // existing findings whose last_seen was bumped
	Duration       time.Duration
}

// RunSince re-matches stored dependencies against vulns changed since `cutoff`.
// This is the entry point the sync worker calls after each OSV update.
func RunSince(ctx context.Context, pool *pgxpool.Pool, cutoff time.Time) (Result, error) {
	start := time.Now()
	st := store.New(pool)
	res := Result{}

	// 1. What changed?
	changed, err := st.ChangedVulnsSince(ctx, cutoff)
	if err != nil {
		return res, fmt.Errorf("continuity: changed vulns: %w", err)
	}
	res.ChangedVulns = len(changed)
	if len(changed) == 0 {
		res.Duration = time.Since(start)
		return res, nil
	}

	// 2. Which stored deps could be affected? (bounded candidate set)
	candidates, err := st.DepsAffectedByVulns(ctx, changed)
	if err != nil {
		return res, fmt.Errorf("continuity: affected deps: %w", err)
	}
	res.CandidateDeps = len(candidates)
	if len(candidates) == 0 {
		res.Duration = time.Since(start)
		return res, nil
	}

	// 3. Re-match each candidate dep against the (updated) local DB.
	//    Group by project/snapshot so findings persist under the right owner.
	loc := matcher.NewLocal(pool)
	newF, updatedF, err := rematch(ctx, st, loc, candidates)
	if err != nil {
		return res, err
	}
	res.NewFindings = newF
	res.UpdatedFindings = updatedF
	res.Duration = time.Since(start)
	return res, nil
}

// rematch runs the local matcher over the candidate deps and upserts findings,
// tallying new vs updated. Deps are converted to model.Dependency for matching.
func rematch(ctx context.Context, st *store.Store, loc *matcher.LocalMatcher,
	candidates []store.DepRowWithProject) (newF, updatedF int, err error) {

	// Batch by (project, snapshot) so we can attribute findings correctly.
	type key struct{ project, snapshot int64 }
	groups := map[key][]store.DepRowWithProject{}
	for _, c := range candidates {
		k := key{c.ProjectID, c.SnapshotID}
		groups[k] = append(groups[k], c)
	}

	for k, group := range groups {
		deps := make([]model.Dependency, len(group))
		for i, g := range group {
			deps[i] = model.Dependency{
				Name:      g.Name,
				Version:   g.Version,
				Ecosystem: model.Ecosystem(g.Ecosystem),
				IsDirect:  g.IsDirect,
			}
		}
		findings, err := loc.MatchDependencies(ctx, deps)
		if err != nil {
			return newF, updatedF, fmt.Errorf("continuity: rematch project %d: %w", k.project, err)
		}
		// Upsert each finding under its project/snapshot. Enrichment/prioritization
		// would normally run here too; for the continuity path we apply EPSS-less
		// prioritization (priority stays at the CVSS floor) — a future enhancement
		// is to run the full pipeline. The finding lifecycle is preserved either way.
		for _, f := range findings {
			priority := f.Severity // CVSS-derived floor; full prioritizer runs on scan
			row := store.FindingRow{
				ProjectID:          k.project,
				SnapshotID:         k.snapshot,
				DependencyPurl:     purlFor(f.Dependency),
				DependencyName:     f.Dependency.Name,
				DependencyVersion:  f.Dependency.Version,
				DependencyEcosystem: string(f.Dependency.Ecosystem),
				IsDirect:           f.Dependency.IsDirect,
				VulnID:             f.VulnID,
				CVSS:               float32(f.CVSS),
				Priority:           string(priority),
				Actionable:         actionableFor(f),
			}
			created, err := st.UpsertFinding(ctx, row)
			if err != nil {
				// A single bad insert shouldn't abort the whole loop.
				continue
			}
			if created {
				newF++
			} else {
				updatedF++
			}
		}
	}
	return newF, updatedF, nil
}

func purlFor(d model.Dependency) string {
	eco := string(d.Ecosystem)
	switch d.Ecosystem {
	case model.EcosystemPyPI:
		eco = "pypi"
	case model.EcosystemCargo:
		eco = "cargo"
	case model.EcosystemGo:
		eco = "golang"
	}
	return fmt.Sprintf("pkg:%s/%s@%s", eco, d.Name, d.Version)
}

func actionableFor(f model.Finding) string {
	for _, v := range f.FixedVersions {
		if v != "" {
			return string(model.ActionableNow)
		}
	}
	return string(model.ActionableMonitor)
}
