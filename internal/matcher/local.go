package matcher

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/osvclient"
	"github.com/sabeel111/Amparo/internal/store"
)

// LocalMatcher matches dependencies against vuln records stored in Postgres
// (populated by the osvsync worker). This is the "continuity" path: matching
// runs against the local DB, so a newly-synced CVE alerts on existing snapshots
// without any rescan.
type LocalMatcher struct {
	store *store.Store
}

// NewLocal returns a matcher backed by the given store.
func NewLocal(pool *pgxpool.Pool) *LocalMatcher {
	return &LocalMatcher{store: store.New(pool)}
}

// MatchDependencies evaluates deps against the local vuln DB.
func (m *LocalMatcher) MatchDependencies(ctx context.Context, deps []model.Dependency) ([]model.Finding, error) {
	if len(deps) == 0 {
		return nil, nil
	}

	// Group dependencies by ecosystem+package to batch the DB lookups.
	type key struct{ eco, name string }
	candidates := map[key][]model.Dependency{}
	for _, d := range deps {
		k := key{eco: localEcosystem(d.Ecosystem), name: d.Name}
		candidates[k] = append(candidates[k], d)
	}

	type result struct {
		findings []model.Finding
		err      error
	}
	results := make(chan result, len(candidates))
	var wg sync.WaitGroup

	// Bounded concurrency: query each (ecosystem, package) once, then match all
	// versions of that package against the returned records.
	sem := make(chan struct{}, 8)
	for k, pkgDeps := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(k key, pkgDeps []model.Dependency) {
			defer wg.Done()
			defer func() { <-sem }()
			rows, err := m.store.FindVulnsByPackage(ctx, k.eco, k.name)
			if err != nil {
				results <- result{err: err}
				return
			}
			records := make([]Record, 0, len(rows))
			for _, row := range rows {
				rec, err := rowToRecord(row)
				if err != nil {
					continue // skip undecodable records
				}
				records = append(records, rec)
			}
			var findings []model.Finding
			for _, d := range pkgDeps {
				findings = append(findings, FindingsForDependency(d, records)...)
			}
			results <- result{findings: findings}
		}(k, pkgDeps)
	}

	go func() { wg.Wait(); close(results) }()

	var all []model.Finding
	for r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("local match: %w", r.err)
		}
		all = append(all, r.findings...)
	}
	return all, nil
}

// localEcosystem maps our model.Ecosystem to the bucket-name stored in
// vuln_record.ecosystem by the sync worker. The sync stores the OSV bucket name
// ("crates.io", "PyPI", "Go"), so cargo deps must look up "crates.io".
func localEcosystem(eco model.Ecosystem) string {
	switch eco {
	case model.EcosystemCargo:
		return "crates.io"
	case model.EcosystemPyPI:
		return "PyPI"
	case model.EcosystemGo:
		return "Go"
	case model.EcosystemMaven:
		return "Maven"
	}
	return string(eco)
}

// rowToRecord converts a stored VulnRow (with raw JSON affected) into a neutral
// matcher Record, decoding the OSV affected[] structure.
func rowToRecord(row store.VulnRow) (Record, error) {
	var affected []osvclient.Affected
	if err := json.Unmarshal(row.Affected, &affected); err != nil {
		return Record{}, err
	}
	rec := Record{
		ID:            row.OSVID,
		Aliases:       row.Aliases,
		Summary:       row.Summary,
		CVSSVectors:   row.CVSSVectors,
		FixedVersions: row.FixedVersions,
	}
	for _, aff := range affected {
		r := AffectedPackage{Name: aff.Package.Name, Ecosystem: aff.Package.Ecosystem}
		for _, rng := range aff.Ranges {
			rr := Range{Type: rng.Type}
			for _, ev := range rng.Events {
				rr.Events = append(rr.Events, RangeEvent{
					Introduced: ev.Introduced, Fixed: ev.Fixed, LastAffected: ev.LastAffected,
				})
			}
			r.Ranges = append(r.Ranges, rr)
		}
		rec.Affected = append(rec.Affected, r)
	}
	return rec, nil
}
