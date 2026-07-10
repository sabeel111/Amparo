// Package scan contains the reusable scan pipeline used by both the CLI
// (amparo scan) and the GitHub webhook receiver (amparo serve).
//
// Extracting the pipeline here means the webhook handler can trigger the exact
// same discover → parse → resolve → match → dedupe → EPSS → prioritize →
// remediate → persist flow that the CLI runs, without duplicating logic.
package scan

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/epss"
	"github.com/sabeel111/Amparo/internal/matcher"
	"github.com/sabeel111/Amparo/internal/model"
	"github.com/sabeel111/Amparo/internal/osvclient"
	"github.com/sabeel111/Amparo/internal/parser"
	pipparser "github.com/sabeel111/Amparo/internal/parser/pip"
	"github.com/sabeel111/Amparo/internal/prioritize"
	"github.com/sabeel111/Amparo/internal/remediate"
	"github.com/sabeel111/Amparo/internal/report"
	"github.com/sabeel111/Amparo/internal/resolver"
	"github.com/sabeel111/Amparo/internal/store"
)

// Options configures a scan.
type Options struct {
	Path        string // directory or lockfile path to scan
	ProjectName string // project name for persistence (defaults to path basename)
	SHA         string // git commit SHA (for webhook-sourced scans; "" if unknown)
	MatchMode   string // "auto" | "local" | "live"
	NoEPSS      bool
	Persist     bool
	Strict      bool // fail when any supported discovered lockfile cannot be read or parsed
	Timeout     time.Duration
	Log         io.Writer // progress logs (stderr for CLI, captured for webhooks)
}

// Result is the outcome of a scan.
type Result struct {
	Report      report.Report
	SnapshotID  int64 // 0 if not persisted
	ProjectID   int64
	FindingsNew int // findings newly created by this scan
}

// Run executes the full scan pipeline and returns the result.
// This is the single entry point shared by the CLI and the webhook receiver.
func Run(ctx context.Context, pool *pgxpool.Pool, opts Options) (*Result, error) {
	log := opts.Log
	if log == nil {
		log = io.Discard
	}

	// Ensure the PEP 440 comparator is registered for pip matching.
	osvclient.SetPipComparator(pipparser.ComparePipVersions)

	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// 1. Discover + parse lockfiles.
	files, err := discoverLockfiles(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("discovering lockfiles: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no supported lockfiles found at %s", opts.Path)
	}
	registry := parser.NewRegistry()
	var deps []model.Dependency
	coverage := report.Coverage{Complete: true, Discovered: len(files)}
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			warning := fmt.Sprintf("could not read %s: %v", f, err)
			fmt.Fprintf(log, "warn: %s\n", warning)
			coverage.Complete = false
			coverage.Failed++
			coverage.Warnings = append(coverage.Warnings, warning)
			continue
		}
		parsed, err := registry.ParseFile(f, content)
		if err != nil {
			warning := fmt.Sprintf("could not parse %s: %v", f, err)
			fmt.Fprintf(log, "warn: %s\n", warning)
			coverage.Complete = false
			coverage.Failed++
			coverage.Warnings = append(coverage.Warnings, warning)
			continue
		}
		coverage.Parsed++
		deps = append(deps, parsed...)
	}
	if opts.Strict && !coverage.Complete {
		return nil, fmt.Errorf("scan coverage incomplete: %d of %d supported lockfile(s) failed to parse", coverage.Failed, coverage.Discovered)
	}
	if len(deps) == 0 {
		return nil, fmt.Errorf("no dependencies parsed from lockfiles")
	}
	deps = dedupe(deps)
	fmt.Fprintf(log, "amparo: parsed %d dependencies from %d lockfile(s)\n", len(deps), len(files))

	// 1b. Resolve transitive deps for lockfile-less projects.
	if resolver.NeedsResolution(deps) {
		deps = resolveTransitive(ctx, log, deps)
	}

	// 2. Match.
	var findings []model.Finding
	mode := opts.MatchMode
	if mode == "" || mode == "auto" {
		mode = pickMatchMode(ctx, pool)
	}
	switch mode {
	case "local":
		if pool == nil {
			return nil, fmt.Errorf("local DB required but not available")
		}
		fmt.Fprintf(log, "amparo: matching against local OSV DB...\n")
		findings, err = matcher.NewLocal(pool).MatchDependencies(ctx, deps)
		if err != nil {
			return nil, fmt.Errorf("local match: %w", err)
		}
	default:
		fmt.Fprintf(log, "amparo: querying OSV API...\n")
		findings, err = osvclient.New().MatchDependencies(ctx, deps)
		if err != nil {
			return nil, fmt.Errorf("OSV query: %w", err)
		}
	}

	// 3-5. Enrich: dedup → EPSS → prioritize → remediate.
	// (Shared with continuity — both paths now produce identical findings.)
	if opts.NoEPSS && len(findings) > 0 {
		// EPSS skipped via flag: still dedup + prioritize + remediate, just no EPSS.
		findings = matcher.DedupeFindings(findings)
		findings = prioritize.Enrich(findings)
		for i := range findings {
			findings[i].Remediation = remediate.For(findings[i])
		}
	} else {
		findings = EnrichFindings(ctx, log, findings)
	}

	rep := report.Build(findings, len(deps))
	rep.Coverage = coverage
	result := &Result{Report: rep}

	// 6. Persist.
	if opts.Persist && pool != nil {
		st := store.New(pool)
		projectName := opts.ProjectName
		if projectName == "" {
			projectName = filepath.Base(opts.Path)
		}
		pid, snapID, newF, err := persistScan(ctx, st, projectName, opts.SHA, deps, findings)
		if err != nil {
			fmt.Fprintf(log, "warn: persist failed: %v\n", err)
		} else {
			result.ProjectID = pid
			result.SnapshotID = snapID
			result.FindingsNew = newF
			fmt.Fprintf(log, "amparo: persisted snapshot + %d findings (%d new)\n", len(findings), newF)
			// Auto-close findings resolved by this scan (a version bump that
			// fixed a vuln should mark it 'fixed').
			if closed, err := st.CloseSnapshotFindings(ctx, pid, snapID); err == nil && closed > 0 {
				fmt.Fprintf(log, "amparo: auto-closed %d resolved finding(s)\n", closed)
			}
		}
	}

	return result, nil
}

// --- helpers (lifted from cmd/amparo, now shared) ---

func discoverLockfiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("accessing %s: %w", path, err)
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	supported := map[string]bool{
		"package-lock.json": true,
		"pipfile.lock":      true,
		"poetry.lock":       true,
		"requirements.txt":  true,
		"go.sum":            true,
		"go.mod":            true,
		"cargo.lock":        true,
	}
	var found []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == "vendor" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if supported[strings.ToLower(d.Name())] {
			found = append(found, p)
		}
		return nil
	})
	return found, err
}

func dedupe(deps []model.Dependency) []model.Dependency {
	seen := map[string]bool{}
	out := deps[:0]
	for _, d := range deps {
		key := string(d.Ecosystem) + "|" + d.Name + "@" + d.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

func pickMatchMode(ctx context.Context, pool *pgxpool.Pool) string {
	if pool == nil {
		return "live"
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM vuln_record`).Scan(&n); err != nil || n == 0 {
		return "live"
	}
	return "local"
}

func resolveTransitive(ctx context.Context, log io.Writer, deps []model.Dependency) []model.Dependency {
	needsResolve := map[model.Ecosystem][]model.Dependency{}
	for _, d := range deps {
		if !resolver.IsPinnedExported(d) {
			if r := resolver.For(d.Ecosystem); r != nil {
				needsResolve[d.Ecosystem] = append(needsResolve[d.Ecosystem], d)
			}
		}
	}
	if len(needsResolve) == 0 {
		return deps
	}
	resolvedKeys := map[string]bool{}
	var resolvedAll []model.Dependency
	for eco, direct := range needsResolve {
		out, err := resolver.For(eco).Resolve(ctx, direct)
		if err != nil {
			fmt.Fprintf(log, "warn: %s resolution failed (%v); scanning direct deps only\n", eco, err)
			for _, d := range direct {
				resolvedAll = append(resolvedAll, d)
				resolvedKeys[string(d.Ecosystem)+"|"+d.Name] = true
			}
			continue
		}
		transitive := 0
		for _, d := range out {
			if !d.IsDirect {
				transitive++
			}
			resolvedKeys[string(d.Ecosystem)+"|"+d.Name] = true
		}
		fmt.Fprintf(log, "amparo: resolved %d transitive %s dependencies (%d total)\n",
			transitive, eco, len(out))
		resolvedAll = append(resolvedAll, out...)
	}
	seen := map[string]bool{}
	out := []model.Dependency{}
	for _, d := range resolvedAll {
		k := string(d.Ecosystem) + "|" + d.Name + "@" + d.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, d)
	}
	for _, d := range deps {
		if resolver.IsPinnedExported(d) && !resolvedKeys[string(d.Ecosystem)+"|"+d.Name] {
			k := string(d.Ecosystem) + "|" + d.Name + "@" + d.Version
			if !seen[k] {
				seen[k] = true
				out = append(out, d)
			}
		}
	}
	return out
}

func enrichEPSS(ctx context.Context, log io.Writer, findings []model.Finding) {
	var cves []string
	for _, f := range findings {
		cves = append(cves, f.VulnID)
		cves = append(cves, f.Aliases...)
	}
	scores, err := epss.New().FetchScores(ctx, cves)
	if err != nil {
		fmt.Fprintf(log, "warn: EPSS enrichment failed (%v); continuing without exploit-probability signal\n", err)
		return
	}
	epss.Enrich(findings, scores)
}

func persistScan(ctx context.Context, st *store.Store, projectName, sha string, deps []model.Dependency, findings []model.Finding) (projectID, snapID int64, newFindings int, err error) {
	projectID, err = st.EnsureProject(ctx, "default", projectName)
	if err != nil {
		return 0, 0, 0, err
	}
	manifestHash := hashDeps(deps)
	snapID, err = st.CreateSnapshot(ctx, projectID, sha, manifestHash)
	if err != nil {
		return 0, 0, 0, err
	}
	depRows := make([]store.DepRow, len(deps))
	for i, d := range deps {
		depRows[i] = store.DepRow{
			Purl: purlFor(d), Name: d.Name, Version: d.Version,
			Ecosystem: string(d.Ecosystem), IsDirect: d.IsDirect,
		}
	}
	if err := st.InsertDependencies(ctx, snapID, depRows); err != nil {
		return 0, 0, 0, err
	}
	for _, f := range findings {
		row := store.FindingRow{
			ProjectID: projectID, SnapshotID: snapID,
			DependencyPurl:      purlFor(f.Dependency),
			DependencyName:      f.Dependency.Name,
			DependencyVersion:   f.Dependency.Version,
			DependencyEcosystem: string(f.Dependency.Ecosystem),
			IsDirect:            f.Dependency.IsDirect,
			VulnID:              f.VulnID, CVSS: float32(f.CVSS),
			EPSSProbability: float32(f.EPSSProbability), EPSSPercentile: float32(f.EPSSPercentile),
			Priority: string(f.Priority), Actionable: string(f.Actionable),
		}
		created, err := st.UpsertFinding(ctx, row)
		if err != nil {
			continue
		}
		if created {
			newFindings++
		}
	}
	return projectID, snapID, newFindings, nil
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

func hashDeps(deps []model.Dependency) string {
	// Simple deterministic hash of the dependency set for snapshot identity.
	h := 0
	for _, d := range deps {
		h = h*31 + hashString(string(d.Ecosystem)+"|"+d.Name+"|"+d.Version)
	}
	return fmt.Sprintf("%x", h)
}

func hashString(s string) int {
	h := 0
	for _, c := range s {
		h = h*31 + int(c)
	}
	return h
}
