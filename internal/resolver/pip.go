package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sabeel111/Amparo/internal/model"
	pipparser "github.com/sabeel111/Amparo/internal/parser/pip"
)

// pipResolver expands PyPI dependencies via the pypi.org JSON API.
//
// For each package, GET https://pypi.org/pypi/<name>/json returns:
//   info.requires_dist: ["urllib3 (<3,>=1.21.1)", "certifi (>=2017.4.17)", ...]
//   releases: {"1.0": [...], "1.1": [...], ...}  (we use info.version as latest)
//
// Algorithm: BFS from direct deps, picking the highest version satisfying the
// declared range (using the PEP 440 comparator), recursing into requires_dist.
// Optional deps (the "extra == '...'" markers) are skipped — they're not part
// of the default install.
type pipResolver struct {
	baseURL string
	http    *http.Client
}

func init() {
	Register(&pipResolver{
		baseURL: "https://pypi.org/pypi",
		http:    &http.Client{Timeout: 30 * time.Second},
	})
}

func (p *pipResolver) Ecosystem() model.Ecosystem { return model.EcosystemPyPI }

// pypiPackage is the subset of the pypi.org JSON response we need.
type pypiPackage struct {
	Info struct {
		Version      string   `json:"version"`
		RequiresDist []string `json:"requires_dist"`
	} `json:"info"`
}

// Resolve walks the PyPI dependency graph from `direct` and returns the full
// closure. Direct deps that are already pinned (==X.Y.Z) are kept as-is (their
// requires_dist is still walked for transitives). Range/bare deps are resolved
// to the highest satisfying version.
func (p *pipResolver) Resolve(ctx context.Context, direct []model.Dependency) ([]model.Dependency, error) {
	// per-package response cache (a package may appear in multiple chains).
	cache := &sync.Map{}
	fetch := func(name string) (*pypiPackage, error) {
		if v, ok := cache.Load(name); ok {
			if v == nil {
				return nil, fmt.Errorf("cached miss for %s", name)
			}
			return v.(*pypiPackage), nil
		}
		pkg, err := p.fetchPackage(ctx, name)
		if err != nil {
			cache.Store(name, nil) // negative cache to avoid re-fetching
			return nil, err
		}
		cache.Store(name, pkg)
		return pkg, nil
	}

	// Result set keyed by normalized name to dedupe across the graph.
	type resolved struct {
		dep      model.Dependency
		processed bool
	}
	result := map[string]*resolved{}
	var resultMu sync.Mutex

	add := func(d model.Dependency) {
		key := normalizePip(d.Name)
		resultMu.Lock()
		defer resultMu.Unlock()
		if _, exists := result[key]; !exists {
			result[key] = &resolved{dep: d}
		}
	}

	// Seed with direct deps.
	for _, d := range direct {
		add(d)
	}

	// BFS: process each unique package once.
	for {
		// Find an unprocessed entry.
		var next string
		resultMu.Lock()
		for name, r := range result {
			if !r.processed {
				next = name
				r.processed = true
				break
			}
		}
		resultMu.Unlock()
		if next == "" {
			break // all processed
		}

		dep := result[next].dep

		// Determine the version to fetch.
		version := dep.Version
		if !isPinned(dep) {
			// Range/bare — pick highest satisfying. We fetch latest releases.
			v, err := p.pickVersion(ctx, fetch, dep.Name, dep.Version)
			if err != nil {
				continue // can't resolve this one; skip but keep going
			}
			version = v
			// Update the stored dep with the resolved version.
			resultMu.Lock()
			result[next].dep.Version = v
			resultMu.Unlock()
		}

		// Fetch requires_dist for this package@version and enqueue transitives.
		pkg, err := p.fetchPackageVersion(ctx, fetch, dep.Name, version)
		if err != nil || pkg == nil {
			continue
		}
		for _, req := range pkg.Info.RequiresDist {
			name, rangeSpec, optional := parseRequiresDist(req)
			if name == "" || optional {
				continue // skip optional (extra) deps
			}
			tname := normalizePip(name)
			resultMu.Lock()
			if _, exists := result[tname]; !exists {
				result[tname] = &resolved{
					dep: model.Dependency{
						Name: tname, Version: rangeSpec,
						Ecosystem: model.EcosystemPyPI, IsDirect: false,
					},
				}
			}
			resultMu.Unlock()
		}
	}

	// Collect results.
	out := make([]model.Dependency, 0, len(result))
	for _, r := range result {
		out = append(out, r.dep)
	}
	return out, nil
}

// fetchPackage gets the latest version's metadata for a package.
func (p *pipResolver) fetchPackage(ctx context.Context, name string) (*pypiPackage, error) {
	url := fmt.Sprintf("%s/%s/json", p.baseURL, name)
	return p.fetchURL(ctx, url)
}

// fetchPackageVersion gets metadata for a specific version. Uses the
// /pypi/<name>/<version>/json endpoint.
func (p *pipResolver) fetchPackageVersion(ctx context.Context, fetch func(string) (*pypiPackage, error), name, version string) (*pypiPackage, error) {
	// For the latest version, the cached fetch suffices.
	if cached, err := fetch(name); err == nil && cached != nil && cached.Info.Version == version {
		return cached, nil
	}
	url := fmt.Sprintf("%s/%s/%s/json", p.baseURL, name, version)
	return p.fetchURL(ctx, url)
}

func (p *pipResolver) fetchURL(ctx context.Context, url string) (*pypiPackage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// pypi.org recommends a User-Agent identifying the client.
	req.Header.Set("User-Agent", "Amparo-SCA/0.5 (supply chain vulnerability tracker)")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pypi: fetching %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("pypi: package not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pypi: %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var pkg pypiPackage
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, fmt.Errorf("pypi: decoding: %w", err)
	}
	return &pkg, nil
}

// pickVersion resolves a range/bare spec to the highest available version.
// For simplicity and because OSV matches against concrete versions, we fetch the
// release list and pick the highest version satisfying the spec. A bare name
// (no spec) resolves to the latest version.
func (p *pipResolver) pickVersion(ctx context.Context, fetch func(string) (*pypiPackage, error), name, spec string) (string, error) {
	// Fetch the releases listing via the JSON API.
	url := fmt.Sprintf("%s/%s/json", p.baseURL, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Amparo-SCA/0.5")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("pypi: %d for %s", resp.StatusCode, name)
	}
	var listing struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
		Releases map[string][]any `json:"releases"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listing); err != nil {
		return "", err
	}

	// Collect all release versions.
	var versions []string
	for v := range listing.Releases {
		versions = append(versions, v)
	}
	if listing.Info.Version != "" {
		versions = append(versions, listing.Info.Version)
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("pypi: no releases for %s", name)
	}

	// PEP 440 pre-release handling: by default, EXCLUDE pre-releases (a/b/rc/dev)
	// unless the spec explicitly references one. We prefer stable releases so we
	// don't resolve e.g. django@6.1b1 (a beta) when stable 5.x exists.
	specHasPreRelease := specReferencesPreRelease(spec)

	// If spec is empty (bare name) or a range, pick the highest satisfying.
	if spec == "" {
		// latest stable = highest non-pre-release version.
		best := ""
		for _, v := range versions {
			if !specHasPreRelease && isPreRelease(v) {
				continue
			}
			if best == "" || pipparser.ComparePipVersions(v, best) > 0 {
				best = v
			}
		}
		// Fallback: if excluding pre-releases left nothing, allow them.
		if best == "" {
			for _, v := range versions {
				if best == "" || pipparser.ComparePipVersions(v, best) > 0 {
					best = v
				}
			}
		}
		return best, nil
	}

	// Range spec: parse constraints, pick highest STABLE version satisfying all.
	constraints := parseRangeSpec(spec)
	best := ""
	for _, v := range versions {
		if !specHasPreRelease && isPreRelease(v) {
			continue
		}
		if satisfiesAll(v, constraints) {
			if best == "" || pipparser.ComparePipVersions(v, best) > 0 {
				best = v
			}
		}
	}
	if best == "" {
		// No stable version satisfies — retry including pre-releases.
		for _, v := range versions {
			if satisfiesAll(v, constraints) {
				if best == "" || pipparser.ComparePipVersions(v, best) > 0 {
					best = v
				}
			}
		}
	}
	if best == "" {
		// Truly nothing satisfies — fall back to latest as degraded result rather
		// than dropping the dep entirely (better to match than to be invisible).
		best = listing.Info.Version
	}
	return best, nil
}

// isPreRelease reports whether a version string is a PEP 440 pre-release
// (contains a/b/rc/dev markers after the release segment).
// e.g. "6.1b1", "1.0.0rc2", "2.0a3.dev1" → true; "4.2.0", "1.0.1" → false.
func isPreRelease(v string) bool {
	v = strings.ToLower(v)
	// Strip epoch and local-version segments that don't affect pre-release status.
	if i := strings.Index(v, "+"); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexAny(v, "-"); i >= 0 {
		// Could be a pre-release separator; check the tail.
		tail := v[i+1:]
		if isPreReleaseTail(tail) {
			return true
		}
	}
	// Also check inline (no dash): "1.0a1", "2.0rc2".
	return strings.ContainsAny(v, "abc") && hasPreReleaseMarker(v)
}

// isPreReleaseTail checks if a tail like "alpha1", "b2", "rc1", "dev0" is a pre-release.
func isPreReleaseTail(tail string) bool {
	tail = strings.ToLower(tail)
	for _, p := range []string{"a", "b", "c", "alpha", "beta", "rc", "pre", "preview", "dev"} {
		if strings.HasPrefix(tail, p) {
			return true
		}
	}
	return false
}

// hasPreReleaseMarker detects inline pre-release markers like "1.0a1", "2.0rc2".
func hasPreReleaseMarker(v string) bool {
	for _, marker := range []string{"a", "b", "rc", "alpha", "beta", "dev"} {
		if idx := strings.Index(v, marker); idx > 0 {
			// Must be followed by a digit to be a real pre-release (e.g. "1.0a1").
			rest := v[idx+len(marker):]
			if len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
				return true
			}
		}
	}
	return false
}

// specReferencesPreRelease reports whether the version spec explicitly mentions
// a pre-release version (e.g. ">=6.1b1"). If so, pre-releases are allowed.
func specReferencesPreRelease(spec string) bool {
	constraints := parseRangeSpec(spec)
	for _, c := range constraints {
		if isPreRelease(c.version) {
			return true
		}
	}
	return false
}

// constraint is a single version comparison (op + version).
type constraint struct {
	op      string // ">=", "<=", "==", "!=", ">", "<", "~="
	version string
}

// parseRangeSpec parses ">=1.0,<2.0" into [{"=", ">="}, ...].
func parseRangeSpec(spec string) []constraint {
	var out []constraint
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		for _, op := range []string{">=", "<=", "==", "!=", "~=", ">", "<"} {
			if strings.HasPrefix(part, op) {
				out = append(out, constraint{op: op, version: strings.TrimSpace(part[len(op):])})
				break
			}
		}
	}
	return out
}

// satisfiesAll reports whether version satisfies every constraint.
func satisfiesAll(version string, constraints []constraint) bool {
	cmp := pipparser.ComparePipVersions
	for _, c := range constraints {
		r := cmp(version, c.version)
		ok := false
		switch c.op {
		case ">=":
			ok = r >= 0
		case "<=":
			ok = r <= 0
		case "==":
			// approximate match: 1.2 == 1.2.0 under PEP 440 padding
			ok = r == 0
		case "!=":
			ok = r != 0
		case ">":
			ok = r > 0
		case "<":
			ok = r < 0
		case "~=":
			// compatible release: ~=1.2 means >=1.2,<2.0; ~=1.2.3 means >=1.2.3,<1.3
			// approximate via >= on the version and < on the next minor/major.
			ok = r >= 0 && compatibleRelease(version, c.version)
		}
		if !ok {
			return false
		}
	}
	return true
}

// compatibleRelease approximates PEP 440 ~= by checking the major.minor prefix.
func compatibleRelease(version, spec string) bool {
	// ~=1.2.3 → version must be in [1.2.3, 1.3.0)
	specParts := strings.Split(spec, ".")
	if len(specParts) < 2 {
		return true
	}
	verParts := strings.Split(version, ".")
	if len(verParts) < 2 || len(specParts) < 3 {
		// ~=1.2 → <2.0; compare first component only
		return sameMajorPrefix(verParts, specParts, 1)
	}
	// ~=1.2.3 → <1.3.0; compare first two components
	return sameMajorPrefix(verParts, specParts, 2)
}

func sameMajorPrefix(ver, spec []string, n int) bool {
	for i := 0; i < n && i < len(ver) && i < len(spec); i++ {
		if strings.TrimSpace(ver[i]) != strings.TrimSpace(spec[i]) {
			return false
		}
	}
	return true
}

// parseRequiresDist parses a PyPI requires_dist string into (name, rangeSpec, optional).
// PyPI's requires_dist format is INCONSISTENT across versions/releases:
//   - Parenthesized form: "urllib3 (<3,>=1.21.1)" — older common form
//   - Bare form: "urllib3<3,>=1.26" — newer form, no parens, no space
//   - Bare name: "chardet" — no spec
//   - With extras: "PySocks (!=1.5.7,>=1.5.6) ; extra == 'socks'"
//
// Returns the normalized name, the version spec (without parens), and whether
// it's an optional (extra) dependency that should be skipped by default.
func parseRequiresDist(req string) (name, spec string, optional bool) {
	// Split off environment markers ("; extra == '...'").
	if i := strings.Index(req, ";"); i >= 0 {
		marker := strings.TrimSpace(req[i+1:])
		req = strings.TrimSpace(req[:i])
		if strings.Contains(marker, "extra") {
			optional = true
		}
	}
	req = strings.TrimSpace(req)

	// Parenthesized form: "name (spec)"
	if lp := strings.Index(req, "("); lp >= 0 {
		name = strings.TrimSpace(req[:lp])
		if rp := strings.LastIndex(req, ")"); rp > lp {
			spec = strings.TrimSpace(req[lp+1 : rp])
		}
		return name, spec, optional
	}

	// Bare form: "name<spec>" or "name==spec" or just "name".
	// Find where the name ends (first operator char).
	end := len(req)
	for i, c := range req {
		if c == '=' || c == '!' || c == '<' || c == '>' || c == '~' {
			end = i
			break
		}
	}
	name = strings.TrimSpace(req[:end])
	spec = strings.TrimSpace(req[end:])
	return name, spec, optional
}

func normalizePip(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}
