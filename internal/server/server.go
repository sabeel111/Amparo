// Package server exposes the Amparo engine over a JSON HTTP API for the
// dashboard (and future integrations). It's a thin layer over internal/store —
// no business logic here, just request/response handling and JSON shaping.
//
// Endpoints (all under /api/v1):
//
//	GET    /healthz                          liveness
//	GET    /projects                         list projects + finding counts
//	GET    /projects/{name}                  project detail + summary
//	GET    /projects/{name}/findings         findings list (filters)
//	GET    /findings/{id}                    single finding detail
//	PATCH  /findings/{id}                    triage/dismiss {status, reason}
//	GET    /summary                          global severity counts
//
// No auth yet (FLAW 7, deferred) — local dev only. CORS is enabled for the
// Next.js dev origin so the dashboard on :3000 can call :8080 directly.
package server

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/sabeel111/Amparo/internal/store"
)

// Server wraps a connection pool with the HTTP machinery.
type Server struct {
	pool *pgxpool.Pool
	store *store.Store
	mux  *http.ServeMux
}

// New creates a Server. The pool must already have migrations applied.
func New(pool *pgxpool.Pool) *Server {
	s := &Server{pool: pool, store: store.New(pool), mux: http.NewServeMux()}
	s.routes()
	return s
}

// routes wires the handler functions to URL patterns.
func (s *Server) routes() {
	mux := s.mux
	mux.HandleFunc("/api/v1/healthz", s.handleHealth)
	mux.HandleFunc("/api/v1/projects", s.handleProjects)
	mux.HandleFunc("/api/v1/projects/", s.handleProjectByName) // /projects/{name}[/findings]
	mux.HandleFunc("/api/v1/findings/", s.handleFindingByID)   // /findings/{id}
	mux.HandleFunc("/api/v1/summary", s.handleSummary)
	mux.HandleFunc("/api/v1/webhooks/github", s.handleGitHubWebhook) // GitHub push/PR intake
}

// Handler returns the CORS-wrapped mux suitable for http.ServeMux.
func (s *Server) Handler() http.Handler {
	return s.withCORS(s.logging(s.mux))
}

// ListenAndServe starts the HTTP server on addr (e.g. ":8080").
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("amparo serve: API on http://localhost%s/api/v1", addr)
	return srv.ListenAndServe()
}

// --- middleware ---

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Permissive CORS for local dev (dashboard on :3000 calling :8080).
		// Tighten before any real deployment — FLAW 7 (auth) covers this.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

// --- response helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// --- handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.pool.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleProjects — GET /projects
func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	projects, err := s.store.ListProjects(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Shape into a clean DTO with consistent JSON field names.
	out := make([]map[string]any, 0, len(projects))
	for _, p := range projects {
		out = append(out, map[string]any{
			"id":              p.ID,
			"org":             p.OrgName,
			"name":            p.Name,
			"total_findings":  p.TotalFindings,
			"open_findings":   p.OpenFindings,
			"critical":        p.CriticalCount,
			"high":            p.HighCount,
			"medium":          p.MediumCount,
			"low":             p.LowCount,
			"last_scanned":    p.LastScanned,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out})
}

// handleProjectByName routes /projects/{name} and /projects/{name}/findings.
func (s *Server) handleProjectByName(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/projects/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		writeError(w, http.StatusBadRequest, "project name required")
		return
	}
	parts := strings.SplitN(path, "/", 2)
	projectName := parts[0]

	projectID, err := s.store.EnsureProject(r.Context(), "default", projectName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if len(parts) == 2 && parts[1] == "findings" {
		s.handleFindings(w, r, projectID, projectName)
		return
	}
	if len(parts) == 1 {
		s.handleProjectDetail(w, r, projectID, projectName)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}

func (s *Server) handleProjectDetail(w http.ResponseWriter, r *http.Request, projectID int64, name string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	ps, err := s.store.ProjectSummary(r.Context(), projectID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":         projectID,
		"name":       name,
		"summary": map[string]any{
			"total":      ps.Total,
			"critical":   ps.Critical,
			"high":       ps.High,
			"medium":     ps.Medium,
			"low":        ps.Low,
			"open":       ps.Open,
			"fixed":      ps.Fixed,
			"direct":     ps.Direct,
			"transitive": ps.Transitive,
			"exploited":  ps.Exploited,
		},
	})
}

// handleFindings — GET /projects/{name}/findings?status=&severity=&ecosystem=&epss=&q=
func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request, projectID int64, name string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	q := r.URL.Query()
	filters := store.FindingFilters{
		Status:    q.Get("status"),
		Severity:  q.Get("severity"),
		Ecosystem: q.Get("ecosystem"),
		OnlyEPSS:  q.Get("epss") == "1" || q.Get("epss") == "true",
		Query:     q.Get("q"),
	}
	if l := q.Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil {
			filters.Limit = n
		}
	}
	findings, err := s.store.FindingsByProjectDetailed(r.Context(), projectID, filters)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		out = append(out, findingToDTO(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"project":  name,
		"findings": out,
		"count":    len(out),
	})
}

// handleFindingByID — GET /findings/{id} and PATCH /findings/{id}
func (s *Server) handleFindingByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
	path = strings.TrimSuffix(path, "/")
	idStr := path
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "finding id must be numeric")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleFindingGet(w, r, id)
	case http.MethodPatch:
		s.handleFindingPatch(w, r, id)
	default:
		writeError(w, http.StatusMethodNotAllowed, "GET or PATCH")
	}
}

func (s *Server) handleFindingGet(w http.ResponseWriter, r *http.Request, id int64) {
	// Fetch via the detailed path: we need project_id to scope the query.
	// Simplest: query the finding row directly, then the vuln join.
	// Reuse FindingsByProjectDetailed by first resolving project from finding id.
	var projectID int64
	err := s.pool.QueryRow(r.Context(),
		`SELECT project_id FROM finding WHERE id=$1`, id).Scan(&projectID)
	if err != nil {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}
	findings, err := s.store.FindingsByProjectDetailed(r.Context(), projectID, store.FindingFilters{Limit: 1000})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	for _, f := range findings {
		if f.ID == id {
			writeJSON(w, http.StatusOK, findingToDTO(f))
			return
		}
	}
	writeError(w, http.StatusNotFound, "finding not found")
}

func (s *Server) handleFindingPatch(w http.ResponseWriter, r *http.Request, id int64) {
	var body struct {
		Status string `json:"status"`
		Reason string `json:"reason"` // accepted but not yet stored separately
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	valid := map[string]bool{"new": true, "triaged": true, "fixed": true, "suppressed": true}
	if !valid[body.Status] {
		writeError(w, http.StatusBadRequest, "status must be one of: new, triaged, fixed, suppressed")
		return
	}
	if err := s.store.UpdateFindingStatus(r.Context(), id, body.Status); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": body.Status})
}

// handleSummary — GET /summary (global across all projects)
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "GET only")
		return
	}
	var ps store.ProjectSummaryRow
	err := s.pool.QueryRow(r.Context(), `
		SELECT
		  COUNT(*),
		  COUNT(*) FILTER (WHERE priority='critical'),
		  COUNT(*) FILTER (WHERE priority='high'),
		  COUNT(*) FILTER (WHERE priority='medium'),
		  COUNT(*) FILTER (WHERE priority='low'),
		  COUNT(*) FILTER (WHERE status IN ('new','triaged')),
		  COUNT(*) FILTER (WHERE status='fixed'),
		  COUNT(*) FILTER (WHERE is_direct AND status IN ('new','triaged')),
		  COUNT(*) FILTER (WHERE NOT is_direct AND status IN ('new','triaged')),
		  COUNT(*) FILTER (WHERE epss_percentile >= 0.95 AND status IN ('new','triaged'))
		FROM finding`).Scan(
		&ps.Total, &ps.Critical, &ps.High, &ps.Medium, &ps.Low,
		&ps.Open, &ps.Fixed, &ps.Direct, &ps.Transitive, &ps.Exploited)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Count projects too.
	var projectCount int
	s.pool.QueryRow(r.Context(), `SELECT count(*) FROM project`).Scan(&projectCount)
	writeJSON(w, http.StatusOK, map[string]any{
		"projects":   projectCount,
		"total":      ps.Total,
		"critical":   ps.Critical,
		"high":       ps.High,
		"medium":     ps.Medium,
		"low":        ps.Low,
		"open":       ps.Open,
		"fixed":      ps.Fixed,
		"direct":     ps.Direct,
		"transitive": ps.Transitive,
		"exploited":  ps.Exploited,
	})
}

// findingToDTO converts a DetailedFinding into the JSON shape the dashboard
// consumes. Field names are snake_case and stable — this is the API contract.
func findingToDTO(f store.DetailedFinding) map[string]any {
	return map[string]any{
		"id":              f.ID,
		"package":         f.DependencyName,
		"version":         f.DependencyVersion,
		"ecosystem":       normalizeEcosystemOut(f.DependencyEcosystem),
		"purl":            f.DependencyPurl,
		"is_direct":       f.IsDirect,
		"vuln_id":         f.VulnID,
		"summary":         f.Summary,
		"aliases":         f.Aliases,
		"cvss":            f.CVSS,
		"epss_probability": f.EPSSProbability,
		"epss_percentile":  f.EPSSPercentile,
		"priority":        f.Priority,
		"actionable":      f.Actionable,
		"status":          f.Status,
		"fixed_versions":  f.FixedVersions,
		"first_seen":      f.FirstSeen,
		"last_seen":       f.LastSeen,
	}
}

// normalizeEcosystemOut maps DB spellings to the UI-friendly lowercase forms
// the dashboard expects (npm, pypi, go, cargo).
func normalizeEcosystemOut(s string) string {
	switch s {
	case "PyPI":
		return "pypi"
	case "Go":
		return "go"
	}
	return strings.ToLower(s)
}
