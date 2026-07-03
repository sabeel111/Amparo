package osvclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client is an HTTP client for the OSV.dev API.
// API docs: https://google.github.io/osv.dev/api/
const (
	defaultBaseURL = "https://api.osv.dev"
	batchSize      = 1000 // OSV allows up to 1000 queries per batch request
)

// Client wraps an http.Client with the OSV base URL.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns an OSV client with a sensible timeout.
func New() *Client {
	return &Client{
		BaseURL: defaultBaseURL,
		HTTP:    &http.Client{Timeout: 60 * time.Second},
	}
}

// --- Request/response types matching the OSV schema ---

// QueryRequest is one query: "is THIS version of THIS package vulnerable?"
type QueryRequest struct {
	Package OSVPackage `json:"package"`
	Version string     `json:"version"`
}

// OSVPackage identifies a package by name + ecosystem.
type OSVPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// QueryBatchRequest holds up to 1000 queries.
type QueryBatchRequest struct {
	Queries []QueryRequest `json:"queries"`
}

// QueryBatchResponse mirrors the batch response: one result per query.
type QueryBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Vulnerability is a subset of the full OSV vulnerability schema — the fields we
// need for matching, scoring, and remediation. Unknown fields are ignored.
type Vulnerability struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`  // "CVSS_V3", "CVSS_V2"
		Score string `json:"score"` // vector string
	} `json:"severity"`
	Affected         []Affected                 `json:"affected"`
	DatabaseSpecific map[string]json.RawMessage `json:"database_specific"`
	Published        string                     `json:"published"`
	Modified         string                     `json:"modified"`
	Withdrawn        string                     `json:"withdrawn"`
}

// Affected describes one package's affected version ranges for a vulnerability.
type Affected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
		Purl      string `json:"purl"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"` // "SEMVER", "ECOSYSTEM", "GIT"
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
}

// QueryVersions returns, for each input query, the list of vulnerability IDs
// that match. The returned slice is parallel to the input queries.
func (c *Client) QueryVersions(ctx context.Context, queries []QueryRequest) (QueryBatchResponse, error) {
	if len(queries) == 0 {
		return QueryBatchResponse{}, nil
	}
	if len(queries) > batchSize {
		return QueryBatchResponse{}, fmt.Errorf("osv: batch size %d exceeds max %d", len(queries), batchSize)
	}

	body, err := json.Marshal(QueryBatchRequest{Queries: queries})
	if err != nil {
		return QueryBatchResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return QueryBatchResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return QueryBatchResponse{}, fmt.Errorf("osv: querybatch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return QueryBatchResponse{}, fmt.Errorf("osv: querybatch returned %d: %s", resp.StatusCode, string(b))
	}

	var out QueryBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return QueryBatchResponse{}, fmt.Errorf("osv: decoding response: %w", err)
	}
	return out, nil
}

// GetVuln fetches the full detail for a single vulnerability ID.
func (c *Client) GetVuln(ctx context.Context, id string) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: get vuln %s: %w", id, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv: get vuln %s returned %d: %s", id, resp.StatusCode, string(b))
	}
	var v Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("osv: decoding vuln %s: %w", id, err)
	}
	return &v, nil
}

// GetVulns fetches details for multiple vulnerability IDs with bounded
// concurrency. Returns a map keyed by vuln ID for easy lookup.
func (c *Client) GetVulns(ctx context.Context, ids []string) (map[string]*Vulnerability, error) {
	out := make(map[string]*Vulnerability, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	// Deduplicate IDs first.
	seen := map[string]bool{}
	uniq := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			uniq = append(uniq, id)
		}
	}

	type result struct {
		id  string
		v   *Vulnerability
		err error
	}

	// Bounded concurrency to be a polite API citizen (OSV is a shared service).
	sem := make(chan struct{}, 10)
	results := make(chan result, len(uniq))

	for _, id := range uniq {
		sem <- struct{}{}
		go func(id string) {
			defer func() { <-sem }()
			v, err := c.GetVuln(ctx, id)
			results <- result{id, v, err}
		}(id)
	}

	for i := 0; i < len(uniq); i++ {
		r := <-results
		if r.err != nil {
			// A single failed detail fetch shouldn't fail the whole scan.
			// Log it by storing nil; caller skips missing entries.
			out[r.id] = nil
			continue
		}
		out[r.id] = r.v
	}
	return out, nil
}
