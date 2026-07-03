// Package epss enriches findings with EPSS (Exploit Prediction Scoring System)
// data from FIRST.org.
//
// EPSS gives the probability that a CVE will be exploited in the wild within 30
// days, plus a percentile rank. This is a far better prioritization signal than
// CVSS alone — a "critical" CVE with EPSS 0.01% is usually noise, while a
// "medium" CVE with EPSS 99% is urgent.
//
// The EPSS API (https://api.first.org/data/v1/epss) accepts up to 200 CVEs per
// request. We collect CVE IDs from finding aliases, query in chunks, and attach
// the values. EPSS failure is NON-FATAL: the product still works, prioritization
// just loses the exploit-probability signal (graceful degradation).
package epss

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sabeel111/Amparo/internal/model"
)

const (
	apiURL      = "https://api.first.org/data/v1/epss"
	batchLimit  = 100  // keep URL length safe; API allows 200 but long URLs get rejected
	maxURLBytes = 7000 // conservative cap on query string length
)

// Score holds the EPSS values for one CVE.
type Score struct {
	Probability float64 // 0..1
	Percentile  float64 // 0..1
}

// Client fetches EPSS data. Has its own http.Client so failures are isolated.
type Client struct {
	HTTP *http.Client
}

// New returns an EPSS client.
func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type apiResponse struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
	} `json:"data"`
}

// FetchScores returns EPSS scores keyed by CVE ID (uppercase).
func (c *Client) FetchScores(ctx context.Context, cves []string) (map[string]Score, error) {
	out := map[string]Score{}
	if len(cves) == 0 {
		return out, nil
	}
	// Dedupe + uppercase + filter to CVE-shaped IDs only. EPSS only tracks CVEs,
	// so querying GHSA-/PYSEC-/BIT- IDs wastes URL budget and risks hitting URL
	// length limits (the API silently returns empty when the URL is too long).
	seen := map[string]bool{}
	uniq := make([]string, 0, len(cves))
	for _, c := range cves {
		cu := strings.ToUpper(strings.TrimSpace(c))
		if cu == "" || seen[cu] || !strings.HasPrefix(cu, "CVE-") {
			continue
		}
		seen[cu] = true
		uniq = append(uniq, cu)
	}

	// Chunk by both count and accumulated URL length to stay under safe limits.
	for start := 0; start < len(uniq); {
		batch, next := takeBatch(uniq, start)
		if err := c.fetchBatch(ctx, batch, out); err != nil {
			return out, err // partial results still returned
		}
		start = next
	}
	return out, nil
}

// takeBatch returns a slice from uniq[start:] bounded by batchLimit entries and
// maxURLBytes of query-string length, plus the index of the next start.
func takeBatch(uniq []string, start int) ([]string, int) {
	end := start
	acc := len(apiURL) + len("?cve=")
	for end < len(uniq) && end-start < batchLimit {
		add := len(uniq[end]) + 1 // +1 for comma
		if acc+add > maxURLBytes {
			break
		}
		acc += add
		end++
	}
	if end == start {
		end = start + 1 // always make progress (single long ID still queried)
	}
	return uniq[start:end], end
}

func (c *Client) fetchBatch(ctx context.Context, cves []string, out map[string]Score) error {
	// Build comma-joined CVE list for ?cve=CVE-1,CVE-2
	q := strings.Join(cves, ",")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL+"?cve="+q, nil)
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("epss: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("epss: API returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("epss: reading response: %w", err)
	}
	var ar apiResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		return fmt.Errorf("epss: decoding response: %w", err)
	}
	for _, d := range ar.Data {
		out[strings.ToUpper(d.CVE)] = Score{
			Probability: parseFloat(d.EPSS),
			Percentile:  parseFloat(d.Percentile),
		}
	}
	return nil
}

// Enrich attaches EPSS scores to findings based on their CVE aliases.
func Enrich(findings []model.Finding, scores map[string]Score) {
	for i := range findings {
		f := &findings[i]
		var best Score
		found := false
		// Use the highest EPSS probability among the finding's CVE aliases
		// (and the vuln ID itself if it's a CVE).
		candidates := append([]string{f.VulnID}, f.Aliases...)
		for _, c := range candidates {
			if s, ok := scores[strings.ToUpper(c)]; ok {
				if !found || s.Probability > best.Probability {
					best = s
					found = true
				}
			}
		}
		if found {
			f.EPSSProbability = best.Probability
			f.EPSSPercentile = best.Percentile
		}
	}
}

// parseFloat parses a string like "0.073360000" to a float64, returning 0 on error.
func parseFloat(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	if err != nil {
		return 0
	}
	return f
}
