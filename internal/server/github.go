package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sabeel111/Amparo/internal/scan"
)

// GitHub webhook handling.
//
// Minimal intake (FLAW 4): on a push event, shallow-clone the repo at the push
// commit, run the scan pipeline, persist findings with the commit SHA. Uses a
// PAT for clone auth (simplest); the ghinstallation upgrade to a full App is a
// documented drop-in for later.
//
// Security: webhook signature is verified via HMAC-SHA256 over the RAW body
// (never re-serialized JSON) using hmac.Equal (constant-time). The secret comes
// from AMPARO_GITHUB_WEBHOOK_SECRET.

// githubWebhookSecret returns the configured webhook secret, or empty if unset
// (in which case signature verification is skipped — dev only).
func githubWebhookSecret() string {
	return os.Getenv("AMPARO_GITHUB_WEBHOOK_SECRET")
}

// githubCloneToken returns a PAT for cloning private repos, embedded in the URL.
func githubCloneToken() string {
	return os.Getenv("AMPARO_GITHUB_TOKEN")
}

// verifyGitHubSignature verifies the X-Hub-Signature-256 header against the raw body.
func verifyGitHubSignature(secret string, body []byte, sigHeader string) bool {
	if secret == "" {
		return true // dev mode: no secret configured, skip verification
	}
	if !strings.HasPrefix(sigHeader, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body) // RAW bytes — not re-serialized JSON
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sigHeader)) // constant-time
}

// githubPushPayload is the subset of the push webhook payload we need.
type githubPushPayload struct {
	Ref          string `json:"ref"` // e.g. "refs/heads/main"
	After        string `json:"after"` // commit SHA
	Repository   struct {
		FullName string `json:"full_name"` // "owner/repo"
		CloneURL string `json:"clone_url"`
		Private  bool   `json:"private"`
	} `json:"repository"`
}

// githubPRPayload is the subset of the pull_request webhook payload we need.
type githubPRPayload struct {
	Action      string `json:"action"`
	Number      int    `json:"number"`
	PullRequest struct {
		Head struct {
			SHA string `json:"sha"`
			Ref string `json:"ref"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Repository struct {
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

// handleGitHubWebhook receives GitHub push/PR events and triggers a scan.
func (s *Server) handleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}

	// 1. Read the RAW body (required for HMAC — must not be re-serialized).
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}

	// 2. Verify signature.
	if !verifyGitHubSignature(githubWebhookSecret(), body, r.Header.Get("X-Hub-Signature-256")) {
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	switch event {
	case "ping":
		writeJSON(w, http.StatusOK, map[string]string{"status": "pong"})
		return
	case "push":
		s.handleGitHubPush(w, r, body)
	case "pull_request":
		s.handleGitHubPR(w, r, body)
	default:
		// Acknowledge but ignore other events.
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "event": event})
	}
}

func (s *Server) handleGitHubPush(w http.ResponseWriter, r *http.Request, body []byte) {
	var payload githubPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid push payload")
		return
	}

	// Only scan pushes to the default branch (main/master). Configurable later.
	if !strings.HasSuffix(payload.Ref, "/heads/main") && !strings.HasSuffix(payload.Ref, "/heads/master") {
		writeJSON(w, http.StatusOK, map[string]string{"status": "skipped", "reason": "non-default-branch"})
		return
	}

	// Respond 200 immediately; scan runs async so GitHub doesn't time out.
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "accepted", "repo": payload.Repository.FullName, "sha": payload.After[:7],
	})

	go s.scanGitHubRepo(payload.Repository.CloneURL, payload.Repository.FullName, payload.After, payload.Repository.Private)
}

func (s *Server) handleGitHubPR(w http.ResponseWriter, r *http.Request, body []byte) {
	var payload githubPRPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		writeError(w, http.StatusBadRequest, "invalid PR payload")
		return
	}
	// Only scan opened/synchronized PRs targeting main/master.
	if payload.Action != "opened" && payload.Action != "synchronize" && payload.Action != "reopened" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "skipped", "reason": "action:" + payload.Action})
		return
	}
	if payload.PullRequest.Base.Ref != "main" && payload.PullRequest.Base.Ref != "master" {
		writeJSON(w, http.StatusOK, map[string]string{"status": "skipped", "reason": "non-default-base"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "accepted", "repo": payload.Repository.FullName, "sha": payload.PullRequest.Head.SHA[:7], "pr": fmt.Sprintf("#%d", payload.Number),
	})

	go s.scanGitHubRepo(payload.Repository.CloneURL, payload.Repository.FullName, payload.PullRequest.Head.SHA, payload.Repository.FullName != "")
}

// scanGitHubRepo clones the repo (shallow), runs the scan pipeline, persists.
// Runs in a goroutine so the webhook handler returns fast.
func (s *Server) scanGitHubRepo(cloneURL, repoFullName, sha string, private bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	log.Printf("amparo webhook: scanning %s @ %s", repoFullName, sha[:7])

	// Shallow clone into a temp dir.
	dir, cleanup, err := shallowClone(ctx, cloneURL, sha, private)
	if err != nil {
		log.Printf("amparo webhook: clone failed for %s: %v", repoFullName, err)
		return
	}
	defer cleanup()

	// Run the scan pipeline (same code path as `amparo scan`).
	result, err := scan.Run(ctx, s.pool, scan.Options{
		Path:        dir,
		ProjectName: repoFullName,
		SHA:         sha,
		MatchMode:   "auto",
		Persist:     true,
		Timeout:     5 * time.Minute,
		Log:         logWriter(),
	})
	if err != nil {
		log.Printf("amparo webhook: scan failed for %s: %v", repoFullName, err)
		return
	}
	log.Printf("amparo webhook: scanned %s @ %s → %d findings (%d new), snapshot %d",
		repoFullName, sha[:7], result.Report.Summary.Total, result.FindingsNew, result.SnapshotID)
}

// logWriter returns an io.Writer that writes to the standard logger.
func logWriter() io.Writer {
	return &logWriterType{}
}

type logWriterType struct{}

func (l *logWriterType) Write(p []byte) (int, error) {
	log.Printf("%s", bytes.TrimRight(p, "\n"))
	return len(p), nil
}

// shallowClone does a `git clone --depth 1` of the repo at a specific commit
// into a temp dir. Returns the dir path and a cleanup func.
//
// Uses os/exec (git must be installed) rather than go-git to keep the dep tree
// small. For private repos, the clone URL is rewritten with the token.
func shallowClone(ctx context.Context, cloneURL, sha string, private bool) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "amparo-scan-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { os.RemoveAll(dir) }

	// For private repos, embed the token in the URL if configured.
	url := cloneURL
	if token := githubCloneToken(); token != "" && strings.Contains(url, "github.com") {
		// https://github.com/owner/repo.git → https://x-access-token:TOKEN@github.com/owner/repo.git
		url = strings.Replace(url, "https://", "https://x-access-token:"+token+"@", 1)
	}

	// Shallow clone at the specific commit. --depth 1 + the SHA fetch is the
	// cheapest way to get just that commit's tree.
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--no-checkout", url, dir)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0") // never prompt for credentials
	if out, err := cmd.CombinedOutput(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("git clone: %w: %s", err, string(out))
	}

	// Fetch the specific commit and check it out. (Shallow clone may not include
	// an arbitrary SHA by default, so we fetch it explicitly.)
	if sha != "" {
		fetch := exec.CommandContext(ctx, "git", "fetch", "--depth", "1", "origin", sha)
		fetch.Dir = dir
		fetch.Env = cmd.Env
		if _, err := fetch.CombinedOutput(); err != nil {
			// Fallback: checkout the default branch HEAD (already cloned).
			co := exec.CommandContext(ctx, "git", "checkout", "HEAD")
			co.Dir = dir
			_ = co.Run()
		} else {
			co := exec.CommandContext(ctx, "git", "checkout", "FETCH_HEAD")
			co.Dir = dir
			if out, err := co.CombinedOutput(); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("git checkout: %w: %s", err, string(out))
			}
		}
	} else {
		co := exec.CommandContext(ctx, "git", "checkout", "HEAD")
		co.Dir = dir
		_ = co.Run()
	}

	// Verify the checkout has content.
	if entries, err := os.ReadDir(dir); err != nil || len(entries) == 0 {
		cleanup()
		return "", nil, fmt.Errorf("clone produced empty dir")
	}
	_ = filepath.Walk(dir, func(_ string, _ os.FileInfo, _ error) error { return nil }) // touch
	return dir, cleanup, nil
}
