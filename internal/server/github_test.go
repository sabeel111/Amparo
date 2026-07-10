package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestVerifyGitHubSignature covers the HMAC-SHA256 verification that's the
// security gate for the webhook. The classic gotcha: the HMAC must be over the
// RAW body, not re-serialized JSON. We test both valid and invalid signatures.
func TestVerifyGitHubSignature(t *testing.T) {
	secret := "test-webhook-secret"
	body := []byte(`{"ref":"refs/heads/main","after":"abc123","repository":{"full_name":"owner/repo"}}`)

	// Compute a valid signature the way GitHub does: HMAC-SHA256 over raw body.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	validSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	cases := []struct {
		name     string
		sig      string
		expected bool
	}{
		{"valid signature", validSig, true},
		{"invalid signature", "sha256=deadbeef", false},
		{"wrong prefix", "sha1=" + validSig[7:], false},
		{"empty signature", "", false},
		{"tampered body", validSig, false}, // tested separately below
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "tampered body" {
				// The signature was computed over the original body; a different
				// body must fail verification.
				tampered := []byte(`{"ref":"refs/heads/main","after":"HACKED"}`)
				got := verifyGitHubSignature(secret, tampered, validSig)
				if got {
					t.Error("signature verified against a tampered body — HMAC broken")
				}
				return
			}
			got := verifyGitHubSignature(secret, body, c.sig)
			if got != c.expected {
				t.Errorf("verifyGitHubSignature(%s) = %v, want %v", c.name, got, c.expected)
			}
		})
	}
}

// TestVerifyGitHubSignature_DevMode confirms that with NO secret configured,
// verification is skipped (returns true) — for local dev convenience.
func TestVerifyGitHubSignature_DevMode(t *testing.T) {
	got := verifyGitHubSignature("", []byte("anything"), "sha256=whatever")
	if !got {
		t.Error("expected dev mode (empty secret) to skip verification (return true)")
	}
}
