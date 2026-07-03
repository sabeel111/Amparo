// Package osvclient computes CVSS v3.1 base scores from vector strings and
// provides an HTTP client for the OSV.dev API.
//
// OSV records carry CVSS as a VECTOR string (e.g.
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"), not a numeric score. To
// prioritize by severity we must compute the base score ourselves. This is the
// official CVSS v3.1 base-score formula (FIRST.org spec §7.1) — deterministic
// math that belongs in code, never delegated to an LLM.
package osvclient

import (
	"math"
	"strings"
)

// metricValue maps a CVSS v3.1 metric abbreviation to its numeric value.
// See CVSS v3.1 specification table for the exact constants.

// CVSSv3 holds the parsed metrics from a CVSS v3.1 vector.
type CVSSv3 struct {
	AV string // Attack Vector
	AC string // Attack Complexity
	PR string // Privileges Required
	UI string // User Interaction
	S  string // Scope
	C  string // Confidentiality
	I  string // Integrity
	A  string // Availability
}

// ParseCVSSv3 parses a CVSS v3.1 vector string like
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" into a struct.
// Returns false if the vector is malformed.
func ParseCVSSv3(vector string) (CVSSv3, bool) {
	var c CVSSv3
	parts := strings.Split(vector, "/")
	ok := true
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "CVSS:") || p == "" {
			continue
		}
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			ok = false
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "AV":
			c.AV = v
		case "AC":
			c.AC = v
		case "PR":
			c.PR = v
		case "UI":
			c.UI = v
		case "S":
			c.S = v
		case "C":
			c.C = v
		case "I":
			c.I = v
		case "A":
			c.A = v
		}
	}
	// Require the mandatory metrics.
	if c.AV == "" || c.AC == "" || c.PR == "" || c.UI == "" || c.S == "" ||
		c.C == "" || c.I == "" || c.A == "" {
		return c, false
	}
	return c, ok
}

// numeric metric lookups (CVSS v3.1 spec values)
func avValue(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "A":
		return 0.62
	case "L":
		return 0.55
	case "P":
		return 0.2
	}
	return 0.0
}

func acValue(v string) float64 {
	switch v {
	case "L":
		return 0.77
	case "H":
		return 0.44
	}
	return 0.0
}

// prValue depends on Scope (CVSS v3.1 spec: PR has different values when Scope changes).
func prValue(v, scope string) float64 {
	if scope == "C" { // Scope Changed
		switch v {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.5
		}
		return 0.0
	}
	// Scope Unchanged
	switch v {
	case "N":
		return 0.85
	case "L":
		return 0.62
	case "H":
		return 0.27
	}
	return 0.0
}

func uiValue(v string) float64 {
	switch v {
	case "N":
		return 0.85
	case "R":
		return 0.62
	}
	return 0.0
}

func ciaValue(v string) float64 {
	switch v {
	case "H":
		return 0.56
	case "L":
		return 0.22
	case "N":
		return 0.0
	}
	return 0.0
}

// BaseScore computes the CVSS v3.1 base score (0–10) from a parsed vector.
func (c CVSSv3) BaseScore() float64 {
	conf := ciaValue(c.C)
	integ := ciaValue(c.I)
	avail := ciaValue(c.A)

	// Impact Sub-Score (ISC)
	isc := 1 - (1-conf)*(1-integ)*(1-avail)

	var impact float64
	scopeChanged := c.S == "C"
	if scopeChanged {
		impact = 7.52*(isc-0.029) - 3.25*math.Pow(isc-0.02, 15)
	} else {
		impact = 6.42 * isc
	}

	exploitability := 8.22 * avValue(c.AV) * acValue(c.AC) * prValue(c.PR, c.S) * uiValue(c.UI)

	if impact <= 0 {
		return 0
	}
	var score float64
	if scopeChanged {
		score = 1.08 * (impact + exploitability)
	} else {
		score = impact + exploitability
	}
	return roundup(math.Min(score, 10))
}

// roundup implements the CVSS v3.1 Roundup function (spec §7.1.4):
// round up to one decimal place using the official algorithm so our scores
// match FIRST.org/NVD exactly.
func roundup(input float64) float64 {
	intInput := int(math.Round(input * 100000))
	if intInput%10000 == 0 {
		return float64(intInput) / 100000.0
	}
	return (float64(intInput/10000) + 1) / 10.0
}

// ScoreFromVector parses and scores a CVSS v3.1 vector, returning the base
// score and whether the vector was valid. Returns 0, false on parse failure.
func ScoreFromVector(vector string) (float64, bool) {
	c, ok := ParseCVSSv3(vector)
	if !ok {
		return 0, false
	}
	return c.BaseScore(), true
}

// ScoreFromVectors takes multiple CVSS vector strings (e.g. v3 and v2) and
// returns the highest valid base score. This matches how we want to present
// severity: the worst-case score across provided metrics.
func ScoreFromVectors(vectors []string) float64 {
	var best float64
	for _, v := range vectors {
		if s, ok := ScoreFromVector(v); ok && s > best {
			best = s
		}
	}
	return best
}
