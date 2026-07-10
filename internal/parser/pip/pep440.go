package pipparser

import (
	"strconv"
	"strings"
)

// This file implements a pragmatic PEP 440 version parser and comparator.
//
// PEP 440 versions are NOT semver. They look like:
//   1.0
//   1.0.1b2       (beta)
//   1.0a3.dev1    (alpha, dev release)
//   1!2.0         (epoch)
//   1.0.post1     (post-release)
//   1.0+local     (local version)
//   2018.11       (calendar versioning, common in pip)
//
// We parse into a comparable struct so that remediation can pick the lowest
// fixed version correctly. This is not a 100% complete PEP 440 implementation
// but covers the overwhelming majority of real PyPI versions.

type pep440 struct {
	epoch   int
	release []int
	pre     *preRelease // nil = no pre-release
	post    *int        // nil = no post-release
	dev     *int        // nil = no dev release
	local   string
}

type preRelease struct {
	kind string // "a","b","rc","alpha","beta","c","pre","preview"
	num  int
}

// parsePEP440 parses a version string into a comparable pep440. On any parse
// trouble it returns a value that compares via a numeric prefix fallback so the
// caller never crashes; callers should prefer the explicit comparator.
func parsePEP440(v string) pep440 {
	p := pep440{}
	v = strings.TrimSpace(v)

	// Strip local version (after '+'). Keep the rest for ordering; local versions
	// sort after the public version but we treat them as equal to the public base
	// for fix-selection purposes.
	if i := strings.Index(v, "+"); i >= 0 {
		p.local = v[i+1:]
		v = v[:i]
	}

	// Epoch: "N!..."
	if i := strings.Index(v, "!"); i >= 0 {
		if e, err := strconv.Atoi(v[:i]); err == nil {
			p.epoch = e
		}
		v = v[i+1:]
	}

	// Separate release segment from the pre/post/dev trailer at the first letter
	// or '.'-adjacent separator like ".post"/"-dev".
	releasePart, tail := splitReleaseTail(v)
	p.release = parseRelease(releasePart)
	p.pre, p.post, p.dev = parseTail(tail)

	return p
}

func splitReleaseTail(v string) (release, tail string) {
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= '0' && c <= '9' {
			continue
		}
		if c == '.' {
			continue
		}
		// First non-digit/non-dot: rest is tail.
		return v[:i], v[i:]
	}
	return v, ""
}

func parseRelease(s string) []int {
	s = strings.Trim(s, ".")
	if s == "" {
		return []int{0}
	}
	parts := strings.Split(s, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}

func parseTail(tail string) (pre *preRelease, post *int, dev *int) {
	tail = strings.ReplaceAll(tail, "_", ".")
	tail = strings.TrimLeft(tail, ".-")
	tail = strings.ToLower(tail)
	if tail == "" {
		return nil, nil, nil
	}

	// dev release: e.g. ".dev1"
	if strings.Contains(tail, "dev") {
		idx := strings.Index(tail, "dev")
		numStr := strings.TrimLeft(tail[idx+3:], ".-0123456789") // placeholder
		numStr = tail[idx+3:]
		numStr = strings.TrimLeft(numStr, ".-")
		n := 0
		if num, err := strconv.Atoi(grabDigits(numStr)); err == nil {
			n = num
		}
		dev = &n
		tail = strings.TrimSpace(tail[:idx])
	}
	if tail == "" {
		return nil, nil, dev
	}

	// post release: e.g. ".post1"
	if i := strings.Index(tail, "post"); i >= 0 {
		numStr := strings.TrimLeft(tail[i+4:], ".-")
		n := 0
		if num, err := strconv.Atoi(grabDigits(numStr)); err == nil {
			n = num
		}
		post = &n
		tail = strings.TrimSpace(tail[:i])
	}
	if tail == "" {
		return nil, post, dev
	}

	// pre-release: a/alpha, b/beta, c/rc/pre/preview
	tail = strings.TrimLeft(tail, ".-")
	tail = strings.TrimPrefix(tail, "v") // leading v is allowed
	if tail != "" {
		kind := ""
		switch {
		case strings.HasPrefix(tail, "alpha"):
			kind = "a"
		case strings.HasPrefix(tail, "beta"):
			kind = "b"
		case strings.HasPrefix(tail, "c"):
			kind = "rc"
		case strings.HasPrefix(tail, "pre"), strings.HasPrefix(tail, "preview"):
			kind = "rc"
		case strings.HasPrefix(tail, "rc"):
			kind = "rc"
		case strings.HasPrefix(tail, "a"):
			kind = "a"
		case strings.HasPrefix(tail, "b"):
			kind = "b"
		}
		if kind != "" {
			// Bounds-check: kind may be longer than tail in malformed inputs.
			var rest string
			if len(kind) <= len(tail) {
				rest = tail[len(kind):]
			} else {
				rest = ""
			}
			rest = strings.TrimLeft(rest, ".-")
			n := 0
			if num, err := strconv.Atoi(grabDigits(rest)); err == nil {
				n = num
			}
			pre = &preRelease{kind: kind, num: n}
		}
	}
	return pre, post, dev
}

func grabDigits(s string) string {
	end := len(s)
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			end = i
			break
		}
	}
	return s[:end]
}

// comparePEP440 returns -1, 0, or 1 for a vs b following PEP 440 ordering.
func comparePEP440(a, b pep440) int {
	if a.epoch != b.epoch {
		if a.epoch < b.epoch {
			return -1
		}
		return 1
	}
	if c := compareIntSlices(a.release, b.release); c != 0 {
		return c
	}
	// Pre-release: a version WITH a pre-release is LOWER than one WITHOUT.
	if c := comparePre(a.pre, b.pre); c != 0 {
		return c
	}
	// Dev: a dev release is LOWER than a non-dev.
	if c := compareDev(a.dev, b.dev); c != 0 {
		return c
	}
	// Post: a post-release is HIGHER than a non-post.
	if c := comparePost(a.post, b.post); c != 0 {
		return c
	}
	return 0
}

func compareIntSlices(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// preOrder ranks pre-release kinds: alpha(a) < beta(b) < rc.
func preOrder(kind string) int {
	switch kind {
	case "a":
		return 0
	case "b":
		return 1
	case "rc":
		return 2
	}
	return 3
}

// comparePre: nil (no pre-release) sorts AFTER (greater than) a pre-release.
func comparePre(a, b *preRelease) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1 // a (no pre) > b (has pre)
	case b == nil:
		return -1
	}
	if c := preOrder(a.kind) - preOrder(b.kind); c != 0 {
		if c < 0 {
			return -1
		}
		return 1
	}
	if a.num != b.num {
		if a.num < b.num {
			return -1
		}
		return 1
	}
	return 0
}

// compareDev: nil (not a dev release) sorts AFTER a dev release.
func compareDev(a, b *int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1 // a (not dev) > b (dev)
	case b == nil:
		return -1
	}
	if *a != *b {
		if *a < *b {
			return -1
		}
		return 1
	}
	return 0
}

// comparePost: nil (no post) sorts BEFORE a post-release.
func comparePost(a, b *int) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1 // a (no post) < b (has post)
	case b == nil:
		return 1
	}
	if *a != *b {
		if *a < *b {
			return -1
		}
		return 1
	}
	return 0
}

// ComparePipVersions is the exported comparator used by remediation and the
// resolver. It's called on ARBITRARY external version strings (from pypi release
// lists, OSV records, lockfiles) so it must never panic — a single malformed
// version shouldn't crash the whole scanner. On panic it falls back to
// lexicographic comparison, which is wrong-but-safe (better than a crash).
func ComparePipVersions(a, b string) (result int) {
	defer func() {
		if r := recover(); r != nil {
			// Malformed version that our PEP 440 parser can't handle. Fall back
			// to a naive string compare so we never crash the scanner.
			if a < b {
				result = -1
			} else if a > b {
				result = 1
			} else {
				result = 0
			}
		}
	}()
	return comparePEP440(parsePEP440(a), parsePEP440(b))
}
