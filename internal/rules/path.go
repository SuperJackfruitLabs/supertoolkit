// Package rules decides which HTTP requests an agent may send to a forge.
// It is dependency-free and fails closed: anything it cannot classify with
// certainty is refused.
package rules

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Refusal reasons, named inside the error text returned by NormalizePath.
const (
	reasonDotSegment       = "dot-segment"
	reasonEncodedSeparator = "encoded-separator"
	reasonEmptySegment     = "empty-segment"
	reasonControlByte      = "control-byte"
	reasonBackslash        = "backslash"
	reasonPathParameter    = "path-parameter"
	reasonBadEncoding      = "bad-encoding"
	reasonDoubleEncoding   = "double-encoding"
)

func refuse(reason, detail string) error {
	return fmt.Errorf("path refused: %s: %s", reason, detail)
}

// NormalizePath takes r.URL.EscapedPath() (no query string) and returns the
// decoded path, or an error naming why it was refused. Each segment is
// decoded exactly once. A trailing slash is preserved so that pattern
// matching can distinguish "/a" from "/a/".
// The return value is for matching only and must never be forwarded upstream;
// forward the original escaped path.
func NormalizePath(escaped string) (string, error) {
	if escaped == "" || escaped[0] != '/' {
		return "", refuse(reasonEmptySegment, "path must start with /")
	}
	segs := strings.Split(escaped[1:], "/")
	out := make([]string, len(segs))
	for i, raw := range segs {
		if raw == "" {
			// Only a trailing empty segment (trailing slash, or the root)
			// is tolerated.
			if i == len(segs)-1 {
				continue
			}
			return "", refuse(reasonEmptySegment, "empty interior segment")
		}
		// Raw checks, before any decoding.
		if strings.ContainsRune(raw, '\\') {
			return "", refuse(reasonBackslash, "backslash in segment")
		}
		if hasControl(raw) {
			return "", refuse(reasonControlByte, "control byte in segment")
		}
		if strings.ContainsRune(raw, ';') {
			return "", refuse(reasonPathParameter, "; in segment")
		}
		lower := strings.ToLower(raw)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return "", refuse(reasonEncodedSeparator, "encoded / or \\ in segment")
		}
		dec, err := url.PathUnescape(raw)
		if err != nil {
			return "", refuse(reasonBadEncoding, "invalid percent-encoding")
		}
		if !utf8.ValidString(dec) {
			return "", refuse(reasonBadEncoding, "invalid UTF-8 after decoding")
		}
		if strings.ContainsRune(dec, '%') {
			return "", refuse(reasonDoubleEncoding, "% remains after decoding")
		}
		if dec == "." || dec == ".." {
			if dec != raw {
				return "", refuse(reasonEncodedSeparator, "encoded dot-segment")
			}
			return "", refuse(reasonDotSegment, dec)
		}
		// Decoded checks: %00, %0a, %3b and friends.
		switch {
		case hasControl(dec) || hasC1(dec):
			return "", refuse(reasonControlByte, "encoded control byte in segment")
		case strings.ContainsRune(dec, '\\'):
			return "", refuse(reasonBackslash, "encoded backslash in segment")
		case strings.ContainsRune(dec, ';'):
			return "", refuse(reasonPathParameter, "encoded ; in segment")
		case strings.ContainsRune(dec, '/'):
			return "", refuse(reasonEncodedSeparator, "decoded / in segment")
		}
		out[i] = dec
	}
	return "/" + strings.Join(out, "/"), nil
}

func hasC1(s string) bool {
	for _, r := range s {
		if r >= 0x80 && r <= 0x9f {
			return true
		}
	}
	return false
}

func hasControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// MatchPath reports whether path matches pattern, segment by segment.
// Literals are case-sensitive; "*" matches exactly one segment; "**" matches
// the remaining one-or-more segments and is honoured only as the last pattern
// segment; "{name}" matches one segment and captures it into vars (which may
// be nil). Both inputs are expected to be normalised; a trailing slash on one
// side only does not match. vars is written only on a successful match.
func MatchPath(pattern, path string, vars map[string]string) bool {
	if !strings.HasPrefix(pattern, "/") || !strings.HasPrefix(path, "/") {
		return false
	}
	ps := strings.Split(pattern[1:], "/")
	xs := strings.Split(path[1:], "/")
	captured := map[string]string{}
	for i, p := range ps {
		if p == "**" {
			if i != len(ps)-1 || len(xs) <= i {
				return false
			}
			for _, rest := range xs[i:] {
				if rest == "" {
					return false
				}
			}
			break
		}
		if i >= len(xs) {
			return false
		}
		x := xs[i]
		switch {
		case p == "*":
			if x == "" {
				return false
			}
		case len(p) > 2 && p[0] == '{' && p[len(p)-1] == '}':
			if x == "" {
				return false
			}
			captured[p[1:len(p)-1]] = x
		default:
			if p != x {
				return false
			}
		}
		if i == len(ps)-1 && len(xs) != len(ps) {
			return false
		}
	}
	if vars != nil {
		for k, v := range captured {
			vars[k] = v
		}
	}
	return true
}
