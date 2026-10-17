// Package credential produces the value that goes on the wire, and puts it
// there. Nothing in this package returns a credential to a caller.
package credential

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
)

// Inject replaces a placeholder with the real credential, in the position the
// service expects it.
//
// It reports where the substitution happened and whether anything was done. A
// request with no placeholder is left alone: injecting anyway would attach a
// credential to a call the caller never claimed needed one.
//
// **Injection is credential-scheme aware, and must stay that way.** A string
// replace is correct for Bearer and silently wrong for Basic, where the
// credential sits inside base64 and no substring matches. The silent case is the
// dangerous one — the request leaves with the placeholder and the provider's 401
// looks like a bad credential rather than a broker that did nothing.
func Inject(r *http.Request, placeholder, secret string, p catalog.Placement, field string) (string, bool) {
	switch p {
	case catalog.BearerHeader:
		v := r.Header.Get("Authorization")
		if !strings.Contains(v, placeholder) {
			return "", false
		}
		r.Header.Set("Authorization", "Bearer "+secret)
		return "authorization: bearer", true

	case catalog.BasicHeader:
		v := r.Header.Get("Authorization")
		enc, found := cutPrefixFold(v, "Basic ")
		if !found {
			return "", false
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
		if err != nil {
			// Undecodable is a refusal, not a pass-through. Rewriting bytes we
			// cannot parse would corrupt the header.
			return "", false
		}
		user, pass, split := strings.Cut(string(raw), ":")
		if !split || !strings.Contains(pass, placeholder) {
			return "", false
		}
		if field != "" {
			user = field
		}
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+secret)))
		return "authorization: basic (decoded, replaced, re-encoded)", true

	case catalog.SchemeHeader:
		if field == "" {
			return "", false
		}
		if !strings.Contains(r.Header.Get("Authorization"), placeholder) {
			return "", false
		}
		r.Header.Set("Authorization", field+" "+secret)
		return "authorization: " + field, true

	case catalog.APIKeyHeader:
		if field == "" {
			return "", false
		}
		if !strings.Contains(r.Header.Get(field), placeholder) {
			return "", false
		}
		r.Header.Set(field, secret)
		return "header: " + field, true

	case catalog.QueryParam:
		if field == "" {
			return "", false
		}
		q := r.URL.Query()
		if !strings.Contains(q.Get(field), placeholder) {
			return "", false
		}
		q.Set(field, secret)
		r.URL.RawQuery = q.Encode()
		return "query: " + field, true
	}
	return "", false
}

// cutPrefixFold trims a case-insensitive prefix. Auth scheme names are
// case-insensitive per RFC 7235, and clients do vary.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return "", false
	}
	return s[len(prefix):], true
}
