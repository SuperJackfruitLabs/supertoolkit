package credential

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
)

const (
	ph     = "stk:ref:github:v1"
	secret = "ghp_the_real_credential"
)

func req(t *testing.T, url string) *http.Request {
	t.Helper()
	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInjectBearer(t *testing.T) {
	r := req(t, "https://api.github.com/user")
	r.Header.Set("Authorization", "Bearer "+ph)
	where, ok := Inject(r, ph, secret, catalog.BearerHeader, "")
	if !ok {
		t.Fatal("Inject() reported no injection")
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
		t.Fatalf("Authorization = %q, want the real credential", got)
	}
	if !strings.Contains(where, "bearer") {
		t.Errorf("where = %q, want it to name the bearer header", where)
	}
}

// The bug this exists to prevent: the credential in Basic auth lives inside
// base64, so a string replace matches nothing and silently does not inject.
// The request then leaves carrying the placeholder and the provider's 401 looks
// like a bad credential rather than a broker that did nothing.
func TestInjectBasicIsSchemeAware(t *testing.T) {
	r := req(t, "https://api.github.com/user")
	r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:"+ph)))
	before := r.Header.Get("Authorization")

	where, ok := Inject(r, ph, secret, catalog.BasicHeader, "user")
	if !ok {
		t.Fatal("Inject() reported no injection for Basic auth")
	}
	after := r.Header.Get("Authorization")
	if after == before {
		t.Fatal("the header is unchanged — a naive string replace cannot reach inside base64")
	}

	// The real assertion is what the provider decodes, not merely that bytes changed.
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(after, "Basic "))
	if err != nil {
		t.Fatalf("the rewritten header is not valid base64: %v", err)
	}
	if string(raw) != "user:"+secret {
		t.Fatalf("provider would decode %q, want %q", string(raw), "user:"+secret)
	}
	if !strings.Contains(where, "basic") {
		t.Errorf("where = %q, want it to name basic", where)
	}
}

func TestInjectAPIKeyHeader(t *testing.T) {
	r := req(t, "https://api.github.com/user")
	r.Header.Set("X-Api-Key", ph)
	if _, ok := Inject(r, ph, secret, catalog.APIKeyHeader, "X-Api-Key"); !ok {
		t.Fatal("Inject() reported no injection")
	}
	if got := r.Header.Get("X-Api-Key"); got != secret {
		t.Fatalf("X-Api-Key = %q, want the real credential", got)
	}
}

func TestInjectQueryParam(t *testing.T) {
	r := req(t, "https://api.github.com/user?api_key="+ph+"&other=keep")
	if _, ok := Inject(r, ph, secret, catalog.QueryParam, "api_key"); !ok {
		t.Fatal("Inject() reported no injection")
	}
	q := r.URL.Query()
	if got := q.Get("api_key"); got != secret {
		t.Fatalf("api_key = %q, want the real credential", got)
	}
	if got := q.Get("other"); got != "keep" {
		t.Fatalf("other = %q, want the untouched parameter preserved", got)
	}
}

// No placeholder means nothing to do. Injecting anyway would put a credential on
// a request the caller never claimed needed one.
func TestInjectDoesNothingWithoutThePlaceholder(t *testing.T) {
	r := req(t, "https://api.github.com/user")
	r.Header.Set("Authorization", "Bearer someone-elses-token")
	if where, ok := Inject(r, ph, secret, catalog.BearerHeader, ""); ok {
		t.Fatalf("Inject() injected into a request with no placeholder (where=%q)", where)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer someone-elses-token" {
		t.Fatalf("Authorization = %q, want it untouched", got)
	}
}

func TestInjectRefusesMalformedBasic(t *testing.T) {
	r := req(t, "https://api.github.com/user")
	r.Header.Set("Authorization", "Basic !!!not-base64!!!")
	if _, ok := Inject(r, ph, secret, catalog.BasicHeader, "user"); ok {
		t.Fatal("Inject() claimed success on an undecodable Basic header")
	}
}
