package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
)

const token = "SECRET-forge-token-0123456789"

func forgeEntry(t *testing.T, scheme string) *catalog.Entry {
	t.Helper()
	e, err := catalog.NewForgeEntry(catalog.ForgeSpec{
		Name: "forge-main", Provider: "forgejo", Host: "forge.example",
		Scheme: scheme, Repositories: []string{"o/r"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// fake serves GET /api/v1/user, answering as `handler` decides.
func fake(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/user", handler)
	s := httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s
}

func run(t *testing.T, s *httptest.Server, e *catalog.Entry, expect string) Result {
	t.Helper()
	return Run(context.Background(), Input{Entry: e, Secret: token, ExpectLogin: expect, HTTP: s.Client(), BaseURL: s.URL})
}

func TestVerifyOK(t *testing.T) {
	var got string
	s := fake(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{"login":"chotu"}`))
	})
	res := run(t, s, forgeEntry(t, "bearer"), "")
	if !res.OK || res.Login != "chotu" {
		t.Errorf("Result = %+v, want ok as chotu", res)
	}
	if got != "Bearer "+token {
		t.Errorf("Authorization = %q", got)
	}
}

func TestVerifyTokenScheme(t *testing.T) {
	var got string
	s := fake(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Write([]byte(`{"login":"chotu"}`))
	})
	if res := run(t, s, forgeEntry(t, "token"), ""); !res.OK {
		t.Errorf("Result = %+v", res)
	}
	if got != "token "+token {
		t.Errorf("Authorization = %q, want the token scheme", got)
	}
}

func TestVerifyReasons(t *testing.T) {
	status := func(code int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(body))
		}
	}
	cases := []struct {
		name string
		h    http.HandlerFunc
		want string
	}{
		{"401", status(401, "no"), ReasonUnauthorized},
		{"403", status(403, "no"), ReasonForbidden},
		{"500", status(500, "boom"), ReasonServerError},
		{"404", status(404, "gone"), ReasonUnexpected},
		{"html", status(200, "<html>login</html>"), ReasonUnexpected},
		{"json without a login", status(200, `{"id":3}`), ReasonUnexpected},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := run(t, fake(t, c.h), forgeEntry(t, "bearer"), "")
			if res.OK || res.Reason != c.want {
				t.Errorf("Result = %+v, want reason %q", res, c.want)
			}
		})
	}
}

func TestVerifyUnreachable(t *testing.T) {
	s := fake(t, func(http.ResponseWriter, *http.Request) {})
	e, client, url := forgeEntry(t, "bearer"), s.Client(), s.URL
	s.Close()
	res := Run(context.Background(), Input{Entry: e, Secret: token, HTTP: client, BaseURL: url})
	if res.OK || res.Reason != ReasonUnreachable {
		t.Errorf("Result = %+v, want unreachable", res)
	}
}

func TestVerifyWrongIdentity(t *testing.T) {
	s := fake(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"login":"chotu"}`)) })
	res := run(t, s, forgeEntry(t, "bearer"), "someone-else")
	if res.OK || res.Reason != ReasonWrongIdentity || res.Login != "chotu" {
		t.Errorf("Result = %+v, want wrong-identity naming chotu", res)
	}
}

func TestVerifyDoesNotFollowRedirects(t *testing.T) {
	var hits int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"login":"x"}`))
	}))
	defer other.Close()
	s := fake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v1/user", http.StatusFound)
	})
	res := run(t, s, forgeEntry(t, "bearer"), "")
	if res.OK || res.Reason != ReasonRedirect {
		t.Errorf("Result = %+v, want redirect", res)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Error("the redirect target received a request: the Authorization header would have leaked")
	}
}

func TestVerifyResultNeverContainsSecret(t *testing.T) {
	s := fake(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		w.Write([]byte("bad credentials: " + r.Header.Get("Authorization")))
	})
	res := run(t, s, forgeEntry(t, "bearer"), "")
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), token) {
		t.Errorf("result leaks the secret: %s", b)
	}
}

func TestVerifyUnsupportedForBuiltin(t *testing.T) {
	e, _ := catalog.Lookup("github")
	res := Run(context.Background(), Input{Entry: e, Secret: token})
	if res.OK || res.Reason != ReasonUnsupported {
		t.Errorf("Result = %+v, want unsupported", res)
	}
}
