package verify

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// ---- GitHub App grants ----

const (
	appJWT   = "APP-JWT-aaa.bbb.ccc-SECRET"
	appInstT = "ghs_INSTALLATION-TOKEN-SECRET"
)

func appEntry(t *testing.T, repos ...string) *catalog.Entry {
	t.Helper()
	e, err := catalog.NewForgeEntry(catalog.ForgeSpec{
		Name: "gh-app", Provider: "github", Host: "example.com", Auth: "app", Repositories: repos,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func appIn(s *httptest.Server) *AppInput {
	return &AppInput{
		JWT:               func() (string, error) { return appJWT, nil },
		InstallationToken: func() (string, error) { return appInstT, nil },
	}
}

type ghFake struct {
	slug    string
	pages   [][]string // full_names per page
	appCode int
	hits    []string
	auths   map[string]string
}

func (g *ghFake) start(t *testing.T) *httptest.Server {
	g.auths = map[string]string{}
	var s *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		g.hits = append(g.hits, r.URL.RequestURI())
		g.auths["/app"] = r.Header.Get("Authorization")
		if g.appCode != 0 {
			w.WriteHeader(g.appCode)
			w.Write([]byte("nope " + r.Header.Get("Authorization")))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"slug": g.slug})
	})
	mux.HandleFunc("/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		g.hits = append(g.hits, r.URL.RequestURI())
		g.auths["/installation/repositories"] = r.Header.Get("Authorization")
		page := 1
		if p := r.URL.Query().Get("page"); p != "" {
			page, _ = strconv.Atoi(p)
		}
		if page < len(g.pages) {
			w.Header().Set("Link", `<`+s.URL+`/installation/repositories?per_page=100&page=`+strconv.Itoa(page+1)+`>; rel="next"`)
		}
		var repos []map[string]string
		for _, n := range g.pages[page-1] {
			repos = append(repos, map[string]string{"full_name": n})
		}
		json.NewEncoder(w).Encode(map[string]any{"repositories": repos})
	})
	s = httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s
}

func runApp(t *testing.T, s *httptest.Server, e *catalog.Entry, expect string, app *AppInput) Result {
	t.Helper()
	return Run(context.Background(), Input{Entry: e, ExpectLogin: expect, HTTP: s.Client(), BaseURL: s.URL, App: app})
}

func TestVerifyAppOK(t *testing.T) {
	g := &ghFake{slug: "my-app", pages: [][]string{{"Corp/r", "Corp/s", "Corp/extra"}}}
	s := g.start(t)
	res := runApp(t, s, appEntry(t, "Corp/r", "Corp/s"), "My-App[bot]", appIn(s))
	if !res.OK || res.Login != "my-app[bot]" {
		t.Errorf("Result = %+v, want ok as my-app[bot]", res)
	}
	if g.auths["/app"] != "Bearer "+appJWT || g.auths["/installation/repositories"] != "Bearer "+appInstT {
		t.Errorf("credentials sent = %v", g.auths)
	}
}

func TestVerifyAppWrongSlug(t *testing.T) {
	g := &ghFake{slug: "my-app", pages: [][]string{{"Corp/r"}}}
	s := g.start(t)
	res := runApp(t, s, appEntry(t, "Corp/r"), "other[bot]", appIn(s))
	if res.OK || res.Reason != ReasonWrongIdentity || res.Login != "my-app[bot]" {
		t.Errorf("Result = %+v, want wrong-identity as my-app[bot]", res)
	}
}

func TestVerifyAppRepositoryMissing(t *testing.T) {
	g := &ghFake{slug: "my-app", pages: [][]string{{"Corp/r"}}}
	s := g.start(t)
	res := runApp(t, s, appEntry(t, "Corp/r", "Corp/secret-name"), "", appIn(s))
	if res.OK || res.Reason != ReasonRepositoryMissing || res.Login != "my-app[bot]" {
		t.Errorf("Result = %+v, want repository-missing", res)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "Corp/") {
		t.Errorf("result names a repository: %s", b)
	}
}

func TestVerifyAppUnauthorized(t *testing.T) {
	g := &ghFake{appCode: 401, pages: [][]string{{}}}
	s := g.start(t)
	res := runApp(t, s, appEntry(t, "Corp/r"), "", appIn(s))
	if res.OK || res.Reason != ReasonUnauthorized {
		t.Errorf("Result = %+v, want unauthorized", res)
	}
}

func TestVerifyAppStatusReasons(t *testing.T) {
	for code, want := range map[int]string{403: ReasonForbidden, 500: ReasonServerError, 404: ReasonUnexpected, 302: ReasonRedirect} {
		g := &ghFake{appCode: code, pages: [][]string{{}}}
		s := g.start(t)
		if res := runApp(t, s, appEntry(t, "Corp/r"), "", appIn(s)); res.Reason != want {
			t.Errorf("/app %d: %+v, want %s", code, res, want)
		}
	}
}

func TestVerifyAppCredentialErrorsAreFixedReasons(t *testing.T) {
	g := &ghFake{slug: "a", pages: [][]string{{"Corp/r"}}}
	s := g.start(t)
	e := appEntry(t, "Corp/r")
	boom := func() (string, error) { return "", errors.New("PRIVATE-KEY-MATERIAL") }
	for name, app := range map[string]*AppInput{
		"jwt":   {JWT: boom, InstallationToken: appIn(s).InstallationToken},
		"token": {JWT: appIn(s).JWT, InstallationToken: boom},
	} {
		res := runApp(t, s, e, "", app)
		b, _ := json.Marshal(res)
		if res.OK || res.Reason != ReasonUnauthorized || strings.Contains(string(b), "PRIVATE") {
			t.Errorf("%s: Result = %s, want unauthorized without error text", name, b)
		}
	}
}

func TestVerifyAppResultNeverContainsTokens(t *testing.T) {
	g := &ghFake{slug: "a", pages: [][]string{{"Corp/r"}}}
	s := g.start(t)
	for _, code := range []int{0, 401, 500} {
		g.appCode = code
		b, _ := json.Marshal(runApp(t, s, appEntry(t, "Corp/r"), "", appIn(s)))
		if strings.Contains(string(b), appJWT) || strings.Contains(string(b), appInstT) {
			t.Errorf("code %d: result leaks a credential: %s", code, b)
		}
	}
	g.appCode = 0
	g.pages = [][]string{{}}
	b, _ := json.Marshal(runApp(t, s, appEntry(t, "Corp/r"), "", appIn(s)))
	if strings.Contains(string(b), appInstT) || strings.Contains(string(b), appJWT) {
		t.Errorf("leak: %s", b)
	}
}

func TestVerifyAppPaginatesRepositories(t *testing.T) {
	g := &ghFake{slug: "a", pages: [][]string{{"Corp/a"}, {"Corp/b"}, {"Corp/target"}}}
	s := g.start(t)
	res := runApp(t, s, appEntry(t, "Corp/target"), "", appIn(s))
	if !res.OK {
		t.Errorf("Result = %+v, want ok (repo on page 3)", res)
	}
}

func TestVerifyAppCaseInsensitiveRepos(t *testing.T) {
	g := &ghFake{slug: "a", pages: [][]string{{"CORP/Repo"}}}
	s := g.start(t)
	if res := runApp(t, s, appEntry(t, "corp/REPO"), "", appIn(s)); !res.OK {
		t.Errorf("Result = %+v, want ok", res)
	}
}

func TestVerifyAppPaginationCap(t *testing.T) {
	var pages [][]string
	for i := 0; i < 30; i++ {
		pages = append(pages, []string{"Corp/p" + strconv.Itoa(i)})
	}
	g := &ghFake{slug: "a", pages: pages}
	s := g.start(t)
	// The repo is on page 25: beyond the cap, so it cannot be found.
	res := runApp(t, s, appEntry(t, "Corp/p24"), "", appIn(s))
	if res.OK {
		t.Errorf("Result = %+v, want a failure past the cap", res)
	}
	repoHits := 0
	for _, h := range g.hits {
		if strings.HasPrefix(h, "/installation/repositories") {
			repoHits++
		}
	}
	if repoHits != 20 {
		t.Errorf("repository requests = %d, want exactly 20", repoHits)
	}
}

func TestVerifyAppNextLinkOnOtherHostStops(t *testing.T) {
	var otherHits int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&otherHits, 1)
		w.Write([]byte(`{"repositories":[{"full_name":"Corp/target"}]}`))
	}))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"slug":"a"}`)) })
	mux.HandleFunc("/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `<`+other.URL+`/installation/repositories?page=2>; rel="next"`)
		w.Write([]byte(`{"repositories":[{"full_name":"Corp/a"}]}`))
	})
	s := httptest.NewTLSServer(mux)
	defer s.Close()
	res := runApp(t, s, appEntry(t, "Corp/target"), "", appIn(s))
	if res.OK || res.Reason != ReasonUnexpected {
		t.Errorf("Result = %+v, want unexpected-response", res)
	}
	if atomic.LoadInt32(&otherHits) != 0 {
		t.Error("the installation token was sent to another host")
	}
}

func TestVerifyAppDoesNotFollowRedirects(t *testing.T) {
	var hits int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Write([]byte(`{"slug":"x"}`))
	}))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"slug":"a"}`)) })
	mux.HandleFunc("/installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/installation/repositories", http.StatusFound)
	})
	s := httptest.NewTLSServer(mux)
	defer s.Close()
	res := runApp(t, s, appEntry(t, "Corp/r"), "", appIn(s))
	if res.OK || res.Reason != ReasonRedirect {
		t.Errorf("Result = %+v, want redirect", res)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Error("the redirect target received a request")
	}
}

func TestVerifyAppRequiresAppInput(t *testing.T) {
	g := &ghFake{slug: "a", pages: [][]string{{"Corp/r"}}}
	s := g.start(t)
	for _, app := range []*AppInput{nil, {}, {JWT: appIn(s).JWT}} {
		res := runApp(t, s, appEntry(t, "Corp/r"), "", app)
		if res.OK || res.Reason != ReasonUnsupported {
			t.Errorf("app=%+v: Result = %+v, want unsupported", app, res)
		}
	}
	if len(g.hits) != 0 {
		t.Errorf("provider was called: %v", g.hits)
	}
}
