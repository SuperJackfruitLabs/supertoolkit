package webui

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func handler(t *testing.T, token string) http.Handler {
	t.Helper()
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	})
	h, err := Handler(Options{Token: token, API: api})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestWithoutTheTokenNothingIsServed(t *testing.T) {
	h := handler(t, "the-token")
	for _, path := range []string{"/", "/api/status", "/api/approvals"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token = %d, want 401", path, rec.Code)
		}
	}
}

// Jupyter's pattern: the URL carries the token once, then a cookie does.
func TestTokenFromURLThenCookie(t *testing.T) {
	h := handler(t, "the-token")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/status?token=the-token", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("a URL token = %d, want a redirect", rec.Code)
	}
	// The token must leave the address bar, or a shared screenshot carries it.
	if loc := rec.Header().Get("Location"); strings.Contains(loc, "token=") {
		t.Errorf("the redirect kept the token in the URL: %s", loc)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("no cookie was set")
	}
	c := cookies[0]
	if !c.HttpOnly {
		t.Error("the cookie is readable by scripts")
	}
	if c.SameSite != http.SameSiteStrictMode {
		t.Error("the cookie is not SameSite=Strict, so another site could drive this UI")
	}

	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(c)
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Fatalf("with the cookie = %d, want 200", rec2.Code)
	}
}

func TestWrongTokenIsRefused(t *testing.T) {
	h := handler(t, "the-token")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: "not-the-token"})
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a wrong token = %d, want 401", rec.Code)
	}
}

// A prefix of the real token must not be accepted, which a non-constant-time
// or length-prefix comparison could allow.
func TestPartialTokenIsRefused(t *testing.T) {
	h := handler(t, "abcdefghijklmnop")
	for _, bad := range []string{"", "a", "abcdefgh", "abcdefghijklmnopq"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/status", nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: bad})
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("token %q = %d, want 401", bad, rec.Code)
		}
	}
}

// The invariant, kept by making a violation break the tests. A route whose name
// suggests it returns a credential should be hard to add quietly.
func TestNoRouteReturnsACredential(t *testing.T) {
	banned := []string{"secret", "credential", "token", "password", "key", "reveal", "export", "dump"}
	for _, r := range Routes {
		low := strings.ToLower(r)
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("route %q looks like it returns a credential; nothing here may", r)
			}
		}
	}
	if len(Routes) != 8 {
		t.Errorf("Routes has %d entries, want 8 — a new route needs a deliberate review", len(Routes))
	}
}

func TestHandlerRefusesToRunWithoutAToken(t *testing.T) {
	if _, err := Handler(Options{Token: ""}); err == nil {
		t.Fatal("Handler() built an unauthenticated UI on a process that holds credentials")
	}
}

// A careless `stk ui` on a machine with a public IP must not publish a console
// for its own credentials.
func TestNonLoopbackBindIsRefusedUnlessMeant(t *testing.T) {
	if ln, err := Listen("0.0.0.0:0", false); err == nil {
		ln.Close()
		t.Fatal("binding 0.0.0.0 was allowed without saying so explicitly")
	}
	ln, err := Listen("127.0.0.1:0", false)
	if err != nil {
		t.Fatalf("loopback was refused: %v", err)
	}
	ln.Close()

	// And it is allowed when the caller means it.
	ln2, err := Listen("127.0.0.1:0", true)
	if err != nil {
		t.Fatal(err)
	}
	ln2.Close()
}

func TestURLCarriesTheTokenAndAReachableHost(t *testing.T) {
	got := URL("0.0.0.0:7420", "tok")
	if !strings.Contains(got, "127.0.0.1:7420") {
		t.Errorf("URL() = %q, want a host a browser can actually open", got)
	}
	if !strings.Contains(got, "token=tok") {
		t.Errorf("URL() = %q, want the one-time token", got)
	}
}

func TestListenerIsSeparateFromTheCredentialPlane(t *testing.T) {
	// The UI binds its own TCP listener; the credential plane is a Unix socket
	// served by a different package with no HTTP handler at all.
	ln, err := Listen("127.0.0.1:0", false)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if _, ok := ln.(*net.TCPListener); !ok {
		t.Fatalf("the UI listener is %T, want its own TCP listener", ln)
	}
}
