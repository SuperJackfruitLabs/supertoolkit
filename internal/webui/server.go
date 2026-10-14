// Package webui serves supertoolkit's five screens to the person who runs it.
//
// Adding HTTP to a process that holds credentials is the kind of change that
// quietly widens things, so three rules hold it in place:
//
//   - It binds its **own** listener. The socket agents reach gains no HTTP route.
//   - It is **just another caller**. It holds no privilege to read a secret,
//     because no such privilege exists anywhere in this program. It may show
//     that a credential is present, its fields, scopes and age — never its value.
//   - It binds to the **narrowest interface its owner can reach**, and is
//     started on demand, so the default attack surface is unchanged.
package webui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
)

// Routes is the complete route table, declared so a test can assert that none
// of them hands back a credential. A new route is a deliberate review rather
// than a silent addition.
var Routes = []string{
	"GET /api/status",
	"GET /api/services",
	"GET /api/policy",
	"GET /api/approvals",
	"GET /api/audit",
	"POST /api/policy",
	"POST /api/approvals/decide",
	"POST /api/services/revoke",
}

// NewToken mints the one-time URL token.
//
// Jupyter's pattern: the URL carries it once, the browser keeps a cookie. No
// login system, nothing to get wrong, and nothing stored that could be stolen
// from disk.
func NewToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Options configure the server.
type Options struct {
	Token string
	// API answers the data routes. Supplied by the caller so this package never
	// reaches a credential store directly.
	API http.Handler
	// Assets serves the built web app, when one was embedded.
	Assets http.Handler
}

const cookieName = "stk_ui"

// Handler builds the whole UI handler, token check included.
func Handler(o Options) (http.Handler, error) {
	if o.Token == "" {
		return nil, fmt.Errorf("webui: a token is required; an unauthenticated UI on a credential holder is not offered")
	}
	mux := http.NewServeMux()
	if o.API != nil {
		mux.Handle("/api/", o.API)
	}
	if o.Assets != nil {
		mux.Handle("/", o.Assets)
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintln(w, "supertoolkit: this binary was built without the web assets.")
			fmt.Fprintln(w, "Build them with `pnpm -C web build`, or use the API directly.")
		})
	}
	return authenticate(o.Token, mux), nil
}

// authenticate accepts the token from the URL once, then from a cookie.
func authenticate(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query().Get("token"); q != "" && constantTimeEqual(q, token) {
			http.SetCookie(w, &http.Cookie{
				Name: cookieName, Value: token, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteStrictMode,
			})
			// Redirect so the token leaves the address bar and the browser
			// history, which is where a shared screenshot would otherwise
			// carry it.
			clean := *r.URL
			q := clean.Query()
			q.Del("token")
			clean.RawQuery = q.Encode()
			http.Redirect(w, r, clean.RequestURI(), http.StatusFound)
			return
		}
		if c, err := r.Cookie(cookieName); err == nil && constantTimeEqual(c.Value, token) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, "supertoolkit: this page needs the one-time link from `stk ui`.", http.StatusUnauthorized)
	})
}

// constantTimeEqual compares without leaking length or content through timing.
func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Listen binds the UI's own listener.
//
// A non-loopback address is refused unless the caller says it means it, because
// a careless `stk ui` on a machine with a public IP would otherwise publish a
// console for its own credentials.
func Listen(addr string, allowNonLoopback bool) (net.Listener, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("webui: %q is not host:port: %w", addr, err)
	}
	if !allowNonLoopback && !isLoopback(host) {
		return nil, fmt.Errorf(
			"webui: refusing to bind %s: it is not loopback, and this process holds credentials.\n"+
				"      Use --bind with an address on a private network if you mean it.", addr)
	}
	return net.Listen("tcp", addr)
}

func isLoopback(host string) bool {
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// SortedRoutes is Routes, sorted, for stable output.
func SortedRoutes() []string {
	out := append([]string(nil), Routes...)
	sort.Strings(out)
	return out
}

// URL is the one-time link to print.
func URL(addr, token string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr + "/?token=" + token
	}
	if host == "" || host == "::" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("http://%s:%s/?token=%s", host, port, token)
}
