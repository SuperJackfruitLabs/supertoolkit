package oauth2flow

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 7636 §4.2: the challenge is BASE64URL(SHA256(ASCII(verifier))), without
// padding. A `plain` challenge *is* the verifier, so anyone who sees the
// authorization request can redeem the code.
func TestPKCEIsS256AndNotPlain(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if p.Verifier == p.Challenge {
		t.Fatal("the challenge equals the verifier — that is `plain`, and it defeats PKCE entirely")
	}
	sum := sha256.Sum256([]byte(p.Verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.Challenge != want {
		t.Errorf("challenge = %q, want the S256 of the verifier", p.Challenge)
	}
	if n := len(p.Verifier); n < 43 || n > 128 {
		t.Errorf("verifier is %d characters, outside RFC 7636's 43–128", n)
	}
	// And it must differ every time.
	q, _ := NewPKCE()
	if q.Verifier == p.Verifier {
		t.Error("two verifiers were identical")
	}
}

func TestAuthorizeURLCarriesS256AndState(t *testing.T) {
	p := PKCE{Verifier: "v", Challenge: "c"}
	raw := AuthorizeURL(Config{
		AuthorizeURL: "https://x.com/i/oauth2/authorize",
		ClientID:     "client-id",
		Scopes:       []string{"tweet.read", "tweet.write", "offline.access"},
	}, "http://127.0.0.1:7788/callback", "the-state", p)

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type":         "code",
		"client_id":             "client-id",
		"code_challenge":        "c",
		"code_challenge_method": "S256",
		"state":                 "the-state",
		"redirect_uri":          "http://127.0.0.1:7788/callback",
		"scope":                 "tweet.read tweet.write offline.access",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	// The verifier must never leave the machine in the authorization request.
	if strings.Contains(raw, "v") && q.Get("code_verifier") != "" {
		t.Error("the authorization URL carries the code verifier")
	}
}

// tokenServer records what the token endpoint received.
type tokenServer struct {
	*httptest.Server
	gotForm  url.Values
	gotBasic bool
	user     string
	pass     string
	// rotate makes the server behave like a provider that invalidates the old
	// refresh token on use.
	rotate bool
	nth    int
}

func newTokenServer(t *testing.T, rotate bool) *tokenServer {
	ts := &tokenServer{rotate: rotate}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		ts.gotForm = r.PostForm
		ts.user, ts.pass, ts.gotBasic = r.BasicAuth()
		ts.nth++
		w.Header().Set("Content-Type", "application/json")
		refresh := "refresh-1"
		if ts.rotate {
			refresh = fmt.Sprintf("refresh-%d", ts.nth+1)
		} else if r.PostForm.Get("grant_type") == "refresh_token" {
			refresh = "" // this provider does not rotate and says nothing
		}
		fmt.Fprintf(w, `{"access_token":"access-%d","refresh_token":%q,"token_type":"bearer",
			"scope":"tweet.write","expires_in":7200}`, ts.nth, refresh)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestExchangeSendsTheVerifierAndRedirect(t *testing.T) {
	ts := newTokenServer(t, false)
	tok, err := Exchange(context.Background(), Config{TokenURL: ts.URL, ClientID: "cid"},
		"the-code", "http://127.0.0.1:7788/callback", "the-verifier")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" {
		t.Fatal("no access token")
	}
	if tok.ExpiresAt.IsZero() {
		t.Error("expires_in was ignored, so the token will be used past its life")
	}
	for k, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "the-code",
		"code_verifier": "the-verifier",
		"redirect_uri":  "http://127.0.0.1:7788/callback",
	} {
		if got := ts.gotForm.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if ts.gotBasic {
		t.Error("a public client sent Basic auth")
	}
}

// RFC 6749 §2.3.1: a confidential client authenticates with Basic, which every
// server must support — client_secret_post is optional and X, Google and Slack
// differ on it.
func TestConfidentialClientUsesBasicAuth(t *testing.T) {
	ts := newTokenServer(t, false)
	_, err := Exchange(context.Background(),
		Config{TokenURL: ts.URL, ClientID: "cid", ClientSecret: "csecret"},
		"code", "http://127.0.0.1:1/callback", "verifier")
	if err != nil {
		t.Fatal(err)
	}
	if !ts.gotBasic {
		t.Fatal("a confidential client did not use Basic auth")
	}
	if ts.user != "cid" || ts.pass != "csecret" {
		t.Errorf("Basic carried %q/%q", ts.user, ts.pass)
	}
	if ts.gotForm.Get("client_secret") != "" {
		t.Error("the secret was also in the form body, doubling where it travels")
	}
}

// The failure that surfaces hours later, far from its cause: a provider rotates
// the refresh token and invalidates the old one. Dropping the new value locks
// the operator out at the next refresh.
func TestRotatedRefreshTokenIsReturnedToBeStored(t *testing.T) {
	ts := newTokenServer(t, true)
	cfg := Config{TokenURL: ts.URL, ClientID: "cid"}

	first, err := Refresh(context.Background(), cfg, "refresh-1")
	if err != nil {
		t.Fatal(err)
	}
	if first.RefreshToken == "refresh-1" {
		t.Fatal("the rotated refresh token was not returned; the next refresh would fail")
	}
	if first.RefreshToken != "refresh-2" {
		t.Errorf("refresh token = %q, want the provider's new one", first.RefreshToken)
	}
	if ts.gotForm.Get("grant_type") != "refresh_token" {
		t.Errorf("grant_type = %q", ts.gotForm.Get("grant_type"))
	}
}

// A provider that does not rotate says nothing about it. The caller must still
// be able to store the result unconditionally without knowing which kind of
// provider it is.
func TestNonRotatingProviderCarriesTheOldTokenForward(t *testing.T) {
	ts := newTokenServer(t, false)
	tok, err := Refresh(context.Background(), Config{TokenURL: ts.URL, ClientID: "cid"}, "refresh-keep")
	if err != nil {
		t.Fatal(err)
	}
	if tok.RefreshToken != "refresh-keep" {
		t.Errorf("refresh token = %q, want the existing one carried forward", tok.RefreshToken)
	}
}

func TestProviderErrorIsReportedWithItsDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Value passed for the authorization code was invalid."}`)
	}))
	defer srv.Close()
	_, err := Refresh(context.Background(), Config{TokenURL: srv.URL, ClientID: "cid"}, "stale")
	if err == nil {
		t.Fatal("a refused grant succeeded")
	}
	for _, want := range []string{"invalid_grant", "authorization code was invalid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to carry %q", err, want)
		}
	}
	// It must not carry the token it tried.
	if strings.Contains(err.Error(), "stale") {
		t.Error("the error contains the refresh token")
	}
}

func TestReceiverCapturesTheCodeOnLoopbackOnly(t *testing.T) {
	state, _ := NewState()
	r, uri, err := Listen(0, state)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if !strings.HasPrefix(uri, "http://127.0.0.1:") {
		t.Fatalf("redirect URI = %q, want loopback — a reachable one lets anyone deliver a code", uri)
	}

	go http.Get(uri + "?code=the-code&state=" + url.QueryEscape(state))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := r.Wait(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Code != "the-code" {
		t.Errorf("code = %q", got.Code)
	}
}

// Without the state check, any page the operator visits could send their
// browser here carrying a code of the attacker's choosing.
func TestMismatchedStateIsDiscarded(t *testing.T) {
	r, uri, err := Listen(0, "the-real-state")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	resp, err := http.Get(uri + "?code=attacker-code&state=not-the-state")
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 2048)
	n, _ := resp.Body.Read(body)
	resp.Body.Close()
	// The page must not echo the attacker's code back.
	if strings.Contains(string(body[:n]), "attacker-code") {
		t.Error("the page echoed the code from the query string")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got, err := r.Wait(ctx); err == nil {
		t.Fatalf("a mismatched state was accepted, yielding %+v", got)
	} else if !strings.Contains(err.Error(), "state") {
		t.Errorf("err = %v, want it to name the state mismatch", err)
	}
}

func TestEmptyStateNeverMatches(t *testing.T) {
	if SameState("", "") {
		t.Error("two empty states compared equal; an unset state must never match")
	}
	if SameState("a", "b") {
		t.Error("different states compared equal")
	}
	if !SameState("same", "same") {
		t.Error("identical states compared unequal")
	}
}

func TestProviderRefusalReachesTheWaiter(t *testing.T) {
	r, uri, err := Listen(0, "s")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	go http.Get(uri + "?error=access_denied&error_description=The+user+denied+the+request")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := r.Wait(ctx); err == nil {
		t.Fatal("a refusal looked like success")
	} else if !strings.Contains(err.Error(), "access_denied") {
		t.Errorf("err = %v", err)
	}
}
