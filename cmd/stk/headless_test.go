package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

// fakeProvider behaves the way a real one does: pending for a while, then a
// slow_down, then approval.
func fakeProvider(t *testing.T, token string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A one-second interval: the shortest a provider may honestly state,
		// and short enough that the test is not mostly waiting.
		fmt.Fprint(w, `{"device_code":"DEVICE-CODE-SECRET","user_code":"WXYZ-1234",
			"verification_uri":"https://example.invalid/device","interval":1,"expires_in":900}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch polls.Add(1) {
		case 1:
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
		default:
			fmt.Fprintf(w, `{"access_token":%q,"token_type":"bearer","scope":"repo"}`, token)
		}
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, &polls
}

// rig points stk's config and home at a temporary directory.
func rig(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "supertoolkit.yaml")
	if err := os.WriteFile(cfg, []byte(config), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STK_CONFIG", cfg)
	t.Setenv("STK_HOME", filepath.Join(dir, "home"))
	t.Setenv("STK_PASSPHRASE", "test-passphrase")
	return dir
}

func TestConnectDeviceStoresTheTokenAndNeverPrintsTheDeviceCode(t *testing.T) {
	const token = "gho_the_token_the_provider_issued"
	prov, polls := fakeProvider(t, token)
	rig(t, fmt.Sprintf(`workspace: test
services:
  github:
    scopes: []
    device:
      client_id: Iv1.testclientid
      authorization_url: %s/device/code
      token_url: %s/token
`, prov.URL, prov.URL))

	var out strings.Builder
	if err := connectDevice("github", &out); err != nil {
		t.Fatalf("connectDevice: %v", err)
	}
	text := out.String()

	// The token reached the store.
	dir, _ := home()
	pass, _, err := credential.StoreKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.Material("github")
	if err != nil {
		t.Fatalf("nothing was stored: %v", err)
	}
	if m.Token() != token {
		t.Errorf("stored %q, want the provider's token", m.Token())
	}

	// It polled more than once, so `authorization_pending` did not abort.
	if n := polls.Load(); n < 2 {
		t.Errorf("polled %d times; pending must not end the flow", n)
	}

	// The user code is shown — it is what the person types.
	if !strings.Contains(text, "WXYZ-1234") {
		t.Error("the user code was never shown; nobody can approve what they cannot read")
	}
	// The device code and the token are not. One is what a poll redeems, the
	// other is the credential itself.
	if strings.Contains(text, "DEVICE-CODE-SECRET") {
		t.Error("the device code was printed")
	}
	if strings.Contains(text, token) {
		t.Error("the credential was printed")
	}
	// What is about to happen is said before it happens.
	for _, want := range []string{"without a browser", "to this broker only"} {
		if !strings.Contains(text, want) {
			t.Errorf("the output never says %q:\n%s", want, text)
		}
	}
}

// Two different kinds of "no" need two different answers: a provider that does
// not offer the flow cannot be fixed by configuration, and a missing client id
// can.
func TestDeviceRefusalsSayWhichPieceIsMissing(t *testing.T) {
	rig(t, `workspace: test
services:
  github:
    scopes: []
`)
	err := connectDevice("github", &strings.Builder{})
	if err == nil {
		t.Fatal("connecting with no client id succeeded")
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("the error does not name the missing client id: %v", err)
	}

	rig(t, `workspace: test
services:
  aws-sts:
    scopes: []
`)
	err = connectDevice("aws-sts", &strings.Builder{})
	if err == nil {
		t.Fatal("connecting a provider with no device support succeeded")
	}
	if !strings.Contains(err.Error(), "does not offer") || !strings.Contains(err.Error(), "handover") {
		t.Errorf("the error does not offer the remaining paths: %v", err)
	}
}

func TestConnectDeviceNeedsTheServiceAdded(t *testing.T) {
	rig(t, "workspace: test\nservices: {}\n")
	err := connectDevice("github", &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "stk add") {
		t.Errorf("err = %v, want it to point at `stk add`", err)
	}
}

// A device endpoint pair that moves half-way would poll an address that never
// issued the code, and wait forever for an approval that cannot arrive.
func TestHalfOverriddenDeviceEndpointsAreRejected(t *testing.T) {
	rig(t, `workspace: test
services:
  github:
    scopes: []
    device:
      client_id: x
      token_url: https://example.invalid/token
`)
	if err := connectDevice("github", &strings.Builder{}); err == nil {
		t.Fatal("a half-overridden endpoint pair was accepted")
	} else if !strings.Contains(err.Error(), "authorization_url") {
		t.Errorf("err = %v, want it to name the missing endpoint", err)
	}
}

// fakeOAuth2Provider is an authorization server: it issues a code at the
// authorize endpoint and exchanges it at the token endpoint, checking the PKCE
// verifier the way a real one does.
func fakeOAuth2Provider(t *testing.T, refresh string) (*httptest.Server, *url.Values) {
	t.Helper()
	var exchanged url.Values
	var challenge string
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		challenge = q.Get("code_challenge")
		// Redirect back the way a provider does, carrying the state verbatim.
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=the-auth-code&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		exchanged = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		// Verify the PKCE binding, as a real provider must: S256 of the
		// verifier has to equal the challenge from the authorization request.
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"error":"invalid_grant","error_description":"code_verifier does not match code_challenge"}`)
			return
		}
		fmt.Fprintf(w, `{"access_token":"the-access-token","refresh_token":%q,
			"token_type":"bearer","scope":"tweet.write offline.access","expires_in":7200}`, refresh)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s, &exchanged
}

func TestConnectBrowserStoresTheRefreshTokenAndNotTheAccessToken(t *testing.T) {
	prov, exchanged := fakeOAuth2Provider(t, "the-refresh-token")
	oauthPort = 0 // an ephemeral port, so this test can run beside others
	t.Cleanup(func() { oauthPort = 7837 })

	rig(t, fmt.Sprintf(`workspace: test
services:
  x:
    scopes: []
    oauth2:
      client_id: test-client-id
`))
	// Point the catalogue's endpoints at the fake provider through the policy
	// file's own override path, the same way a self-hosted instance would.
	cfgPath := os.Getenv("STK_CONFIG")
	body, _ := os.ReadFile(cfgPath)
	os.WriteFile(cfgPath, []byte(string(body)), 0o644)

	var out strings.Builder
	// The "browser" is a plain GET: the provider redirects, the receiver
	// captures the code, and the exchange follows.
	openBrowser := func(u string) error {
		// Rewrite the authorize URL onto the fake provider.
		parsed, err := url.Parse(u)
		if err != nil {
			return err
		}
		go http.Get(prov.URL + "/authorize?" + parsed.RawQuery)
		return nil
	}
	if err := connectBrowserWith(t, prov.URL, "x", &out, openBrowser); err != nil {
		t.Fatalf("connectBrowser: %v", err)
	}
	text := out.String()

	dir, _ := home()
	pass, _, _ := credential.StoreKey(dir)
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.Material("x")
	if err != nil {
		t.Fatalf("nothing was stored: %v", err)
	}
	if m[credential.FieldRefreshToken] != "the-refresh-token" {
		t.Errorf("refresh token = %q", m[credential.FieldRefreshToken])
	}
	if m[credential.FieldClientID] != "test-client-id" {
		t.Errorf("client id = %q — without it the refresh cannot be made", m[credential.FieldClientID])
	}
	// The access token is deliberately not stored: a stolen store should yield
	// something that must be exchanged with the provider first.
	for field, v := range m {
		if v == "the-access-token" {
			t.Errorf("the access token was stored in %q", field)
		}
	}

	// The PKCE verifier reached the token endpoint, which is what binds the
	// code to this process.
	if exchanged.Get("code_verifier") == "" {
		t.Error("no code_verifier was sent; the code is not bound to this request")
	}
	if exchanged.Get("grant_type") != "authorization_code" {
		t.Errorf("grant_type = %q", exchanged.Get("grant_type"))
	}
	// Nothing secret is printed.
	for _, secret := range []string{"the-access-token", "the-refresh-token", "the-auth-code"} {
		if strings.Contains(text, secret) {
			t.Errorf("the output contains %q", secret)
		}
	}
	if !strings.Contains(text, "connected") {
		t.Errorf("the output never says it connected:\n%s", text)
	}
}

// connectBrowserWith points the service's endpoints at a test provider by
// rewriting the config, which is the same override a self-hosted instance uses.
func connectBrowserWith(t *testing.T, provURL, name string, out *strings.Builder, open func(string) error) error {
	t.Helper()
	cfgPath := os.Getenv("STK_CONFIG")
	os.WriteFile(cfgPath, []byte(fmt.Sprintf(`workspace: test
services:
  %s:
    scopes: []
    oauth2:
      client_id: test-client-id
      authorize_url: %s/authorize
      token_url: %s/token
`, name, provURL, provURL)), 0o644)
	// X is a confidential client, so the secret arrives on stdin.
	return connectBrowser(name, out, strings.NewReader("the-client-secret\n"), open)
}

// A provider that issues no refresh token leaves a connection that dies in two
// hours and cannot recover, which is worse than not connecting at all.
func TestConnectBrowserRefusesAGrantWithNoRefreshToken(t *testing.T) {
	prov, _ := fakeOAuth2Provider(t, "")
	oauthPort = 0
	t.Cleanup(func() { oauthPort = 7837 })
	rig(t, "workspace: test\nservices: {}\n")

	var out strings.Builder
	open := func(u string) error {
		parsed, _ := url.Parse(u)
		go http.Get(prov.URL + "/authorize?" + parsed.RawQuery)
		return nil
	}
	err := connectBrowserWith(t, prov.URL, "x", &out, open)
	if err == nil {
		t.Fatal("a grant with no refresh token was accepted")
	}
	if !strings.Contains(err.Error(), "offline access") {
		t.Errorf("err = %v, want it to name what is missing", err)
	}
}

// A provider matches the redirect URI exactly against what was registered, so
// an operator with an existing app must be able to name theirs rather than
// edit the app to suit us.
func TestAnAlreadyRegisteredRedirectIsHonoured(t *testing.T) {
	port, path, err := loopbackRedirect("http://127.0.0.1:3000/oauth/x/callback")
	if err != nil {
		t.Fatal(err)
	}
	if port != 3000 {
		t.Errorf("port = %d, want 3000", port)
	}
	if path != "/oauth/x/callback" {
		t.Errorf("path = %q, want the registered one", path)
	}

	// localhost and 127.0.0.1 are the same host and different strings, and the
	// provider compares strings.
	if _, _, err := loopbackRedirect("http://localhost:8080/cb"); err != nil {
		t.Errorf("localhost was rejected: %v", err)
	}
	// The default stands when nothing is configured.
	p, pa, _ := loopbackRedirect("")
	if p != oauthPort || pa != "/callback" {
		t.Errorf("default = %d %q", p, pa)
	}
}

// The broker listens for the redirect itself, so a callback pointing anywhere
// else can never reach this machine — and one reachable from the network lets
// anybody on it deliver a code here.
func TestANonLoopbackRedirectIsRefused(t *testing.T) {
	for _, bad := range []string{
		"https://example.com/callback",
		"http://192.168.1.10:7837/callback",
		"https://myapp.ngrok.io/cb",
	} {
		_, _, err := loopbackRedirect(bad)
		if err == nil {
			t.Errorf("redirect_uri %q was accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("err for %q = %v, want it to say why", bad, err)
		}
	}
}

// GitHub issues a refresh token whenever the app has token expiration enabled,
// and discarding it meant a device-granted connection died at its expiry and
// needed a person with a phone again — on a machine with no browser, which is
// the one place that cannot be asked.
func TestDeviceFlowKeepsARefreshTokenWhenOneIsIssued(t *testing.T) {
	const access, refresh = "gho_access_token", "ghr_refresh_token"
	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/device/code", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"device_code":"DEVICE-SECRET","user_code":"ABCD-1234",
			"verification_uri":"https://example.invalid/device","interval":1,"expires_in":900}`)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if polls.Add(1) == 1 {
			fmt.Fprint(w, `{"error":"authorization_pending"}`)
			return
		}
		// An app with token expiration enabled, as the operator's was.
		fmt.Fprintf(w, `{"access_token":%q,"refresh_token":%q,"token_type":"bearer",
			"scope":"repo,read:org","expires_in":28800,"refresh_token_expires_in":15897600}`, access, refresh)
	})
	prov := httptest.NewServer(mux)
	t.Cleanup(prov.Close)

	rig(t, fmt.Sprintf(`workspace: test
services:
  github:
    scopes: []
    device:
      client_id: Ov23litestclientid
      authorization_url: %s/device/code
      token_url: %s/token
`, prov.URL, prov.URL))

	var out strings.Builder
	if err := connectDevice("github", &out); err != nil {
		t.Fatal(err)
	}

	dir, _ := home()
	pass, _, _ := credential.StoreKey(dir)
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	m, err := store.Material("github")
	if err != nil {
		t.Fatal(err)
	}
	if m[credential.FieldRefreshToken] != refresh {
		t.Fatalf("the refresh token was dropped; the connection would die at its expiry and need a person with a phone on a headless machine")
	}
	// The client id must travel with it, or the refresh cannot be made.
	if m[credential.FieldClientID] != "Ov23litestclientid" {
		t.Errorf("client id = %q", m[credential.FieldClientID])
	}
	if m[credential.FieldToken] != access {
		t.Errorf("access token = %q", m[credential.FieldToken])
	}

	// And the operator is told, rather than left to find out at the expiry.
	text := out.String()
	if !strings.Contains(text, "renews itself") {
		t.Errorf("the output does not say the connection renews itself:\n%s", text)
	}
	for _, secret := range []string{access, refresh, "DEVICE-SECRET"} {
		if strings.Contains(text, secret) {
			t.Errorf("the output contains %q", secret)
		}
	}
}

// A provider that issues no refresh token must say so plainly, because then
// someone really will have to connect again.
func TestDeviceFlowSaysWhenAConnectionWillNotRenew(t *testing.T) {
	prov, _ := fakeProvider(t, "gho_only_an_access_token")
	rig(t, fmt.Sprintf(`workspace: test
services:
  github:
    scopes: []
    device:
      client_id: Ov23litestclientid
      authorization_url: %s/device/code
      token_url: %s/token
`, prov.URL, prov.URL))

	var out strings.Builder
	if err := connectDevice("github", &out); err != nil {
		t.Fatal(err)
	}
	dir, _ := home()
	pass, _, _ := credential.StoreKey(dir)
	store, _ := credential.OpenStore(dir, pass)
	m, _ := store.Material("github")
	if _, ok := m[credential.FieldRefreshToken]; ok {
		t.Error("a refresh token was invented where the provider issued none")
	}
}

// Every user-facing line about a credential must describe the credential, not
// the catalogue entry it was obtained under.
//
// `stk doctor` said "the stored token is what goes on the wire, so treat it as
// long-lived" about a device-granted token that refreshes itself — the second
// time one of these sentences described the table instead of the thing in front
// of it. The first was the OAuth 2.0 browser flow.
func TestAStoredRefreshTokenChangesWhatWeSayAboutIt(t *testing.T) {
	rig(t, "workspace: test\nservices:\n  github:\n    scopes: []\n")
	dir, _ := home()
	pass, _, _ := credential.StoreKey(dir)
	store, err := credential.OpenStore(dir, pass)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := catalog.Lookup("github")

	// A plain token: the catalogue is right about it.
	if err := store.PutMaterial("github", credential.Material{credential.FieldToken: "gho_plain"}); err != nil {
		t.Fatal(err)
	}
	if got := effectiveAuth(entry, store, "github"); got != catalog.AuthToken {
		t.Errorf("a plain token reads as %v, want substitute", got)
	}
	if !strings.Contains(effectiveAuth(entry, store, "github").Reassurance(), "long-lived") {
		t.Error("a plain token should be described as long-lived; it is")
	}

	// The same service, granted through the device flow with a refresh token.
	if err := store.PutMaterial("github", credential.Material{
		credential.FieldToken:        "gho_access",
		credential.FieldRefreshToken: "ghr_refresh",
		credential.FieldClientID:     "Ov23li",
	}); err != nil {
		t.Fatal(err)
	}
	got := effectiveAuth(entry, store, "github")
	if got != catalog.AuthOAuth2 {
		t.Fatalf("a credential that refreshes itself reads as %v", got)
	}
	r := got.Reassurance()
	if strings.Contains(r, "long-lived") {
		t.Errorf("a self-renewing credential is still described as long-lived: %q", r)
	}
	if !strings.Contains(r, "short-lived access token") {
		t.Errorf("reassurance = %q, want it to describe the refresh", r)
	}
}
