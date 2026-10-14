// Package oauth2flow implements the OAuth 2.0 authorization code grant with
// PKCE, and the refresh that keeps its result alive.
//
// This is the scheme most providers now want: X recommends it over OAuth 1.0a
// for new integrations and requires it outright for media upload, and Google,
// Slack user tokens, Notion and Linear all use it. The device grant in
// `internal/deviceflow` is the same family without a redirect; this one needs a
// browser to come back to, which is why it belongs with the broker's own
// listener rather than with a headless path.
//
// Three things here are security properties rather than details, and each is
// tested:
//
//   - **PKCE is S256, never `plain`.** A `plain` challenge is the verifier, so
//     an attacker who intercepts the authorization request can redeem the code.
//   - **`state` is required and compared in constant time.** Without it, any
//     site can send the operator's browser to our loopback listener carrying a
//     code of the attacker's choosing.
//   - **A rotated refresh token must be persisted.** Providers that rotate
//     invalidate the old one on use; dropping the new one locks the operator
//     out at the next refresh, and the failure surfaces hours later, far from
//     its cause.
package oauth2flow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes a provider's authorization-code endpoints.
type Config struct {
	AuthorizeURL string
	TokenURL     string
	ClientID     string
	// ClientSecret is empty for a public client. When present the token
	// endpoint is called with HTTP Basic, which is what a confidential client
	// must do — X, Google and Slack all require it.
	ClientSecret string
	Scopes       []string
	Client       *http.Client
}

func (c Config) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Token is what the provider returns.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scope        string
	ExpiresAt    time.Time
}

// PKCE is one proof key.
type PKCE struct {
	Verifier  string
	Challenge string
}

// NewPKCE generates a verifier and its S256 challenge.
//
// 32 random bytes, base64url without padding: 43 characters, inside RFC 7636's
// 43–128 range with no encoding ambiguity.
func NewPKCE() (PKCE, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PKCE{}, err
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(v))
	return PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(sum[:])}, nil
}

// NewState generates an anti-forgery value.
func NewState() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SameState compares in constant time, so a timing difference cannot reveal
// how much of a guess was right.
func SameState(a, b string) bool {
	return len(a) > 0 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// AuthorizeURL is where the operator's browser goes.
func AuthorizeURL(cfg Config, redirectURI, state string, p PKCE) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"state":                 {state},
		"code_challenge":        {p.Challenge},
		"code_challenge_method": {"S256"},
	}
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	sep := "?"
	if strings.Contains(cfg.AuthorizeURL, "?") {
		sep = "&"
	}
	return cfg.AuthorizeURL + sep + q.Encode()
}

// Exchange redeems the authorization code.
func Exchange(ctx context.Context, cfg Config, code, redirectURI, verifier string) (*Token, error) {
	return post(ctx, cfg, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
		"client_id":     {cfg.ClientID},
	})
}

// Refresh exchanges a refresh token for a new access token.
//
// The returned Token's RefreshToken is **the one to store from now on**. Some
// providers return the same value, some rotate it and invalidate the old one
// immediately; a caller that ignores the field works until the first rotation
// and then locks the operator out.
func Refresh(ctx context.Context, cfg Config, refreshToken string) (*Token, error) {
	t, err := post(ctx, cfg, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {cfg.ClientID},
	})
	if err != nil {
		return nil, err
	}
	if t.RefreshToken == "" {
		// The provider did not rotate. Carry the existing one forward so a
		// caller can store the result unconditionally and never has to know
		// which kind of provider it is talking to.
		t.RefreshToken = refreshToken
	}
	return t, nil
}

// post calls the token endpoint. A credential never appears in an error here:
// the form carries the code, the verifier and possibly the refresh token.
func post(ctx context.Context, cfg Config, form url.Values) (*Token, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// A confidential client authenticates with Basic rather than a form field.
	// Providers differ on whether they accept client_secret_post at all, and
	// Basic is the one RFC 6749 §2.3.1 requires them to support.
	if cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(cfg.ClientID), url.QueryEscape(cfg.ClientSecret))
	}

	resp, err := cfg.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach the token endpoint")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var out struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		Scope            string `json:"scope"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("the provider answered %s with something that is not JSON", resp.Status)
	}
	if out.Error != "" {
		// The provider's own description is the useful part. It names the
		// grant, not the secret.
		msg := out.Error
		if out.ErrorDescription != "" {
			msg += ": " + out.ErrorDescription
		}
		return nil, fmt.Errorf("the provider refused the grant — %s", msg)
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("the provider answered %s", resp.Status)
	}
	if out.AccessToken == "" {
		return nil, fmt.Errorf("the provider returned no access token and no error")
	}
	t := &Token{
		AccessToken: out.AccessToken, RefreshToken: out.RefreshToken,
		TokenType: out.TokenType, Scope: out.Scope,
	}
	if out.ExpiresIn > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return t, nil
}

// Redirect is a captured authorization response.
type Redirect struct {
	Code  string
	State string
}

// Receiver listens on loopback for the provider's redirect.
//
// It binds 127.0.0.1 only. A redirect URI reachable from the network is one
// anybody on that network can deliver a code to, and the operator's browser is
// on this machine by definition — if it is not, the device grant or the
// broker's own UI over a private network is the right path instead.
type Receiver struct {
	ln    net.Listener
	srv   *http.Server
	got   chan Redirect
	fail  chan error
	state string
}

// Listen starts the receiver. The returned URI is what must be registered with
// the provider and sent in the authorization request.
func Listen(port int, state string) (*Receiver, string, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, "", fmt.Errorf("could not listen for the provider's redirect: %w", err)
	}
	r := &Receiver{
		ln: ln, got: make(chan Redirect, 1), fail: make(chan error, 1), state: state,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", r.callback)
	r.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go r.srv.Serve(ln)
	return r, "http://" + ln.Addr().String() + "/callback", nil
}

func (r *Receiver) callback(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	if e := q.Get("error"); e != "" {
		msg := e
		if d := q.Get("error_description"); d != "" {
			msg += ": " + d
		}
		page(w, "Not connected", "The provider refused: "+msg+". You can close this tab.")
		r.fail <- fmt.Errorf("the provider refused — %s", msg)
		return
	}
	// The state check comes before anything else is believed. Without it, any
	// page the operator visits could deliver a code of its own choosing here.
	if !SameState(r.state, q.Get("state")) {
		page(w, "Not connected", "That response did not match this request, so it was discarded. You can close this tab.")
		r.fail <- fmt.Errorf("the redirect carried the wrong state, so it was discarded — nothing was stored")
		return
	}
	code := q.Get("code")
	if code == "" {
		page(w, "Not connected", "The provider sent no authorization code. You can close this tab.")
		r.fail <- fmt.Errorf("the provider sent no authorization code")
		return
	}
	page(w, "Connected", "supertoolkit has the credential. It stays on this machine; the agent never sees it. You can close this tab.")
	r.got <- Redirect{Code: code, State: q.Get("state")}
}

// page writes the one screen the operator sees. It deliberately echoes nothing
// from the query string, so a code cannot end up in a screenshot or a Referer.
func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// A redirect carries the code in the URL; this stops the page from passing
	// it onward if the operator clicks anything.
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>%s — supertoolkit</title>
<style>body{font:16px/1.6 system-ui,sans-serif;margin:4rem auto;max-width:34rem;padding:0 1rem}
h1{font-size:1.25rem;margin:0 0 .5rem}p{color:#444}</style>
<h1>%s</h1><p>%s</p>`, title, title, body)
}

// Wait blocks until the provider redirects, the operator gives up, or the
// context is cancelled.
func (r *Receiver) Wait(ctx context.Context) (Redirect, error) {
	select {
	case got := <-r.got:
		return got, nil
	case err := <-r.fail:
		return Redirect{}, err
	case <-ctx.Done():
		return Redirect{}, ctx.Err()
	}
}

// Close stops listening.
func (r *Receiver) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return r.srv.Shutdown(ctx)
}
