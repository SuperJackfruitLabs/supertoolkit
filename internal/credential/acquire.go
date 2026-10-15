package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Acquirer exchanges a long-lived secret for a short-lived token, and caches the
// result.
//
// The exchange is **single-flight**: twenty callers arriving together cause one
// exchange, not twenty. Without that, a burst of agent activity would hammer the
// provider's token endpoint and invite rate limiting at exactly the moment the
// agent is busiest.
//
// A failed exchange is deliberately not cached, so the next call retries rather
// than inheriting an empty token for the cache's lifetime.
type Acquirer struct {
	// Exchange performs one acquisition and reports when the result expires.
	Exchange func(ctx context.Context, service string, m Material) (token string, expires time.Time, err error)
	// Material reads the long-lived secret. It is a function so the Acquirer
	// never holds one between exchanges.
	Material func(service string) (Material, error)
	// Early is how long before expiry a cached token is considered stale, so a
	// call never goes out with a token that expires mid-flight.
	Early time.Duration

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	token   string
	expires time.Time
	wg      *sync.WaitGroup // non-nil while an exchange is in flight
	err     error
}

const defaultEarly = 60 * time.Second

// Token returns a valid short-lived token for a service, exchanging if needed.
func (a *Acquirer) Token(ctx context.Context, service string) (string, error) {
	early := a.Early
	if early <= 0 {
		early = defaultEarly
	}

	a.mu.Lock()
	if a.cache == nil {
		a.cache = map[string]*entry{}
	}
	e := a.cache[service]
	if e != nil && e.wg == nil && e.token != "" && time.Now().Add(early).Before(e.expires) {
		tok := e.token
		a.mu.Unlock()
		return tok, nil
	}
	if e != nil && e.wg != nil {
		// Someone is already exchanging; wait for their result rather than
		// starting a second one.
		wg := e.wg
		a.mu.Unlock()
		wg.Wait()
		a.mu.Lock()
		cur := a.cache[service]
		var tok string
		var err error
		if cur != nil {
			tok, err = cur.token, cur.err
		}
		a.mu.Unlock()
		if err != nil {
			return "", err
		}
		if tok == "" {
			return "", fmt.Errorf("acquiring a token for %q produced nothing", service)
		}
		return tok, nil
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	a.cache[service] = &entry{wg: wg}
	a.mu.Unlock()

	m, err := a.Material(service)
	var tok string
	var exp time.Time
	if err == nil {
		tok, exp, err = a.Exchange(ctx, service, m)
	}

	a.mu.Lock()
	if err != nil {
		// Do not cache a failure: the next call should retry.
		delete(a.cache, service)
		a.cache[service] = &entry{err: err}
		a.mu.Unlock()
		wg.Done()
		// And clear the error entry so a later call starts fresh.
		a.mu.Lock()
		delete(a.cache, service)
		a.mu.Unlock()
		return "", err
	}
	a.cache[service] = &entry{token: tok, expires: exp}
	a.mu.Unlock()
	wg.Done()
	return tok, nil
}

// Invalidate drops a cached token, so a revoked credential is not reused.
func (a *Acquirer) Invalidate(service string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cache, service)
}

// ExchangeGitHubApp mints a JWT from the stored private key and trades it for an
// installation token.
//
// The private key never goes to GitHub; the JWT does, and the installation
// token GitHub returns is valid for an hour. So the broker holds the only
// long-lived thing and everything downstream of it expires.
func ExchangeGitHubApp(apiBase string, client *http.Client) func(context.Context, string, Material) (string, time.Time, error) {
	return func(ctx context.Context, service string, m Material) (string, time.Time, error) {
		if err := m.Require(FieldAppID, FieldPrivateKey, FieldInstallationID); err != nil {
			return "", time.Time{}, fmt.Errorf("github app: %w", err)
		}
		jwt, err := MintJWT(m, map[string]any{"iss": m[FieldAppID]}, 9*time.Minute)
		if err != nil {
			return "", time.Time{}, err
		}
		u := strings.TrimSuffix(apiBase, "/") + "/app/installations/" +
			url.PathEscape(m[FieldInstallationID]) + "/access_tokens"
		req, err := http.NewRequestWithContext(ctx, "POST", u, nil)
		if err != nil {
			return "", time.Time{}, err
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := client.Do(req)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("github app: exchanging the JWT: %w", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if resp.StatusCode/100 != 2 {
			// The body is the provider's words, not ours, and carries no
			// credential of ours.
			return "", time.Time{}, fmt.Errorf("github app: the exchange returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
		}
		var out struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			return "", time.Time{}, fmt.Errorf("github app: could not read the exchange response: %w", err)
		}
		if out.Token == "" {
			return "", time.Time{}, fmt.Errorf("github app: the exchange returned no token")
		}
		if out.ExpiresAt.IsZero() {
			out.ExpiresAt = time.Now().Add(55 * time.Minute)
		}
		return out.Token, out.ExpiresAt, nil
	}
}

// ExchangeRefresh builds an Acquirer exchange for the OAuth 2.0 refresh grant.
//
// This is the operation most providers now need: the store holds a refresh
// token and the client's identity, and the broker turns that into a short-lived
// access token on demand. The long-lived value never reaches the wire to the
// API — only to the provider's own token endpoint.
//
// `persist` is not optional and not a convenience. A provider that rotates
// invalidates the old refresh token the moment it issues a new one, so a
// rotation that is not written back locks the operator out at the next refresh
// — and the failure surfaces hours later, nowhere near its cause. The refresher
// therefore stores the token it was handed back before returning the access
// token it was asked for.
//
// `reread` re-reads the stored material after a refusal. A provider that
// rotates invalidates the old token the instant it issues a new one, and X
// rotates on *every* use — so two `stk run` invocations starting together each
// refresh with the same stored token, one wins, and the other is refused with
// `invalid_grant` for a token that was valid when it read it. The loser re-reads
// and tries once with whatever the winner just stored, which turns the race
// into nothing. It is optional: without it the behaviour is the previous one,
// a failed call and an intact connection.
func ExchangeRefresh(
	refresh func(ctx context.Context, service string, m Material) (access, newRefresh string, expires time.Time, err error),
	persist func(service string, m Material) error,
	reread func(service string) (Material, error),
) func(context.Context, string, Material) (string, time.Time, error) {
	return func(ctx context.Context, service string, m Material) (string, time.Time, error) {
		if err := m.Require(FieldRefreshToken, FieldClientID); err != nil {
			return "", time.Time{}, fmt.Errorf("oauth2 refresh: %w", err)
		}
		access, newRefresh, expires, err := refresh(ctx, service, m)
		if err != nil && reread != nil {
			// Another process may have rotated the token between our read and
			// our use. Only retry when the stored value actually changed —
			// retrying with the same token would just repeat the refusal.
			if fresh, rerr := reread(service); rerr == nil &&
				fresh[FieldRefreshToken] != "" &&
				fresh[FieldRefreshToken] != m[FieldRefreshToken] {
				m = fresh
				access, newRefresh, expires, err = refresh(ctx, service, m)
			}
		}
		if err != nil {
			return "", time.Time{}, err
		}
		if newRefresh != "" && newRefresh != m[FieldRefreshToken] {
			// Write the rotation back before handing out the access token. If
			// this fails, the access token we hold still works but the next
			// refresh will not, so it is an error now rather than a surprise
			// later.
			next := Material{}
			for k, v := range m {
				next[k] = v
			}
			next[FieldRefreshToken] = newRefresh
			if persist == nil {
				return "", time.Time{}, fmt.Errorf(
					"oauth2 refresh: %s rotated its refresh token and there is nowhere to store it — the next refresh would fail", service)
			}
			if err := persist(service, next); err != nil {
				return "", time.Time{}, fmt.Errorf(
					"oauth2 refresh: %s rotated its refresh token and storing it failed: %w — reconnect the service before the access token expires", service, err)
			}
		}
		return access, expires, nil
	}
}
