package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/oauth2flow"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// Acquirers holds one acquirer per scheme that needs an exchange.
//
// Each scheme caches and single-flights separately, because their token lives
// differ by an order of magnitude: a GitHub App installation token lasts an
// hour, an X access token two, and sharing one cache would make the shorter one
// govern both.
type Acquirers struct {
	GitHubApp *credential.Acquirer
	OAuth2    *credential.Acquirer
	// Service exchanges a stored service credential at an issuer for a token
	// that lasts minutes (catalog.AuthServiceExchange).
	Service *credential.Acquirer
	// ForgeApp holds one acquirer per `kind: forge` service with auth: app.
	// Each has its own App, installation, API base and repository list, so
	// sharing a cache would hand one service's token to another.
	ForgeApp map[string]*credential.Acquirer
}

func NewAcquirers(cfg *policy.Config, store *credential.Store, client *http.Client) *Acquirers {
	return NewAcquirersFn(func() *policy.Config { return cfg }, store, client)
}

// NewAcquirersFn is NewAcquirers over a policy that may be reloaded: the
// OAuth 2.0 refresh looks the service up in whatever policy is current.
func NewAcquirersFn(cfgFn func() *policy.Config, store *credential.Store, client *http.Client) *Acquirers {
	cfg := cfgFn()
	return &Acquirers{
		ForgeApp: ForgeAppAcquirers(cfg, store, client, nil),
		GitHubApp: &credential.Acquirer{
			Material: store.Material,
			Shared:   store,
			Exchange: credential.ExchangeGitHubApp("https://api.github.com", client, nil),
		},
		Service: &credential.Acquirer{
			Material: store.Material,
			Shared:   store,
			Exchange: credential.ExchangeService(client, func(service string) (credential.ServiceExchangeTarget, error) {
				svc, ok := cfgFn().Service(service)
				if !ok {
					return credential.ServiceExchangeTarget{}, fmt.Errorf("%s is not configured", service)
				}
				e := svc.Entry()
				if e.Auth != catalog.AuthServiceExchange {
					return credential.ServiceExchangeTarget{}, fmt.Errorf("%s is not a service-exchange credential", service)
				}
				return credential.ServiceExchangeTarget{TokenURL: e.Exchange.TokenURL, Audience: e.Exchange.Audience}, nil
			}),
		},
		OAuth2: &credential.Acquirer{
			Material: store.Material,
			// Every process on this machine shares one short-lived token, so a
			// fresh `stk run` reuses it instead of exchanging — which is what
			// made concurrent invocations fight over a rotating refresh token.
			Shared: store,
			Exchange: credential.ExchangeRefresh(
				func(ctx context.Context, service string, m credential.Material) (string, string, time.Time, error) {
					svc, ok := cfgFn().Service(service)
					if !ok {
						return "", "", time.Time{}, fmt.Errorf("%s is not configured", service)
					}
					o := svc.OAuth2()
					if o.TokenURL == "" {
						// A device-granted token refreshes at the device
						// flow's own token endpoint, which is the same one.
						o.TokenURL = svc.Device().TokenURL
					}
					if o.TokenURL == "" {
						return "", "", time.Time{}, fmt.Errorf("%s has no token endpoint to refresh against", service)
					}
					tok, err := oauth2flow.Refresh(ctx, oauth2flow.Config{
						TokenURL:     o.TokenURL,
						ClientID:     m[credential.FieldClientID],
						ClientSecret: m[credential.FieldClientSecret],
						Client:       client,
					}, m[credential.FieldRefreshToken])
					if err != nil {
						return "", "", time.Time{}, err
					}
					return tok.AccessToken, tok.RefreshToken, tok.ExpiresAt, nil
				},
				// The rotation is written back to the same store the material
				// came from, before the access token is handed out.
				store.PutMaterial,
				// And re-read from it when a refusal suggests another process
				// rotated the token first.
				store.Material,
			),
		},
	}
}

// ForgeAppAcquirers builds one acquirer per app-authenticated forge service.
// An acquirer in prev whose scope is unchanged is kept, so a reload does not
// discard its single-flight state; a changed scope gets a fresh one.
func ForgeAppAcquirers(cfg *policy.Config, store *credential.Store, client *http.Client, prev map[string]*credential.Acquirer) map[string]*credential.Acquirer {
	out := map[string]*credential.Acquirer{}
	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		e := svc.Entry()
		if e.Forge == nil || e.Auth != catalog.AuthGitHubApp {
			continue
		}
		names := append([]string(nil), e.Forge.RepositoryNames...)
		key := appScopeKey(e.Forge.APIBase, e.Forge.Owner, names)
		if old, ok := prev[name]; ok {
			if sc, ok := old.Shared.(scopedCache); ok && sc.scope == key {
				out[name] = old
				continue
			}
		}
		out[name] = &credential.Acquirer{
			Material: store.Material,
			Shared:   scopedCache{store, key},
			Exchange: credential.ExchangeGitHubApp(e.Forge.APIBase, client,
				func(string) []string { return names }),
		}
	}
	return out
}

// appScopeKey digests what an app forge's installation token is minted for. A
// token cached under a different scope must never be served: a narrowed
// repository list would otherwise keep the broader token until it expired.
func appScopeKey(apiBase, owner string, names []string) string {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(apiBase + "\n" + owner + "\n" + strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])[:16]
}

// scopedCache keys the shared token cache by service and scope, so entries
// written for an old scope are simply never read again and expire.
type scopedCache struct {
	inner credential.SharedCache
	scope string
}

func (c scopedCache) key(service string) string { return service + ".scope-" + c.scope }

func (c scopedCache) CachedToken(service string, early time.Duration) (string, time.Time, bool) {
	return c.inner.CachedToken(c.key(service), early)
}

func (c scopedCache) CacheToken(service, token string, expires time.Time) error {
	return c.inner.CacheToken(c.key(service), token, expires)
}

func (c scopedCache) LockRefresh(service string, wait time.Duration) (func(), bool) {
	return c.inner.LockRefresh(c.key(service), wait)
}

// SharedCacheKey is the name a service's short-lived token is cached under:
// scoped for an app forge, the bare service name for everything else.
func SharedCacheKey(e *catalog.Entry, service string) string {
	if e.Forge != nil && e.Auth == catalog.AuthGitHubApp {
		return scopedCache{scope: appScopeKey(e.Forge.APIBase, e.Forge.Owner, e.Forge.RepositoryNames)}.key(service)
	}
	return service
}

// App returns the acquirer for a service whose catalogue auth is a GitHub App.
func (a *Acquirers) App(service string) *credential.Acquirer {
	if acq, ok := a.ForgeApp[service]; ok {
		return acq
	}
	return a.GitHubApp
}

// EffectiveAuth is the operation a stored credential actually performs.
//
// The catalogue says what a service usually needs; the store says what was
// actually obtained, and the two can differ. A GitHub token granted through the
// device flow is a plain bearer token to the API and an OAuth 2.0 grant to the
// token endpoint, so the catalogue calls it a substitution while it is really
// an acquisition.
//
// That matters because the difference is what every user-facing line about the
// credential is derived from. `stk doctor` told an operator "the stored token
// is what goes on the wire, so treat it as long-lived" about a credential that
// refreshes itself — the second time one of these sentences described the
// catalogue instead of the thing in front of it.
func EffectiveAuth(entry *catalog.Entry, store *credential.Store, service string) catalog.Auth {
	if Refreshable(store, service) {
		return catalog.AuthOAuth2
	}
	return entry.Auth
}

// refreshable reports whether the stored credential can renew itself.
func Refreshable(store *credential.Store, service string) bool {
	for _, f := range store.Fields(service) {
		if f == credential.FieldRefreshToken {
			return true
		}
	}
	return false
}

// SecretSource is what the egress proxy asks for a service's credential.
//
// Three of the five schemes never hand over a long-lived secret: two acquire a
// short-lived token first, and SigV4 is signed in the broker and never reaches
// this path at all. One switch, dispatching on the catalogue's declared
// operation, so `stk run` and `stk serve` cannot drift apart about what a
// scheme means.
func SecretSource(cfg *policy.Config, store *credential.Store, acqs *Acquirers) func(string) (string, error) {
	return func(service string) (string, error) {
		svc, ok := cfg.Service(service)
		if !ok {
			return "", fmt.Errorf("unknown service %q", service)
		}
		// A credential that carries a refresh token renews itself, whatever the
		// catalogue says its scheme is. A device-granted GitHub token is a
		// plain bearer token to the API and an OAuth 2.0 grant to the token
		// endpoint, and only what was stored can tell the difference.
		if Refreshable(store, service) {
			return acqs.OAuth2.Token(context.Background(), service)
		}
		switch svc.Entry().Auth {
		case catalog.AuthGitHubApp:
			return acqs.App(service).Token(context.Background(), service)
		case catalog.AuthOAuth2:
			return acqs.OAuth2.Token(context.Background(), service)
		case catalog.AuthServiceExchange:
			return acqs.Service.Token(context.Background(), service)
		case catalog.AuthSigV4:
			// A SigV4 request is signed, not substituted. Reaching here means
			// a client sent a placeholder for a service that has none, and
			// saying so beats putting a key on the wire.
			return "", fmt.Errorf("%s is signed, not substituted: it cannot be brokered through the proxy, only through `stk mcp`", service)
		default:
			return store.Get(service)
		}
	}
}

// Authorize attaches whatever this service's scheme requires.
//
// One switch, dispatching on the catalogue's declared operation, so there is a
// single place where a credential meets a request and no second path to drift.
// Three of the four arms never put a long-lived secret on the wire.
func Authorize(ctx context.Context, name string, e *catalog.Entry, req *http.Request,
	store *credential.Store, acqs *Acquirers) error {
	// A device/browser grant can make a catalogue token service renewable.
	// Match the actual stored material, as the egress proxy's SecretSource does.
	if Refreshable(store, name) {
		tok, err := acqs.OAuth2.Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}
	switch e.Auth {
	case catalog.AuthSigV4:
		m, err := store.Material(name)
		if err != nil {
			return err
		}
		return credential.SignSigV4(req, m, e.Region, e.AWSService, time.Now())

	case catalog.AuthGitHubApp:
		// The private key stays in the broker; a short-lived installation token
		// goes out, and twenty concurrent callers cause one exchange.
		tok, err := acqs.App(name).Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
		return nil

	case catalog.AuthOAuth2:
		// The refresh token stays in the broker and only ever reaches the
		// provider's own token endpoint; a short-lived access token goes to
		// the API.
		tok, err := acqs.OAuth2.Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil

	case catalog.AuthServiceExchange:
		// The stored service credential only ever reaches the issuer's
		// exchange endpoint; a token valid for minutes goes to the API.
		tok, err := acqs.Service.Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil

	default:
		secret, err := store.Get(name)
		if err != nil {
			return err
		}
		// The placeholder is written in and immediately substituted, so this
		// shares the proxy's injection path rather than duplicating it.
		if e.Placement == catalog.BearerHeader {
			req.Header.Set("Authorization", "Bearer "+broker.Placeholder(name))
		}
		credential.Inject(req, broker.Placeholder(name), secret, e.Placement, e.Field)
		return nil
	}
}
