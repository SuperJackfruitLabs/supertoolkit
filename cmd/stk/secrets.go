package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/oauth2flow"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// acquirers holds one acquirer per scheme that needs an exchange.
//
// Each scheme caches and single-flights separately, because their token lives
// differ by an order of magnitude: a GitHub App installation token lasts an
// hour, an X access token two, and sharing one cache would make the shorter one
// govern both.
type acquirers struct {
	githubApp *credential.Acquirer
	oauth2    *credential.Acquirer
}

func newAcquirers(cfg *policy.Config, store *credential.Store, client *http.Client) *acquirers {
	return &acquirers{
		githubApp: &credential.Acquirer{
			Material: store.Material,
			Exchange: credential.ExchangeGitHubApp("https://api.github.com", client),
		},
		oauth2: &credential.Acquirer{
			Material: store.Material,
			Exchange: credential.ExchangeRefresh(
				func(ctx context.Context, service string, m credential.Material) (string, string, time.Time, error) {
					svc, ok := cfg.Service(service)
					if !ok {
						return "", "", time.Time{}, fmt.Errorf("%s is not configured", service)
					}
					o := svc.OAuth2()
					if o.TokenURL == "" {
						return "", "", time.Time{}, fmt.Errorf("%s has no OAuth 2.0 token endpoint", service)
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

// secretSource is what the egress proxy asks for a service's credential.
//
// Three of the five schemes never hand over a long-lived secret: two acquire a
// short-lived token first, and SigV4 is signed in the broker and never reaches
// this path at all. One switch, dispatching on the catalogue's declared
// operation, so `stk run` and `stk serve` cannot drift apart about what a
// scheme means.
func secretSource(cfg *policy.Config, store *credential.Store, acqs *acquirers) func(string) (string, error) {
	return func(service string) (string, error) {
		svc, ok := cfg.Service(service)
		if !ok {
			return "", fmt.Errorf("unknown service %q", service)
		}
		switch svc.Entry().Auth {
		case catalog.AuthGitHubApp:
			return acqs.githubApp.Token(context.Background(), service)
		case catalog.AuthOAuth2:
			return acqs.oauth2.Token(context.Background(), service)
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
