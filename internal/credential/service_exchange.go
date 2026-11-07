package credential

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ServiceExchangeTarget is where one service's stored credential is exchanged,
// and for which audience.
type ServiceExchangeTarget struct {
	TokenURL string
	Audience string
}

// ExchangeService builds an Acquirer exchange for an issuer's service-token
// exchange (the Organization plane's POST /api/token/service).
//
// The stored credential is presented only to the issuer's exchange endpoint,
// as a Bearer token, with the audience in the body. What comes back is a token
// valid for minutes, which is what goes to the API. lookup resolves a service
// to its endpoint from the policy in force, so a reload is honoured.
func ExchangeService(client *http.Client, lookup func(service string) (ServiceExchangeTarget, error)) func(context.Context, string, Material) (string, time.Time, error) {
	return func(ctx context.Context, service string, m Material) (string, time.Time, error) {
		if err := m.Require(FieldToken); err != nil {
			return "", time.Time{}, fmt.Errorf("%s: %w", service, err)
		}
		target, err := lookup(service)
		if err != nil {
			return "", time.Time{}, err
		}
		if target.TokenURL == "" || target.Audience == "" {
			return "", time.Time{}, fmt.Errorf("%s has no service exchange configured", service)
		}
		body, err := json.Marshal(map[string]string{"audience": target.Audience})
		if err != nil {
			return "", time.Time{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.TokenURL, bytes.NewReader(body))
		if err != nil {
			return "", time.Time{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+m[FieldToken])

		// A redirect would carry the stored credential to wherever it points.
		// The exchange never redirects, so one is a refusal, not a hop.
		c := *client
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := c.Do(req)
		if err != nil {
			// The cause tells a refused connection from a TLS failure, a timeout
			// or a cancelled context. It is the inner error of *url.Error, which
			// carries the URL and the transport cause, never request headers —
			// the stored credential travels only in Authorization.
			cause := err
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				cause = urlErr.Err
			}
			return "", time.Time{}, fmt.Errorf("%s: could not reach the service exchange: %w", service, cause)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if resp.StatusCode/100 != 2 {
			// Only the status: a token endpoint's body may echo a token, and an
			// error message travels to logs and terminals.
			return "", time.Time{}, fmt.Errorf("%s: the service exchange returned %s", service, resp.Status)
		}
		var out struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int64  `json:"expires_in"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return "", time.Time{}, fmt.Errorf("%s: could not read the service exchange response", service)
		}
		if out.AccessToken == "" {
			return "", time.Time{}, fmt.Errorf("%s: the service exchange returned no token", service)
		}
		if out.ExpiresIn <= 0 {
			// Without a lifetime the token cannot be cached safely; use it for
			// this call only rather than guess how long it lives.
			return out.AccessToken, time.Now(), nil
		}
		return out.AccessToken, time.Now().Add(time.Duration(out.ExpiresIn) * time.Second), nil
	}
}
