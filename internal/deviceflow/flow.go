// Package deviceflow implements the OAuth 2.0 device authorization grant,
// RFC 8628.
//
// It is how a machine with no browser gets a credential: the broker asks the
// provider, the provider returns a short code and a URL, a person approves it
// in their own browser wherever they are, and the token comes back **to the
// broker directly**. It never passes through the operator's machine, a hub, or
// us.
//
// Three details of the spec decide whether this works in practice, and all
// three fail silently when got wrong:
//
//   - `authorization_pending` is the normal case, not an error. It means the
//     person has not finished yet.
//   - `slow_down` means widen the interval by five seconds and keep going. A
//     client that retries at the same rate gets rate-limited at the exact
//     moment a person is trying to help it.
//   - `expired_token` means the code died, which an operator can act on, and is
//     not a network fault, which they cannot.
package deviceflow

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config describes a provider's device endpoints.
type Config struct {
	// AuthorizationURL issues the device and user codes.
	AuthorizationURL string
	// TokenURL is polled until the person approves.
	TokenURL string
	ClientID string
	Scopes   []string
	// Client is injectable so tests need no network.
	Client *http.Client
}

// Authorization is what the provider returns to start the flow.
type Authorization struct {
	// DeviceCode is what the poll redeems. It is not shown to anyone and never
	// appears in an error.
	DeviceCode string
	// UserCode is what a person types. It is useless without them approving it,
	// so it may be read aloud, printed, or sent through a notification.
	UserCode string
	// VerificationURI is where the person goes. VerificationURIComplete, when a
	// provider offers it, already contains the code.
	VerificationURI         string
	VerificationURIComplete string
	Interval                time.Duration
	ExpiresAt               time.Time
}

// Token is the result.
type Token struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	Scope        string
	ExpiresAt    time.Time
}

// Reason distinguishes the ways a flow can end, so a caller can say something
// useful rather than "it failed".
type Reason string

const (
	// Denied means the person refused.
	Denied Reason = "denied"
	// Expired means the code died before anyone approved it.
	Expired Reason = "expired"
	// Failed means the provider or the network misbehaved.
	Failed Reason = "failed"
)

// Error carries the reason, so callers can tell a refusal from an outage.
type Error struct {
	Reason  Reason
	Message string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }

func (c Config) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// Start asks the provider for a code.
func Start(ctx context.Context, cfg Config) (*Authorization, error) {
	form := url.Values{"client_id": {cfg.ClientID}}
	if len(cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.AuthorizationURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.client().Do(req)
	if err != nil {
		return nil, &Error{Failed, "could not reach the provider: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode/100 != 2 {
		return nil, &Error{Failed, fmt.Sprintf("the provider answered %s", resp.Status)}
	}
	var out struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		Interval                int    `json:"interval"`
		ExpiresIn               int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, &Error{Failed, "could not read the provider's answer"}
	}
	if out.DeviceCode == "" || out.UserCode == "" {
		return nil, &Error{Failed, "the provider returned no code"}
	}
	interval := time.Duration(out.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second // RFC 8628 §3.2: five seconds when unstated
	}
	expires := 15 * time.Minute
	if out.ExpiresIn > 0 {
		expires = time.Duration(out.ExpiresIn) * time.Second
	}
	return &Authorization{
		DeviceCode: out.DeviceCode, UserCode: out.UserCode,
		VerificationURI: out.VerificationURI, VerificationURIComplete: out.VerificationURIComplete,
		Interval: interval, ExpiresAt: time.Now().Add(expires),
	}, nil
}

// Poll waits for the person, and returns the token when they approve.
func Poll(ctx context.Context, cfg Config, auth *Authorization) (*Token, error) {
	interval := auth.Interval
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(auth.ExpiresAt) {
			return nil, &Error{Expired, "the code expired before it was approved"}
		}

		tok, errCode, err := redeem(ctx, cfg, auth.DeviceCode)
		if err != nil {
			return nil, err
		}
		switch errCode {
		case "":
			return tok, nil
		case "authorization_pending":
			// The normal case: the person has not finished yet.
			continue
		case "slow_down":
			// RFC 8628 §3.5: widen by five seconds and keep going. Retrying at
			// the same rate is how a client gets rate-limited exactly when
			// someone is trying to help it.
			interval += 5 * time.Second
			continue
		case "access_denied":
			return nil, &Error{Denied, "the request was refused"}
		case "expired_token":
			return nil, &Error{Expired, "the code expired before it was approved"}
		default:
			return nil, &Error{Failed, "the provider said " + errCode}
		}
	}
}

// redeem makes one poll. It returns the token, or the provider's error code.
//
// The device code is sent and never returned in an error, because it is the
// value this call redeems.
func redeem(ctx context.Context, cfg Config, deviceCode string) (*Token, string, error) {
	form := url.Values{
		"client_id":   {cfg.ClientID},
		"device_code": {deviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	req, err := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := cfg.client().Do(req)
	if err != nil {
		return nil, "", &Error{Failed, "could not reach the provider"}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		Scope        string `json:"scope"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, "", &Error{Failed, fmt.Sprintf("the provider answered %s with something unreadable", resp.Status)}
	}
	if out.Error != "" {
		return nil, out.Error, nil
	}
	if out.AccessToken == "" {
		return nil, "", &Error{Failed, "the provider returned no token and no error"}
	}
	t := &Token{
		AccessToken: out.AccessToken, RefreshToken: out.RefreshToken,
		TokenType: out.TokenType, Scope: out.Scope,
	}
	if out.ExpiresIn > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	}
	return t, "", nil
}
