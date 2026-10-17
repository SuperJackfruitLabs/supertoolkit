// Package verify checks that a stored credential works and acts as the account
// it should, by making one read call to the provider's identity endpoint.
//
// It reports a login and a reason. It never reports the credential, and it never
// copies a provider's response text into a reason, because a provider's error
// body can echo the Authorization header it was sent.
package verify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
)

// Reasons a verification can fail. They are stable strings: agentpod records
// them.
const (
	ReasonUnauthorized  = "unauthorized"
	ReasonForbidden     = "forbidden"
	ReasonUnreachable   = "unreachable"
	ReasonUnexpected    = "unexpected-response"
	ReasonWrongIdentity = "wrong-identity"
	ReasonUnsupported   = "unsupported"
)

// Result is the outcome of one verification.
type Result struct {
	OK     bool   `json:"ok"`
	Login  string `json:"login,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Input is what Run needs.
type Input struct {
	Entry       *catalog.Entry
	Secret      string
	ExpectLogin string
	// HTTP is the client to use; nil means a default with a timeout.
	HTTP *http.Client
	// BaseURL replaces https://<Entry.Host>. For tests.
	BaseURL string
}

// maxBody bounds how much of a provider's reply is read.
const maxBody = 1 << 20

// Run calls the provider's identity endpoint with the credential.
func Run(ctx context.Context, in Input) Result {
	e := in.Entry
	if e == nil || e.Forge == nil {
		return Result{Reason: ReasonUnsupported}
	}
	base := in.BaseURL
	if base == "" {
		base = "https://" + e.Host
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+e.Forge.APIPrefix+e.Forge.IdentityPath, nil)
	if err != nil {
		return Result{Reason: ReasonUnexpected}
	}
	switch e.Placement {
	case catalog.SchemeHeader:
		req.Header.Set("Authorization", e.Field+" "+in.Secret)
	default:
		req.Header.Set("Authorization", "Bearer "+in.Secret)
	}
	req.Header.Set("Accept", "application/json")

	// A redirect would carry the Authorization header to wherever it points. The
	// identity endpoint never redirects, so one is a refusal, not a hop.
	base0 := in.HTTP
	if base0 == nil {
		base0 = &http.Client{Timeout: 15 * time.Second}
	}
	client := *base0
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Do(req)
	if err != nil {
		return Result{Reason: ReasonUnreachable}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return Result{Reason: ReasonUnauthorized}
	case resp.StatusCode == http.StatusForbidden:
		return Result{Reason: ReasonForbidden}
	case resp.StatusCode != http.StatusOK:
		return Result{Reason: ReasonUnexpected}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return Result{Reason: ReasonUnreachable}
	}
	login, err := parseLogin(body)
	if err != nil {
		return Result{Reason: ReasonUnexpected}
	}
	if in.ExpectLogin != "" && !strings.EqualFold(login, in.ExpectLogin) {
		return Result{Login: login, Reason: ReasonWrongIdentity}
	}
	return Result{OK: true, Login: login}
}

// parseLogin reads the account name from an identity reply. Forgejo, Gitea and
// GitHub use "login"; some providers use "username".
func parseLogin(body []byte) (string, error) {
	var v struct {
		Login    string `json:"login"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	if v.Login != "" {
		return v.Login, nil
	}
	if v.Username != "" {
		return v.Username, nil
	}
	return "", errors.New("no login in the identity reply")
}
