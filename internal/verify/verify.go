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
	"net/url"
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
	ReasonServerError   = "server-error"
	ReasonRedirect      = "redirect"
	ReasonWrongIdentity = "wrong-identity"
	ReasonUnsupported   = "unsupported"
	// ReasonRepositoryMissing: an app installation does not cover a configured
	// repository.
	ReasonRepositoryMissing = "repository-missing"
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
	// BaseURL replaces https://<Entry.Host>, or Forge.APIBase for an app grant.
	// For tests.
	BaseURL string
	// App supplies the two credentials a GitHub App grant verifies with.
	App *AppInput
}

// AppInput supplies an app grant's credentials lazily, so a failure to mint
// one is a reason and no credential is held longer than a call needs it.
type AppInput struct {
	JWT               func() (string, error)
	InstallationToken func() (string, error)
}

// maxBody bounds how much of a provider's reply is read.
const maxBody = 1 << 20

// Run calls the provider's identity endpoint with the credential.
func Run(ctx context.Context, in Input) Result {
	e := in.Entry
	if e == nil || e.Forge == nil {
		return Result{Reason: ReasonUnsupported}
	}
	if e.Auth == catalog.AuthGitHubApp {
		return verifyApp(ctx, in)
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
	case resp.StatusCode >= 500:
		return Result{Reason: ReasonServerError}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return Result{Reason: ReasonRedirect}
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

// maxRepoPages bounds how many pages of an installation's repositories are read.
const maxRepoPages = 20

// verifyApp verifies a GitHub App grant. An installation token cannot call /user,
// so identity comes from the App itself (GET /app, as the App's JWT) and
// coverage from the installation (GET /installation/repositories, as the
// installation token). Every failure is a fixed reason: no error text from a
// credential function or a provider is copied into the result.
func verifyApp(ctx context.Context, in Input) Result {
	e := in.Entry
	if in.App == nil || in.App.JWT == nil || in.App.InstallationToken == nil {
		return Result{Reason: ReasonUnsupported}
	}
	base := in.BaseURL
	if base == "" {
		base = e.Forge.APIBase
	}
	base = strings.TrimSuffix(base, "/")
	baseURL, err := url.Parse(base)
	if err != nil || baseURL.Host == "" {
		return Result{Reason: ReasonUnexpected}
	}
	base0 := in.HTTP
	if base0 == nil {
		base0 = &http.Client{Timeout: 15 * time.Second}
	}
	client := *base0
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	jwt, err := in.App.JWT()
	if err != nil || jwt == "" {
		return Result{Reason: ReasonUnauthorized}
	}
	body, _, reason := appGet(ctx, &client, base+"/app", jwt)
	if reason != "" {
		return Result{Reason: reason}
	}
	var app struct {
		Slug string `json:"slug"`
	}
	if json.Unmarshal(body, &app) != nil || app.Slug == "" {
		return Result{Reason: ReasonUnexpected}
	}
	login := app.Slug + "[bot]"
	if in.ExpectLogin != "" && !strings.EqualFold(login, in.ExpectLogin) {
		return Result{Login: login, Reason: ReasonWrongIdentity}
	}

	tok, err := in.App.InstallationToken()
	if err != nil || tok == "" {
		return Result{Login: login, Reason: ReasonUnauthorized}
	}
	want := map[string]bool{}
	for _, r := range e.Forge.Repositories {
		want[strings.ToLower(r)] = true
	}
	next := base + "/installation/repositories?per_page=100"
	for page := 0; page < maxRepoPages && next != "" && len(want) > 0; page++ {
		body, hdr, reason := appGet(ctx, &client, next, tok)
		if reason != "" {
			return Result{Login: login, Reason: reason}
		}
		var list struct {
			Repositories []struct {
				FullName string `json:"full_name"`
			} `json:"repositories"`
		}
		if json.Unmarshal(body, &list) != nil {
			return Result{Login: login, Reason: ReasonUnexpected}
		}
		for _, r := range list.Repositories {
			delete(want, strings.ToLower(r.FullName))
		}
		next = ""
		if n := nextLink(hdr.Values("Link")); n != "" && len(want) > 0 {
			u, err := baseURL.Parse(n)
			// The installation token goes wherever this points, so it must
			// point at the host the token was issued for.
			if err != nil || u.Scheme != baseURL.Scheme || !strings.EqualFold(u.Host, baseURL.Host) {
				return Result{Login: login, Reason: ReasonUnexpected}
			}
			next = u.String()
		}
	}
	if len(want) > 0 {
		return Result{Login: login, Reason: ReasonRepositoryMissing}
	}
	return Result{OK: true, Login: login}
}

// appGet makes one authenticated read and maps the status to a reason.
func appGet(ctx context.Context, client *http.Client, u, bearer string) ([]byte, http.Header, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, ReasonUnexpected
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, ReasonUnreachable
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, nil, ReasonUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		return nil, nil, ReasonForbidden
	case resp.StatusCode >= 500:
		return nil, nil, ReasonServerError
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, nil, ReasonRedirect
	case resp.StatusCode != http.StatusOK:
		return nil, nil, ReasonUnexpected
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, nil, ReasonUnreachable
	}
	return body, resp.Header, ""
}

// nextLink returns the rel="next" target of Link headers, or "".
func nextLink(values []string) string {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			target, params, ok := strings.Cut(part, ";")
			if !ok {
				continue
			}
			target = strings.TrimSpace(target)
			if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
				continue
			}
			for _, p := range strings.Split(params, ";") {
				if strings.ReplaceAll(strings.TrimSpace(p), " ", "") == `rel="next"` {
					return target[1 : len(target)-1]
				}
			}
		}
	}
	return ""
}
