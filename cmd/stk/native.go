package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
)

// preparedNative stays inside the broker. Preparing may acquire a credential;
// sending does not. Managed execution can therefore obtain its fresh owner
// grant AFTER acquisition, immediately before its durable dispatch marker.
// Legacy effects use the same credential and audit path, sending immediately.
type preparedNative struct {
	req      *http.Request
	client   *http.Client
	observer observer
	record   broker.Record
	entry    *catalog.Entry
	sent     atomic.Bool
}

func prepareNative(ctx context.Context, live *liveConfig, store *credential.Store, client *http.Client, obs observer, service string, req *http.Request) (*preparedNative, error) {
	st := live.state()
	svc, ok := st.cfg.Service(service)
	if !ok {
		return nil, errors.New("native service is unavailable")
	}
	acqs := st.acqs
	if acqs == nil {
		acqs = newAcquirers(st.cfg, store, client)
	}
	// Clone URL and headers so the caller cannot change the admitted destination
	// or injection after preparation. Managed callers also own a copied body.
	owned := req.Clone(ctx)
	if err := authorize(ctx, service, svc.Entry(), owned, store, acqs); err != nil {
		return nil, err
	}
	owned.Header.Set("User-Agent", "supertoolkit/"+version)
	if c, ok := ctx.Value(callerKey{}).(string); ok {
		obs.caller = c
	}
	rec := broker.Record{
		Service: service, Host: owned.URL.Host, Method: owned.Method, Path: owned.URL.Path,
		AuthzFP: fingerprint(owned.Header.Get("Authorization")), Labels: svc.Labels(),
	}
	if rec.AuthzFP != "(absent)" {
		rec.Injected = "Authorization header"
	}
	return &preparedNative{req: owned, client: client, observer: obs, record: rec, entry: svc.Entry()}, nil
}

func (p *preparedNative) send() (*http.Response, error) {
	if !p.sent.CompareAndSwap(false, true) {
		return nil, errors.New("native request already consumed")
	}
	if err := p.req.Context().Err(); err != nil {
		return nil, err
	}
	resp, err := p.client.Do(p.req)
	p.record.When = time.Now()
	p.record.Status = "request failed"
	if err == nil {
		p.record.Status = resp.Status
	}
	p.observer.Observe(p.record)
	return resp, err
}

// managedNativeClient owns its transport: no environment proxy, redirects,
// connection reuse, compression or replayable request bodies. The managed
// broker never falls back through the agent's egress configuration.
func managedNativeClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DisableKeepAlives = true
	tr.DisableCompression = true
	// HTTP/2 can retry streams after GOAWAY independently of HTTP/1 connection
	// reuse. Managed effects use one HTTP/1 connection and one dispatch only.
	tr.Protocols = new(http.Protocols)
	tr.Protocols.SetHTTP1(true)
	return &http.Client{Transport: managedStatusTransport{tr}, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// managedResult is a protocol outcome, never verification that a product effect
// succeeded. Non-2xx responses remain errors even though a response was received.
type managedResult struct {
	ProtocolResult string `json:"protocol_result"`
	IsError        bool   `json:"is_error"`
	Status         int    `json:"status"`
	Body           string `json:"body"`
}

// managedResponse reads a bounded complete body before any persistence or model
// output. It emits no upstream headers, trailers, status reason or raw errors.
// It redacts exact injected values and common encodings; it does not promise
// to defeat an upstream that deliberately transforms a secret arbitrarily.
func (p *preparedNative) managedResponse() (string, error) {
	// Requests are built from the reviewed native catalogue. Clearing GetBody
	// additionally denies the HTTP client's replay path, including for reads.
	p.req.GetBody = nil
	p.req.Header.Set("Accept-Encoding", "identity")
	resp, err := p.send()
	if err != nil {
		return "", errors.New("managed native outcome is unknown")
	}
	defer resp.Body.Close()
	if coding := resp.Header.Get("Content-Encoding"); coding != "" && coding != "identity" {
		return "", errors.New("managed native response encoding is unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 192*1024+1))
	if err != nil || len(body) > 192*1024 {
		return "", errors.New("managed native response is incomplete")
	}
	clean := string(body)
	for _, secret := range nativeSecrets(p.req, p.entry) {
		clean = strings.ReplaceAll(clean, secret, "[redacted]")
	}
	result, err := json.Marshal(managedResult{"returned", resp.StatusCode < 200 || resp.StatusCode >= 300, resp.StatusCode, clean})
	if err != nil || len(result) > 256*1024 {
		return "", errors.New("managed native result exceeds its bound")
	}
	return string(result), nil
}

func nativeSecrets(req *http.Request, entry *catalog.Entry) []string {
	values := []string{}
	// Values are taken from the actual injected request, not another store read
	// that might have rotated while this request was in flight.
	for key, entries := range req.Header {
		// Only actual authentication fields are sensitive. Public query/header
		// values such as page=1 must not corrupt ordinary API results.
		if !strings.EqualFold(key, "Authorization") && !strings.EqualFold(key, "X-Amz-Security-Token") && !(entry.Placement == catalog.APIKeyHeader && entry.Field != "" && strings.EqualFold(key, entry.Field)) {
			continue
		}
		for _, value := range entries {
			values = append(values, value)
			if strings.EqualFold(key, "Authorization") {
				_, token, ok := strings.Cut(value, " ")
				if ok {
					values = append(values, token)
				}
				if strings.HasPrefix(value, "Basic ") {
					if raw, err := base64.StdEncoding.DecodeString(token); err == nil {
						values = append(values, string(raw))
						if _, pass, ok := strings.Cut(string(raw), ":"); ok {
							values = append(values, pass)
						}
					}
				}
				if strings.HasPrefix(value, "AWS4-HMAC-SHA256 ") {
					for _, part := range strings.Split(token, ",") {
						name, field, ok := strings.Cut(strings.TrimSpace(part), "=")
						if ok && name == "Credential" {
							access, _, _ := strings.Cut(field, "/")
							values = append(values, access)
						}
						if ok && name == "Signature" {
							values = append(values, field)
						}
					}
				}
			}
		}
	}
	if entry.Placement == catalog.QueryParam && entry.Field != "" {
		values = append(values, req.URL.Query()[entry.Field]...)
	}
	set := map[string]bool{}
	for _, value := range values {
		if value == "" {
			continue
		}
		set[value] = true
		set[url.QueryEscape(value)] = true
		set[url.PathEscape(value)] = true
		set[base64.StdEncoding.EncodeToString([]byte(value))] = true
		set[base64.RawStdEncoding.EncodeToString([]byte(value))] = true
		set[base64.URLEncoding.EncodeToString([]byte(value))] = true
		set[base64.RawURLEncoding.EncodeToString([]byte(value))] = true
		if encoded, err := json.Marshal(value); err == nil {
			set[string(encoded[1:len(encoded)-1])] = true
		}
	}
	// Longest first prevents a short variant corrupting a longer encoded value.
	out := make([]string, 0, len(set))
	for value := range set {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) > len(out[j])
	})
	return out
}

// Do not allow an untrusted HTTP reason phrase into the audit record in managed
// mode. This RoundTripper wraps the actual owned transport, not agent input.
type managedStatusTransport struct{ inner http.RoundTripper }

func (t managedStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.inner.RoundTrip(req)
	if err == nil {
		resp.Status = strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode)
	}
	return resp, err
}
