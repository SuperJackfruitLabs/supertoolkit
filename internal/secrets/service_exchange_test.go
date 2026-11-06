package secrets

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// toServer sends every request to one test server, keeping the original host
// so the handler can tell the issuer from the API.
type toServer struct{ target *url.URL }

func (t toServer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Original-Host", r.URL.Host)
	r.URL.Scheme, r.URL.Host = t.target.Scheme, t.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

// The publisher's SuperPipeline credentials are Organization-plane service
// credentials. A stored one must reach only the plane's exchange, for
// SuperPipeline's audience; the API must see only the token it returns. A
// stored token sent straight to the API (the previous AuthToken shape) would
// never be accepted, and would put the long-lived secret on the wire.
func TestApprovalCredentialsAreExchangedAtThePlaneBeforeTheAPI(t *testing.T) {
	stored := "svc_" + "ZZstoredZZ:ZZsecretZZ" // a fixture, not a credential
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Original-Host")+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		mu.Unlock()
		if r.Header.Get("X-Original-Host") == "accounts.superjackfruit.com" && r.URL.Path == "/api/token/service" {
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["audience"] != "https://app.superpipeline.dev" || r.Header.Get("Authorization") != "Bearer "+stored {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"ZZplaneJWTZZ","token_type":"Bearer","expires_in":300}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: toServer{target}}

	cfg, err := policy.Parse("test.yaml", []byte("services:\n  superpipeline-approvals-read: {}\n  superpipeline-approvals-write: {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(t.TempDir(), "test-passphrase")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"superpipeline-approvals-read", "superpipeline-approvals-write"} {
		if err := store.Put(name, stored); err != nil {
			t.Fatal(err)
		}
	}
	acqs := NewAcquirers(cfg, store, client)
	for _, name := range []string{"superpipeline-approvals-read", "superpipeline-approvals-write"} {
		svc, _ := cfg.Service(name)
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://app.superpipeline.dev/v1/boards/b/approval-subjects/s/verify", nil)
		if err := Authorize(context.Background(), name, svc.Entry(), req, store, acqs); err != nil {
			t.Fatalf("%s: Authorize: %v", name, err)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer ZZplaneJWTZZ" {
			t.Errorf("%s: API Authorization = %q, want the exchanged token", name, got)
		}
		if strings.Contains(req.Header.Get("Authorization"), "ZZsecretZZ") {
			t.Errorf("%s: the stored credential would reach the API", name)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range seen {
		if !strings.HasPrefix(s, "accounts.superjackfruit.com /api/token/service ") {
			t.Errorf("the stored credential went somewhere other than the exchange: %q", s)
		}
	}
	if len(seen) == 0 {
		t.Error("no exchange happened")
	}
}
