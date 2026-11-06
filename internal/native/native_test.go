package native

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/audit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/clitest"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func nativeRig(t *testing.T, client *http.Client) (*livepolicy.Config, *credential.Store, audit.Observer) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(file, []byte("services:\n  github: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(dir, "fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Put("github", "native_fixture_secret<&/bytes"); err != nil {
		t.Fatal(err)
	}
	live := livepolicy.New(cfg, store, client)
	obs, err := audit.NewObserverLive(live, dir, "managed-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return live, store, obs
}

func TestPrepareRefusesNativeOnlyServiceForNonPublisherCaller(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(file, []byte("services:\n  superpipeline-approvals-read: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(dir, "fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("superpipeline-approvals-read", "native-only-fixture"); err != nil {
		t.Fatal(err)
	}
	// Preparing may acquire a credential (the plane exchange) but never sends
	// the API request; a refused caller must cause no traffic at all.
	exchanges := 0
	client := &http.Client{Transport: clitest.RoundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "accounts.superjackfruit.com" && r.URL.Path == "/api/token/service" {
			exchanges++
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
				Body: io.NopCloser(strings.NewReader(`{"access_token":"fixture-plane-token","expires_in":300}`)), Request: r}, nil
		}
		t.Fatalf("native-only request was dispatched to %s", r.URL)
		return nil, nil
	})}
	live := livepolicy.New(cfg, store, client)
	obs, err := audit.NewObserverLive(live, dir, "native-only-fixture")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "https://app.superpipeline.dev/v1/boards/brd_fixture/approval-subjects/aps_fixture/verify", nil)
	spoofedAudit := context.WithValue(context.Background(), audit.CallerKey{}, "publish")
	prepared, err := Prepare(spoofedAudit, live, store, client, obs, testVersion, "superpipeline-approvals-read", req)
	if err == nil || prepared != nil || !strings.Contains(err.Error(), "reserved for the publisher") {
		t.Fatalf("Prepare with spoofed audit caller = %#v, %v; want refusal", prepared, err)
	}
	if exchanges != 0 {
		t.Fatalf("a refused caller caused %d exchange(s)", exchanges)
	}
	prepared, err = Prepare(PublisherContext(context.Background()), live, store, client, obs, testVersion, "superpipeline-approvals-read", req)
	if err != nil || prepared == nil {
		t.Fatalf("Prepare with private publisher authority = %#v, %v; want admitted", prepared, err)
	}
	if got := prepared.Req.Header.Get("Authorization"); got != "Bearer fixture-plane-token" {
		t.Errorf("prepared Authorization = %q, want the exchanged token", got)
	}
}

func TestNativePrepareDoesNotDispatchAndOwnedSendIsConsumedOnce(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: clitest.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		if req.URL.Host != "api.github.com" || req.Header.Get("Authorization") != "Bearer native_fixture_secret<&/bytes" {
			t.Error("prepared destination or credential changed")
		}
		return &http.Response{StatusCode: 200, Status: "200 OK", Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})}
	live, store, obs := nativeRig(t, client)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prepared, err := Prepare(ctx, live, store, client, obs, testVersion, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || req.Header.Get("Authorization") != "" {
		t.Fatal("prepare dispatched or leaked injection into caller")
	}
	req.URL.Host = "unadmitted.invalid"
	req.Header.Set("Authorization", "changed")
	resp, err := prepared.Send()
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err = prepared.Send(); err == nil || calls.Load() != 1 {
		t.Fatal("owned request sent twice")
	}
	other, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	prepared, err = Prepare(ctx, live, store, client, obs, testVersion, "github", other)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = prepared.Send(); err == nil || calls.Load() != 1 {
		t.Fatal("cancelled prepared request dispatched")
	}
}

func TestManagedNativeResponseRedactsBeforePersistenceAndMarksHTTPFailure(t *testing.T) {
	const secret = "native_fixture_secret<&/bytes"
	var injected string
	client := &http.Client{Transport: managedStatusTransport{clitest.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		injected = req.Header.Get("Authorization")
		if req.GetBody != nil || req.Header.Get("Accept-Encoding") != "identity" {
			t.Error("replay or opaque response allowed")
		}
		encoded, _ := json.Marshal(secret)
		return &http.Response{StatusCode: 403, Status: "403 " + secret, Header: http.Header{"X-Secret": []string{secret}},
			Body: io.NopCloser(strings.NewReader(secret + " " + base64.StdEncoding.EncodeToString([]byte(secret)) + " " + url.QueryEscape(secret) + " " + string(encoded) + " public-page=1"))}, nil
	})}}
	live, store, obs := nativeRig(t, client)
	req, _ := http.NewRequest("GET", "https://api.github.com/user?page=1", nil)
	prepared, err := Prepare(context.Background(), live, store, client, obs, testVersion, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prepared.ManagedResponse()
	if err != nil {
		t.Fatal(err)
	}
	var out ManagedResult
	if json.Unmarshal([]byte(result), &out) != nil || !out.IsError || out.Status != 403 || out.ProtocolResult != "returned" {
		t.Fatalf("HTTP failure looked successful: %s", result)
	}
	if injected != "Bearer "+secret || strings.Contains(result, secret) || !strings.Contains(out.Body, "[redacted]") {
		t.Fatal("actual injection or redaction missing")
	}
	if !strings.Contains(out.Body, "public-page=1") {
		t.Fatal("redaction changed public request parameters in the result")
	}
	rows, err := obs.Led.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(rows)
	if len(rows) != 1 || strings.Contains(string(data), secret) || !strings.Contains(string(data), "403 Forbidden") {
		t.Fatalf("audit did not retain safe failure: %s", data)
	}
}

func TestManagedNativeClientRefusesRedirectWithoutForwarding(t *testing.T) {
	var forwards atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwards.Add(1) }))
	defer target.Close()
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer entry.Close()
	client := ManagedClient()
	req, _ := http.NewRequest("POST", entry.URL, strings.NewReader("effect"))
	req.Header.Set("Authorization", "synthetic-only")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 307 || forwards.Load() != 0 {
		t.Fatal("redirect forwarded the credential/effect")
	}
}

func TestManagedNativeIncompleteResponseIsUnknown(t *testing.T) {
	client := &http.Client{Transport: clitest.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 192*1024+1)))}, nil
	})}
	live, store, obs := nativeRig(t, client)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	prepared, err := Prepare(context.Background(), live, store, client, obs, testVersion, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := prepared.ManagedResponse(); err == nil || result != "" {
		t.Fatal("truncated body became a successful result")
	}
}

func TestNativeExpiredSendGrantCannotReachActualAPI(t *testing.T) {
	var effects atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects.Add(1); io.WriteString(w, "{}") }))
	defer api.Close()
	client := ManagedClient()
	live, store, obs := nativeRig(t, client)
	req, _ := http.NewRequest("GET", api.URL, nil)
	prepared, err := Prepare(context.Background(), live, store, client, obs, testVersion, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	prepared.SendDeadline = time.Now().Add(-time.Second)
	if _, err = prepared.Send(); err == nil || effects.Load() != 0 {
		t.Fatal("stale final grant reached API")
	}
}

// testVersion stands in for the version main stamps into the binary.
const testVersion = "0.0.1-dev"
