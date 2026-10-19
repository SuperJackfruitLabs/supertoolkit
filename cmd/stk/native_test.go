package main

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

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

type nativeRoundTrip func(*http.Request) (*http.Response, error)

func (fn nativeRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

func nativeRig(t *testing.T, client *http.Client) (*liveConfig, *credential.Store, observer) {
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
	live := newLive(cfg, store, client)
	obs, err := newObserverLive(live, dir, "managed-fixture")
	if err != nil {
		t.Fatal(err)
	}
	return live, store, obs
}

func TestNativePrepareDoesNotDispatchAndOwnedSendIsConsumedOnce(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: nativeRoundTrip(func(req *http.Request) (*http.Response, error) {
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
	prepared, err := prepareNative(ctx, live, store, client, obs, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || req.Header.Get("Authorization") != "" {
		t.Fatal("prepare dispatched or leaked injection into caller")
	}
	req.URL.Host = "unadmitted.invalid"
	req.Header.Set("Authorization", "changed")
	resp, err := prepared.send()
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err = prepared.send(); err == nil || calls.Load() != 1 {
		t.Fatal("owned request sent twice")
	}
	other, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	prepared, err = prepareNative(ctx, live, store, client, obs, "github", other)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err = prepared.send(); err == nil || calls.Load() != 1 {
		t.Fatal("cancelled prepared request dispatched")
	}
}

func TestManagedNativeResponseRedactsBeforePersistenceAndMarksHTTPFailure(t *testing.T) {
	const secret = "native_fixture_secret<&/bytes"
	var injected string
	client := &http.Client{Transport: managedStatusTransport{nativeRoundTrip(func(req *http.Request) (*http.Response, error) {
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
	prepared, err := prepareNative(context.Background(), live, store, client, obs, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	result, err := prepared.managedResponse()
	if err != nil {
		t.Fatal(err)
	}
	var out managedResult
	if json.Unmarshal([]byte(result), &out) != nil || !out.IsError || out.Status != 403 || out.ProtocolResult != "returned" {
		t.Fatalf("HTTP failure looked successful: %s", result)
	}
	if injected != "Bearer "+secret || strings.Contains(result, secret) || !strings.Contains(out.Body, "[redacted]") {
		t.Fatal("actual injection or redaction missing")
	}
	if !strings.Contains(out.Body, "public-page=1") {
		t.Fatal("redaction changed public request parameters in the result")
	}
	rows, err := obs.led.Read(10)
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
	client := managedNativeClient()
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
	client := &http.Client{Transport: nativeRoundTrip(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 192*1024+1)))}, nil
	})}
	live, store, obs := nativeRig(t, client)
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	prepared, err := prepareNative(context.Background(), live, store, client, obs, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := prepared.managedResponse(); err == nil || result != "" {
		t.Fatal("truncated body became a successful result")
	}
}

func TestNativeExpiredSendGrantCannotReachActualAPI(t *testing.T) {
	var effects atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { effects.Add(1); io.WriteString(w, "{}") }))
	defer api.Close()
	client := managedNativeClient()
	live, store, obs := nativeRig(t, client)
	req, _ := http.NewRequest("GET", api.URL, nil)
	prepared, err := prepareNative(context.Background(), live, store, client, obs, "github", req)
	if err != nil {
		t.Fatal(err)
	}
	prepared.sendDeadline = time.Now().Add(-time.Second)
	if _, err = prepared.send(); err == nil || effects.Load() != 0 {
		t.Fatal("stale final grant reached API")
	}
}
