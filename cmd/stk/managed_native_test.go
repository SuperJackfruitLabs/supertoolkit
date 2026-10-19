package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedmcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

func managedFixture(t *testing.T, policyText string, reply func(managedmcp.OwnerRequest) managedmcp.OwnerReply) *managedmcp.Admission {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "stk-managed-")
	if err != nil {
		t.Fatal(err)
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	for _, sub := range []string{"workspace", "store", "state"} {
		if err = os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	policyPath := filepath.Join(dir, "policy.yaml")
	passPath := filepath.Join(dir, "pass")
	if err = os.WriteFile(policyPath, []byte(policyText), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(passPath, []byte("fixture-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "owner.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(socket, 0600); err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("e", 64)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/managed-toolkit/v1/verify" || r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(403)
			return
		}
		var in managedmcp.OwnerRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(reply(in))
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	m := managedmcp.Manifest{Version: 1, RootDigest: strings.Repeat("a", 64), Workspace: filepath.Join(dir, "workspace"), PolicyPath: policyPath, PolicySHA256: hash([]byte(policyText)), StoreDir: filepath.Join(dir, "store"), PassphraseFile: passPath, StateDir: filepath.Join(dir, "state"), OwnerSocket: socket, OwnerKey: key}
	m.ProfileDigest = managedmcp.ProfileFingerprint(m.PolicySHA256, m.Profile)
	body, _ := json.Marshal(m)
	manifest := filepath.Join(dir, "manifest.json")
	if err = os.WriteFile(manifest, body, 0600); err != nil {
		t.Fatal(err)
	}
	a, err := managedmcp.Admit(manifest, hash(body))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func managedAllowed(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
	out := managedmcp.OwnerReply{Version: 1, Phase: r.Phase, RequestDigest: managedmcp.RequestFingerprint(r.Request), Decision: "allowed"}
	if r.Phase == "review" {
		out.DecisionID = "fixture-human-decision"
	}
	if r.Phase == "dispatch" {
		out.SendWithinMS = 5000
	}
	if r.Phase == "admit" || r.Phase == "dispatch" {
		out.AuthorityForMS = 60000
	}
	return out
}
func managedEngine(t *testing.T, a *managedmcp.Admission, server *httptest.Server) *managedNative {
	t.Helper()
	store, err := credential.OpenStore(a.Manifest.StoreDir, "fixture-only")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Put("github", "fixture_native_secret"); err != nil {
		t.Fatal(err)
	}
	engine, err := newManagedNative(a)
	if err != nil {
		t.Fatal(err)
	}
	// Trusted fixture transport redirects every catalogue destination to this
	// owned HTTP server. Production has no host rewrite or configurable client.
	client := managedNativeClient()
	base := client.Transport
	client.Transport = nativeRoundTrip(func(req *http.Request) (*http.Response, error) {
		owned := req.Clone(req.Context())
		owned.URL.Scheme = "http"
		owned.URL.Host = server.Listener.Addr().String()
		return base.RoundTrip(owned)
	})
	engine.client = client
	engine.live = newLive(engine.cfg, engine.store, client)
	return engine
}
func invocation(t *testing.T, s *managedNative, id, action string, args map[string]string) managedmcp.Request {
	t.Helper()
	r, err := s.request(id, "github", action, args, time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestManagedNativeActualPolicyHumanAnswerAndExactlyOneDispatchGrant(t *testing.T) {
	var reviewAllowed atomic.Bool
	var grants, admits, reviews, effects atomic.Int32
	a := managedFixture(t, "services:\n  github: {}\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		out := managedAllowed(r)
		switch r.Phase {
		case "review":
			reviews.Add(1)
			if !reviewAllowed.Load() {
				out.Decision = "pending"
				out.DecisionID = ""
			}
		case "dispatch":
			grants.Add(1)
		case "admit":
			admits.Add(1)
		}
		return out
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		effects.Add(1)
		if r.Method != "POST" || r.URL.Path != "/repos/o/r/issues" || r.Header.Get("Authorization") != "Bearer fixture_native_secret" {
			t.Error("wrong actual native effect")
		}
		w.WriteHeader(201)
		io.WriteString(w, `{"id":7,"echo":"fixture_native_secret"}`)
	}))
	defer api.Close()
	s := managedEngine(t, a, api)
	r := invocation(t, s, "write-1", "create_issue", map[string]string{"owner": "o", "repo": "r", "title": "reviewed fixture"})
	if !r.Approval {
		t.Fatal("write policy did not construct the human gate")
	}
	first, err := s.invoke(context.Background(), r)
	if err != nil || first.State != managedmcp.AwaitingDecision || effects.Load() != 0 || grants.Load() != 0 || admits.Load() != 0 {
		t.Fatal("pending human answer performed an effect")
	}
	forged := r
	forged.Approval = false
	if _, err = s.invoke(context.Background(), forged); err == nil {
		t.Fatal("caller replaced broker policy")
	}
	reviewAllowed.Store(true)
	result, err := s.invoke(context.Background(), r)
	if err != nil || result.State != managedmcp.Returned || grants.Load() != 1 || admits.Load() != 1 || effects.Load() != 1 || strings.Contains(result.Result, "fixture_native_secret") {
		t.Fatalf("owned execution failed: %#v %v", result, err)
	}
	for range 3 {
		same, err := s.invoke(context.Background(), r)
		if err != nil || same != result {
			t.Fatal("saved receipt changed")
		}
	}
	if grants.Load() != 1 || effects.Load() != 1 || reviews.Load() != 2 {
		t.Fatal("reconnect regranted or duplicated work")
	}
	changed := r
	changed.Args = map[string]string{"owner": "o", "repo": "r", "title": "changed"}
	if _, err = s.invoke(context.Background(), changed); err == nil || effects.Load() != 1 {
		t.Fatal("saved invocation accepted changed input")
	}
}

func TestManagedNativeFinalGrantFollowsActualCredentialExchange(t *testing.T) {
	var mu sync.Mutex
	order := []string{}
	var apiCalls atomic.Int32
	appendOrder := func(v string) { mu.Lock(); order = append(order, v); mu.Unlock() }
	a := managedFixture(t, "services:\n  google:\n    oauth2:\n      authorize_url: https://fixture.invalid/auth\n      token_url: https://fixture.invalid/token\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		appendOrder(r.Phase)
		out := managedAllowed(r)
		if r.Phase == "dispatch" {
			out.Decision = "denied"
			out.SendWithinMS = 0
			out.AuthorityForMS = 0
		}
		return out
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			appendOrder("actual-exchange")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture_short_lived_access", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		apiCalls.Add(1)
		io.WriteString(w, "{}")
	}))
	defer api.Close()
	s := managedEngine(t, a, api)
	if err := s.store.PutMaterial("google", credential.Material{credential.FieldClientID: "fixture-client", credential.FieldRefreshToken: "fixture-refresh"}); err != nil {
		t.Fatal(err)
	}
	r, err := s.request("oauth-1", "google", "get_values", map[string]string{"spreadsheet_id": "fixture", "range": "A1"}, time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.invoke(context.Background(), r)
	mu.Lock()
	got := strings.Join(order, ",")
	mu.Unlock()
	if err != nil || v.State != managedmcp.Denied || apiCalls.Load() != 0 || got != "admit,actual-exchange,dispatch" {
		t.Fatalf("stale grant around acquisition: %s %s %v", got, v.State, err)
	}
}

func TestManagedNativeRenewableCatalogueTokenUsesActualStoredGrant(t *testing.T) {
	var mu sync.Mutex
	order := []string{}
	add := func(v string) { mu.Lock(); order = append(order, v); mu.Unlock() }
	a := managedFixture(t, "services:\n  github:\n    oauth2:\n      authorize_url: https://fixture.invalid/auth\n      token_url: https://fixture.invalid/token\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply { add(r.Phase); return managedAllowed(r) })
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			add("actual-exchange")
			json.NewEncoder(w).Encode(map[string]any{"access_token": "fixture_renewable_access", "token_type": "Bearer", "expires_in": 3600})
			return
		}
		add("actual-api")
		if r.Header.Get("Authorization") != "Bearer fixture_renewable_access" {
			t.Error("catalogue token scheme ignored actual renewable stored material")
		}
		io.WriteString(w, `{"echo":"fixture_renewable_access"}`)
	}))
	defer api.Close()
	s := managedEngine(t, a, api)
	if err := s.store.PutMaterial("github", credential.Material{credential.FieldClientID: "fixture-client", credential.FieldRefreshToken: "fixture-refresh"}); err != nil {
		t.Fatal(err)
	}
	r := invocation(t, s, "renewable-1", "get_user", map[string]string{})
	v, err := s.invoke(context.Background(), r)
	mu.Lock()
	got := strings.Join(order, ",")
	mu.Unlock()
	if err != nil || v.State != managedmcp.Returned || got != "admit,actual-exchange,dispatch,actual-api" || strings.Contains(v.Result, "fixture_renewable_access") {
		t.Fatalf("renewable path lost its gate or redaction: %s %s %v", got, v.State, err)
	}
}

func TestManagedNativeHTTPErrorAndIncompleteResultAreNotVerifiedSuccess(t *testing.T) {
	for _, mode := range []string{"non2xx", "oversize", "lost"} {
		t.Run(mode, func(t *testing.T) {
			var effects, grants atomic.Int32
			a := managedFixture(t, "services:\n  github: {}\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
				if r.Phase == "dispatch" {
					grants.Add(1)
				}
				return managedAllowed(r)
			})
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				effects.Add(1)
				if mode == "lost" {
					conn, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					conn.Close()
					return
				}
				if mode == "non2xx" {
					w.WriteHeader(403)
					io.WriteString(w, `{"error":"fixture_native_secret"}`)
				} else {
					io.WriteString(w, strings.Repeat("x", 192*1024+1))
				}
			}))
			defer api.Close()
			s := managedEngine(t, a, api)
			r := invocation(t, s, "read-1", "get_user", map[string]string{})
			v, err := s.invoke(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "non2xx" {
				var result managedResult
				if v.State != managedmcp.Returned || json.Unmarshal([]byte(v.Result), &result) != nil || !result.IsError || result.Status != 403 {
					t.Fatal("HTTP failure appeared successful")
				}
			} else if v.State != managedmcp.OutcomeUnknown || v.Result != "" {
				t.Fatal("partial result claimed completion")
			}
			same, err := s.invoke(context.Background(), r)
			if err != nil || same != v || effects.Load() != 1 || grants.Load() != 1 {
				t.Fatal("uncertain/returned work was replayed")
			}
		})
	}
}

func TestManagedProfilesRejectFrontedAndUnsupportedNativePaths(t *testing.T) {
	for _, body := range []string{
		"services:\n  stripe: {}\n",
		"services:\n  internal-forge:\n    kind: forge\n    provider: github\n    host: example.com\n    repositories: [o/r]\n",
		"servers:\n  fixture:\n    command: arbitrary-command\n    host: example.com\n    env_var: FIXTURE_TOKEN\n",
	} {
		t.Run(body, func(t *testing.T) {
			if _, err := policy.Parse("fixture", []byte(body)); err != nil {
				t.Fatal("negative fixture is not a valid standalone policy", err)
			}
			a := managedFixture(t, body, managedAllowed)
			if _, err := newManagedNative(a); err == nil {
				t.Fatal("unproved broker path became a managed capability")
			}
		})
	}
}

func TestManagedNativeAuthorityExpiryAbortsActualAPIIndependentlyOfRequestExpiry(t *testing.T) {
	accepted, closed := make(chan struct{}), make(chan struct{})
	var effects, grants atomic.Int32
	a := managedFixture(t, "services:\n  github: {}\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		out := managedAllowed(r)
		if r.Phase == "dispatch" {
			grants.Add(1)
			out.SendWithinMS = 2000
			out.AuthorityForMS = 2000
		}
		return out
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		effects.Add(1)
		io.Copy(io.Discard, r.Body)
		close(accepted)
		<-r.Context().Done()
		close(closed)
	}))
	defer api.Close()
	s := managedEngine(t, a, api)
	r := invocation(t, s, "authority-expiry", "get_user", map[string]string{})
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	result := make(chan managedmcp.Receipt, 1)
	go func() {
		defer close(finished)
		v, err := s.invoke(ctx, r)
		if err != nil {
			result <- managedmcp.Receipt{}
			return
		}
		result <- v
	}()
	defer func() { cancel(); <-finished }()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("actual API request was not admitted")
	}
	select {
	case v := <-result:
		if v.State != managedmcp.OutcomeUnknown {
			t.Fatalf("expired authority looked successful: %s", v.State)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request outlived its authority grant")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("local response resource did not close")
	}
	if time.Now().UnixMilli() >= r.ExpiresAtMS {
		t.Fatal("fixture only proved the original request timeout")
	}
	v, err := s.invoke(context.Background(), r)
	if err != nil || v.State != managedmcp.OutcomeUnknown || grants.Load() != 1 || effects.Load() != 1 {
		t.Fatal("expiry retried or regranted the uncertain request")
	}
}

func TestManagedNativeCredentialExchangeAlsoStopsAtItsIndependentAuthorityDeadline(t *testing.T) {
	accepted, closed := make(chan struct{}), make(chan struct{})
	var exchanges, grants, products atomic.Int32
	a := managedFixture(t, "services:\n  github:\n    oauth2:\n      authorize_url: https://fixture.invalid/auth\n      token_url: https://fixture.invalid/token\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		out := managedAllowed(r)
		if r.Phase == "admit" {
			out.AuthorityForMS = 2000
		}
		if r.Phase == "dispatch" {
			grants.Add(1)
		}
		return out
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			products.Add(1)
			io.WriteString(w, "{}")
			return
		}
		exchanges.Add(1)
		io.Copy(io.Discard, r.Body)
		close(accepted)
		<-r.Context().Done()
		close(closed)
	}))
	defer api.Close()
	s := managedEngine(t, a, api)
	if err := s.store.PutMaterial("github", credential.Material{credential.FieldClientID: "fixture-client", credential.FieldRefreshToken: "fixture-refresh"}); err != nil {
		t.Fatal(err)
	}
	r := invocation(t, s, "exchange-authority-expiry", "get_user", map[string]string{})
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan struct{})
	result := make(chan managedmcp.Receipt, 1)
	go func() {
		defer close(finished)
		v, err := s.invoke(ctx, r)
		if err != nil {
			result <- managedmcp.Receipt{}
			return
		}
		result <- v
	}()
	defer func() { cancel(); <-finished }()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("credential exchange did not start")
	}
	select {
	case v := <-result:
		if v.State != managedmcp.Denied {
			t.Fatalf("expired credential authority reached product dispatch: %s", v.State)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("credential exchange outlived authority")
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("credential exchange resource did not close")
	}
	if exchanges.Load() != 1 || grants.Load() != 0 || products.Load() != 0 || time.Now().UnixMilli() >= r.ExpiresAtMS {
		t.Fatal("wrong boundary or request expiry proved")
	}
}
