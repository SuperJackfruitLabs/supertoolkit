package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedmcp"
)

type managedWireRig struct {
	in      *io.PipeWriter
	decoder *json.Decoder
	out     *io.PipeReader
	done    chan error
}

func managedWire(t *testing.T, engine *managedNative) *managedWireRig {
	t.Helper()
	in, write := io.Pipe()
	read, out := io.Pipe()
	rig := &managedWireRig{write, json.NewDecoder(read), read, make(chan error, 1)}
	s := &managedStdio{engine: engine}
	go func() { err := s.serve(context.Background(), in, out); out.Close(); rig.done <- err }()
	t.Cleanup(func() {
		write.Close()
		read.Close()
		in.Close()
		out.Close()
		select {
		case <-rig.done:
		case <-time.After(5 * time.Second):
			t.Error("managed wire did not stop")
		}
	})
	return rig
}
func (r *managedWireRig) send(t *testing.T, value any) {
	t.Helper()
	if err := json.NewEncoder(r.in).Encode(value); err != nil {
		t.Fatal(err)
	}
}
func (r *managedWireRig) read(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	type answer struct {
		value map[string]json.RawMessage
		err   error
	}
	done := make(chan answer, 1)
	go func() {
		var value map[string]json.RawMessage
		err := r.decoder.Decode(&value)
		done <- answer{value, err}
	}()
	select {
	case a := <-done:
		if a.err != nil {
			t.Fatal(a.err)
		}
		return a.value
	case <-time.After(5 * time.Second):
		t.Fatal("managed wire response deadline")
		return nil
	}
}
func wireCall(id int, name string, args any, r managedmcp.Request) any {
	return map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args, "_meta": map[string]any{"salaam.dev/toolkit": map[string]any{"version": 1, "invocation_id": r.InvocationID, "expires_at_ms": r.ExpiresAtMS}}}}
}
func initializeWire(t *testing.T, wire *managedWireRig) {
	t.Helper()
	wire.send(t, map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "fixture", "version": "1"}}})
	response := wire.read(t)
	if !strings.Contains(string(response["result"]), "supertoolkit-managed") {
		t.Fatal("unversioned legacy MCP served readiness")
	}
	if !strings.Contains(string(response["result"]), `"boundedGrants":true`) || !strings.Contains(string(response["result"]), `"nativeKinds":true`) {
		t.Fatal("managed owner requirements were not advertised")
	}
	wire.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
}

func TestVersionedManagedStdioCancellationIsDurableAndReconnectDoesNotReplay(t *testing.T) {
	accepted, closed := make(chan struct{}), make(chan struct{})
	var effects, grants atomic.Int32
	a := managedFixture(t, "services:\n  github: {}\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		if r.Phase == "dispatch" {
			grants.Add(1)
		}
		return managedAllowed(r)
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		effects.Add(1)
		io.Copy(io.Discard, r.Body)
		close(accepted)
		<-r.Context().Done()
		close(closed)
	}))
	defer api.Close()
	engine := managedEngine(t, a, api)
	r := invocation(t, engine, "wire-read-1", "get_user", map[string]string{})
	wire := managedWire(t, engine)
	initializeWire(t, wire)
	args := map[string]any{"category": "github", "action": "get_user", "args": map[string]string{}}
	wire.send(t, wireCall(1, "execute_action", args, r))
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("actual API not reached")
	}
	wire.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}})
	reply := wire.read(t)
	if !strings.Contains(string(reply["result"]), "outcome_unknown") || !strings.Contains(string(reply["result"]), `"isError":true`) {
		t.Fatalf("cancelled effect looked complete: %s", reply["result"])
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("local API response resource not observed closed")
	}
	wire.send(t, wireCall(2, "execute_action", args, r))
	reply = wire.read(t)
	if !strings.Contains(string(reply["result"]), "outcome_unknown") || effects.Load() != 1 || grants.Load() != 1 {
		t.Fatal("saved uncertain work replayed after reconnect")
	}
}

func TestVersionedManagedStdioProgressiveCatalogAndFailureSemantics(t *testing.T) {
	a := managedFixture(t, "services:\n  github: {}\n", managedAllowed)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":"fixture_native_secret"}`)
	}))
	defer api.Close()
	engine := managedEngine(t, a, api)
	wire := managedWire(t, engine)
	initializeWire(t, wire)
	wire.send(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
	list := wire.read(t)
	var catalog struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if json.Unmarshal(list["result"], &catalog) != nil || len(catalog.Tools) != 4 {
		t.Fatal("managed catalogue was not the closed four meta-tools")
	}
	r := invocation(t, engine, "wire-failure", "get_user", map[string]string{})
	wire.send(t, wireCall(2, "execute_action", map[string]any{"category": "github", "action": "get_user", "args": map[string]string{}}, r))
	reply := wire.read(t)
	text := string(reply["result"])
	if !strings.Contains(text, `"isError":true`) || !strings.Contains(text, "returned") || strings.Contains(text, "fixture_native_secret") {
		t.Fatalf("failure/credential disclosure in protocol: %s", text)
	}
}

func TestVersionedManagedStdioCancelDuringHumanReviewReturnsCurrentReceipt(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	a := managedFixture(t, "services:\n  github: {}\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		if r.Phase != "review" {
			t.Error("unreviewed invocation reached native admission")
		}
		close(entered)
		<-release
		return managedAllowed(r)
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("cancelled review dispatched API") }))
	defer api.Close()
	engine := managedEngine(t, a, api)
	wire := managedWire(t, engine)
	initializeWire(t, wire)
	r := invocation(t, engine, "wire-review-cancel", "create_issue", map[string]string{"owner": "o", "repo": "r", "title": "fixture"})
	wire.send(t, wireCall(1, "execute_action", map[string]any{"category": "github", "action": "create_issue", "args": r.Args}, r))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("private review was not reached")
	}
	wire.send(t, map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}})
	reply := wire.read(t)
	if !strings.Contains(string(reply["result"]), "cancelled") || !strings.Contains(string(reply["result"]), `"isError":true`) {
		t.Fatalf("cancel reply retained stale pending state: %s", reply["result"])
	}
}

func TestVersionedManagedCommandRejectsLegacyOrUnknownFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"--profile", "default"}, {"--manifest", "/not-read", "--sha256", "bad", "--unbound"}, {"--sha256", "bad", "--manifest", "/not-read"}} {
		if err := cmdManagedMCP(args); err == nil || strings.Contains(err.Error(), "/not-read") {
			t.Fatal("entry point accepted flags or disclosed private paths")
		}
	}
}

func TestManagedNativeDiscoveryDistinguishesReadKindFromAgentApprovalPolicy(t *testing.T) {
	a := managedFixture(t, "services:\n  github:\n    capabilities:\n      create_issue: agent\n", func(r managedmcp.OwnerRequest) managedmcp.OwnerReply {
		t.Error("discovery asked for an effect grant")
		return managedAllowed(r)
	})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("discovery dispatched an API effect") }))
	defer api.Close()
	engine := managedEngine(t, a, api)
	wire := managedWire(t, engine)
	initializeWire(t, wire)
	wire.send(t, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "get_action_details", "arguments": map[string]string{"category": "github", "action": "create_issue"}}})
	reply := wire.read(t)
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if json.Unmarshal(reply["result"], &result) != nil || len(result.Content) != 1 {
		t.Fatal("missing action details")
	}
	var details struct {
		Kind   string `json:"kind"`
		Policy string `json:"policy"`
	}
	if json.Unmarshal([]byte(result.Content[0].Text), &details) != nil || details.Kind != "write" || details.Policy != "agent" {
		t.Fatal("non-approval write was falsely classified as read-only")
	}
}
