package mcpserve

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

type fakeChild struct {
	mu    sync.Mutex
	calls []string
}

const childTools = `[
 {"name":"fetch","description":"Fetches a URL","inputSchema":{"type":"object"},"title":"Fetch"},
 {"name":"danger","description":"rm -rf","inputSchema":{"type":"object"}},
 {"name":"unannotated","description":"?","inputSchema":{"type":"object"}},
 {"name":"reader","description":"reads","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}
]`

func (f *fakeChild) ToolsRaw(context.Context) ([]mcphost.Tool, []json.RawMessage, error) {
	var tools []mcphost.Tool
	var raws []json.RawMessage
	json.Unmarshal([]byte(childTools), &tools)
	json.Unmarshal([]byte(childTools), &raws)
	return tools, raws, nil
}

func (f *fakeChild) CallToolRaw(_ context.Context, name string, args json.RawMessage) (json.RawMessage, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+string(args))
	f.mu.Unlock()
	return json.RawMessage(`{"content":[{"type":"text","text":"done ` + name + `"}],"isError":false}`), nil
}

type memLedger struct {
	mu sync.Mutex
	es []ledger.Entry
}

func (m *memLedger) Append(e ledger.Entry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.es = append(m.es, e)
	return nil
}

const cfgBody = `
workspace: t
servers:
  fetch:
    command: x
    network: host
    egress: { preset: public-only }
    capabilities:
      fetch: agent
      danger: deny
profiles:
  narrow:
    fetch: [reader]
`

// session runs a server over pipes and returns a function that sends one
// request and returns its result or error.
func session(t *testing.T, profile string) (func(method string, params any) (json.RawMessage, *rpcError), *fakeChild, *memLedger) {
	t.Helper()
	cfg, err := policy.Parse("t.yaml", []byte(cfgBody))
	if err != nil {
		t.Fatal(err)
	}
	child, led := &fakeChild{}, &memLedger{}
	srv := &Server{Name: "fetch", Version: "test", Child: child,
		Gate: &Local{Config: func() *policy.Config { return cfg }, Profile: profile, Server: "fetch", Caller: "test", Ledger: led}}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go srv.Serve(context.Background(), inR, outW)
	t.Cleanup(func() { inW.Close() })
	rd := bufio.NewReader(outR)
	id := 0
	return func(method string, params any) (json.RawMessage, *rpcError) {
		id++
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		inW.Write(append(b, '\n'))
		line, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var resp struct {
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		json.Unmarshal(line, &resp)
		return resp.Result, resp.Error
	}, child, led
}

func TestListsOnlyAllowedToolsUnchanged(t *testing.T) {
	call, _, led := session(t, "")
	if res, err := call("initialize", map[string]any{"protocolVersion": "2025-03-26"}); err != nil || !strings.Contains(string(res), `"2025-03-26"`) {
		t.Fatalf("initialize: %s %v", res, err)
	}
	res, _ := call("tools/list", nil)
	var out struct{ Tools []map[string]any }
	json.Unmarshal(res, &out)
	var names []string
	for _, tl := range out.Tools {
		names = append(names, tl["name"].(string))
	}
	if strings.Join(names, ",") != "fetch,reader" {
		t.Fatalf("listed %v, want fetch,reader", names)
	}
	if out.Tools[0]["title"] != "Fetch" {
		t.Error("a field stk does not model was dropped from the tool")
	}
	if len(led.es) != 0 {
		t.Error("listing wrote audit rows")
	}
}

func TestEveryCallIsDecidedAndRecordedWithItsRule(t *testing.T) {
	call, child, led := session(t, "")
	cases := []struct {
		tool, rule string
		allowed    bool
	}{
		{"fetch", "server:fetch/capabilities.fetch", true},
		{"reader", "server:fetch/default.read-only-hint", true},
		{"danger", "server:fetch/capabilities.danger", false},
		{"unannotated", "server:fetch/default.unannotated", false},
		{"never-listed", "server:fetch/default.unannotated", false},
	}
	for _, c := range cases {
		led.es = nil
		res, rerr := call("tools/call", map[string]any{"name": c.tool, "arguments": map[string]any{"url": "https://example.com"}})
		if rerr != nil {
			t.Fatalf("%s: %v", c.tool, rerr)
		}
		var r struct{ IsError bool }
		json.Unmarshal(res, &r)
		if r.IsError == c.allowed {
			t.Errorf("%s: result %s", c.tool, res)
		}
		if len(led.es) == 0 || led.es[0].Rule != c.rule {
			t.Fatalf("%s: audit %+v, want rule %s", c.tool, led.es, c.rule)
		}
		e := led.es[0]
		if c.allowed && (e.Outcome != "allowed" || len(led.es) != 2 || led.es[1].Outcome != "completed") {
			t.Errorf("%s: allowed rows %+v", c.tool, led.es)
		}
		if !c.allowed && (e.Outcome != "403 denied: "+c.rule || len(led.es) != 1) {
			t.Errorf("%s: denied rows %+v", c.tool, led.es)
		}
		if !c.allowed && !strings.Contains(string(res), c.rule) {
			t.Errorf("%s: the refusal does not name its rule: %s", c.tool, res)
		}
	}
	// The child saw only the allowed calls, with the caller's arguments intact.
	if got := strings.Join(child.calls, "|"); got != `fetch {"url":"https://example.com"}|reader {"url":"https://example.com"}` {
		t.Fatalf("child calls %q", got)
	}
}

func TestProfileNarrowsDirectCalls(t *testing.T) {
	call, child, led := session(t, "narrow")
	res, _ := call("tools/call", map[string]any{"name": "fetch"})
	if !strings.Contains(string(res), "profile:narrow") || len(child.calls) != 0 {
		t.Fatalf("profile did not refuse: %s", res)
	}
	if led.es[0].Rule != "profile:narrow" {
		t.Fatalf("audit %+v", led.es)
	}
}
