package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcpserve"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

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

func (m *memLedger) entries() []ledger.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ledger.Entry(nil), m.es...)
}

const servePublic = "93.184.215.14"

type serveRig struct {
	call       func(tool string, args map[string]string) (string, bool)
	b          *broker.Broker
	led        *memLedger
	secretHits *atomic.Int64
	secretAddr string
}

// newServeRig runs the real `stk mcp serve` machinery — launchFronted, the MCP
// server, a real broker — over a real child process, with only DNS and the
// public origin faked so the test needs no internet.
func newServeRig(t *testing.T, network string) *serveRig {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("network modes other than host are Linux-only")
	}
	bin := filepath.Join(t.TempDir(), "fetchserver")
	if out, err := exec.Command("go", "build", "-o", bin, "../../testdata/fetchserver").CombinedOutput(); err != nil {
		t.Fatalf("building the fixture: %v %s", err, out)
	}
	rig := &serveRig{secretHits: &atomic.Int64{}, led: &memLedger{}}
	secretLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go (&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.secretHits.Add(1)
		io.WriteString(w, "internal")
	})}).Serve(secretLn)
	t.Cleanup(func() { secretLn.Close() })
	rig.secretAddr = secretLn.Addr().String()

	originCA, _ := broker.NewCA("origin", time.Hour)
	leaf, _ := originCA.LeafForTest("public.test")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "public %s %s", r.Method, r.URL.Path) })
	mux.HandleFunc("/to-loopback", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+rig.secretAddr+"/", http.StatusFound)
	})
	originLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go (&http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}}}).ServeTLS(originLn, "", "")
	t.Cleanup(func() { originLn.Close() })

	cfg, err := policy.Parse("t.yaml", []byte(`
workspace: t
servers:
  fetch:
    command: `+bin+`
    network: `+network+`
    egress: { preset: public-only, schemes: [https, http], methods: [GET] }
    capabilities: { fetch: agent, direct: agent }
`))
	if err != nil {
		t.Fatal(err)
	}
	brokerCA, _ := broker.NewCA("broker", time.Hour)
	b, err := broker.New(broker.Options{
		Config: cfg, CA: brokerCA, Secrets: func(string) (string, error) { return "", fmt.Errorf("none") },
		Upstream: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: originCA.Pool()}},
		Resolve: func(_ context.Context, host string) ([]netip.Addr, error) {
			if host == "public.test" {
				return []netip.Addr{netip.MustParseAddr(servePublic)}, nil
			}
			return nil, fmt.Errorf("no such host")
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == servePublic+":443" {
				addr = originLn.Addr().String()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pln, _ := net.Listen("tcp", "127.0.0.1:0")
	go b.Serve(pln)
	t.Cleanup(func() { pln.Close() })
	rig.b = b

	srv, _ := cfg.Server("fetch")
	gate := &mcpserve.Local{Config: func() *policy.Config { return cfg }, Server: "fetch", Caller: "test", Ledger: rig.led}
	spec := serveSpec{Command: srv.Command, Network: srv.Network, ProxyAddr: pln.Addr().String(), CAPEM: string(brokerCA.CertPEM())}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	host, cleanup, err := launchFronted(ctx, "fetch", spec, func(remote string) { rig.led.Append(violationEntry("fetch", "test", remote)) })
	if err != nil && network == policy.NetworkConfined && os.Getenv("STK_REQUIRE_USERNS") == "" &&
		strings.Contains(err.Error(), "cannot confine") {
		t.Skipf("namespaces unavailable here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ms := &mcpserve.Server{Name: "fetch", Version: "test", Child: host, Gate: gate}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go ms.Serve(ctx, inR, outW)
	t.Cleanup(func() { inW.Close() })
	rd := bufio.NewReader(outR)
	id := 0
	rig.call = func(tool string, args map[string]string) (string, bool) {
		id++
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": "tools/call",
			"params": map[string]any{"name": tool, "arguments": args}})
		inW.Write(append(b, '\n'))
		line, err := rd.ReadBytes('\n')
		if err != nil {
			t.Fatal(err)
		}
		var resp struct {
			Result struct {
				Content []struct{ Text string }
				IsError bool
			}
		}
		json.Unmarshal(line, &resp)
		var txt string
		for _, c := range resp.Result.Content {
			txt += c.Text
		}
		return txt, resp.Result.IsError
	}
	return rig
}

func (r *serveRig) lastEgress(t *testing.T) broker.Record {
	t.Helper()
	a := r.b.Audit()
	for i := len(a) - 1; i >= 0; i-- {
		if a[i].Kind == broker.KindEgress {
			return a[i]
		}
	}
	t.Fatal("no egress record")
	return broker.Record{}
}

func TestMCPServeFetchIsDecidedAtTheToolAndTheWire(t *testing.T) {
	rig := newServeRig(t, policy.NetworkWatched)

	txt, isErr := rig.call("fetch", map[string]string{"url": "https://public.test/hello"})
	if isErr || txt != "200 public GET /hello" {
		t.Fatalf("public fetch: %q %v", txt, isErr)
	}
	if e := rig.lastEgress(t); e.Rule != "egress:public-only" || e.Service != "fetch" || e.Path != "/hello" {
		t.Errorf("egress record %+v", e)
	}
	es := rig.led.entries()
	if len(es) != 2 || es[0].Rule != "server:fetch/capabilities.fetch" || es[0].Outcome != "allowed" || es[1].Outcome != "completed" {
		t.Errorf("tool audit %+v", es)
	}

	for url, rule := range map[string]string{
		"http://169.254.169.254/": "egress:public-only/link-local",
		"http://100.78.52.87/":    "egress:public-only/cgnat",
		"https://10.1.2.3/":       "egress:public-only/private",
	} {
		txt, _ := rig.call("fetch", map[string]string{"url": url})
		// Plain http shows the broker's 403; https shows the refused CONNECT.
		if !strings.HasPrefix(txt, "403") && !strings.HasSuffix(txt, "Forbidden") {
			t.Errorf("%s: %q, want the broker's 403", url, txt)
		}
		if e := rig.lastEgress(t); e.Rule != rule {
			t.Errorf("%s: egress record %+v, want %s", url, e, rule)
		}
	}
	if n := rig.secretHits.Load(); n != 0 {
		t.Fatalf("the internal service was reached %d times", n)
	}
}

// A measured finding, kept as a test: Go's ProxyFromEnvironment never proxies
// a request for localhost or a loopback address, so a Go client fetching
// http://127.0.0.1/ — or following a redirect there — goes direct and the
// broker never sees it. On a watched child that is caught and the child is
// stopped; only a confined child cannot reach it at all.
func TestMCPServeLoopbackBypassByAGoClientIsCaughtWhenWatched(t *testing.T) {
	for _, url := range []string{"https://public.test/to-loopback", "http://127.0.0.1:%s/"} {
		rig := newServeRig(t, policy.NetworkWatched)
		if strings.Contains(url, "%s") {
			_, port, _ := net.SplitHostPort(rig.secretAddr)
			url = fmt.Sprintf(url, port)
		}
		rig.call("fetch", map[string]string{"url": url})
		deadline := time.Now().Add(3 * time.Second)
		caught := false
		for time.Now().Before(deadline) && !caught {
			for _, e := range rig.led.entries() {
				caught = caught || (e.Rule == "netwatch:direct" && e.Addr == rig.secretAddr)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !caught {
			t.Fatalf("%s: the direct connection was not caught: %+v", url, rig.led.entries())
		}
	}
}

func TestMCPServeWatchedChildThatBypassesIsCaughtAndStopped(t *testing.T) {
	rig := newServeRig(t, policy.NetworkWatched)
	// The child connects to the internal service directly, ignoring the proxy.
	// Watching cannot prevent that connection; it must see it, record it, and
	// stop the child.
	rig.call("direct", map[string]string{"addr": rig.secretAddr})
	deadline := time.Now().Add(3 * time.Second)
	var found *ledger.Entry
	for time.Now().Before(deadline) && found == nil {
		for _, e := range rig.led.entries() {
			if e.Rule == "netwatch:direct" {
				e := e
				found = &e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if found == nil || found.Addr != rig.secretAddr {
		t.Fatalf("the bypass was not recorded: %+v", rig.led.entries())
	}
	txt, isErr := rig.call("fetch", map[string]string{"url": "https://public.test/after"})
	if !isErr || !strings.Contains(txt, "stopped") {
		t.Fatalf("a stopped child still answered: %q", txt)
	}
}

func TestMCPServeConfinedRefusesWhenItCannotConfine(t *testing.T) {
	// Where namespaces are unavailable, a server declared confined must not
	// start at all; elsewhere, its direct connection must fail.
	rig := newServeRig(t, policy.NetworkConfined)
	txt, isErr := rig.call("direct", map[string]string{"addr": rig.secretAddr})
	if !isErr || rig.secretHits.Load() != 0 {
		t.Fatalf("a confined child connected directly: %q", txt)
	}
	if txt, isErr := rig.call("fetch", map[string]string{"url": "https://public.test/in"}); isErr || txt != "200 public GET /in" {
		t.Fatalf("a confined child could not use the broker: %q", txt)
	}
}
