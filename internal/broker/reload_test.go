package broker

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// setA allows GET issues (preset read) and denies DELETE (default deny).
var setA = forgeAt("    labels: {station: a}\n")

// setB is the reverse: GET issues denied by user#1, DELETE on the repo allowed.
var setB = forgeAt(`    labels: {station: b}
    rules:
      - deny: "GET /repos/{owner}/{repo}/issues"
      - allow: "DELETE /repos/{owner}/{repo}"
`)

// elsewhere moves the only forge service off the fixture's host.
const elsewhere = `
services:
  forge-other:
    kind: forge
    provider: github
    host: git.example.com
    auth: token
    scheme: bearer
    env_var: OTHER_TOKEN
    repositories: [acme/widgets]
    preset: read
`

func loadCfg(t testing.TB, body string) *policy.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "supertoolkit.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := policy.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// doOn makes one request with a chosen client, so a test can keep a tunnel
// open across a reload.
func doOn(t testing.TB, c *http.Client, method, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "https://api.github.com"+path, nil)
	req.Header.Set("Authorization", "Bearer "+Placeholder("forge-main"))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestReloadChangesRulesOnALiveBroker(t *testing.T) {
	for _, h1 := range []bool{false, true} {
		name := "h2"
		if h1 {
			name = "h1"
		}
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, setA)
			c := f.client(h1)
			if st, body := doOn(t, c, "GET", "/repos/acme/widgets/issues"); st != 200 {
				t.Fatalf("before: GET = %d %q, want 200", st, body)
			}
			if st, _ := doOn(t, c, "DELETE", "/repos/acme/widgets"); st != 403 {
				t.Fatalf("before: DELETE = %d, want 403", st)
			}
			connects := f.broker.Stats().Intercept

			if err := f.broker.Reload(loadCfg(t, setB)); err != nil {
				t.Fatal(err)
			}
			// The same client, on the tunnel it already holds.
			if st, body := doOn(t, c, "GET", "/repos/acme/widgets/issues"); st != 403 || !strings.Contains(body, "rule user#1 (") {
				t.Fatalf("after: GET = %d %q, want 403 by user#1", st, body)
			}
			if st, body := doOn(t, c, "DELETE", "/repos/acme/widgets"); st != 200 {
				t.Fatalf("after: DELETE = %d %q, want 200", st, body)
			}
			if got := f.broker.Stats().Intercept; got != connects {
				t.Fatalf("Intercept went %d -> %d: the requests did not reuse the open tunnel, so the test proves nothing about it", connects, got)
			}
			// A fresh tunnel sees the new rules too.
			if st, _ := doOn(t, f.client(h1), "GET", "/repos/acme/widgets/issues"); st != 403 {
				t.Fatalf("fresh tunnel after reload: GET = %d, want 403", st)
			}
			// And back again.
			if err := f.broker.Reload(loadCfg(t, setA)); err != nil {
				t.Fatal(err)
			}
			if st, _ := doOn(t, c, "GET", "/repos/acme/widgets/issues"); st != 200 {
				t.Fatalf("reloaded back: GET = %d, want 200", st)
			}
		})
	}
}

// Every request is decided wholly by one policy: its labels (from the
// snapshot) and its outcome (from that snapshot's rules) must agree.
func TestReloadIsAtomicForInFlightRequests(t *testing.T) {
	f := newFixture(t, setA)
	a, b := loadCfg(t, setA), loadCfg(t, setB)
	clients := []*http.Client{f.client(false), f.client(true), f.client(true)}

	var stop atomic.Bool
	var wg sync.WaitGroup
	var sent atomic.Int64
	for i := 0; i < 6; i++ {
		c := clients[i%len(clients)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				st, body := doOn(t, c, "GET", "/repos/acme/widgets/issues")
				sent.Add(1)
				if st != 200 && !(st == 403 && strings.Contains(body, "rule user#1 (")) {
					t.Errorf("response %d %q matches neither set", st, body)
				}
			}
		}()
	}
	// Reload continuously until enough requests have run through it.
	for i := 0; sent.Load() < 400 && !t.Failed(); i++ {
		cfg := a
		if i%2 == 0 {
			cfg = b
		}
		if err := f.broker.Reload(cfg); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
	}
	stop.Store(true)
	wg.Wait()

	recs := f.broker.Audit()
	if int64(len(recs)) != sent.Load() {
		t.Fatalf("%d records for %d responses", len(recs), sent.Load())
	}
	var seenA, seenB int
	for _, r := range recs {
		switch {
		case r.Labels["station"] == "a" && r.Rule == "" && strings.HasPrefix(r.Status, "200"):
			seenA++
		case r.Labels["station"] == "b" && r.Rule == "user#1" && r.Status == "403 denied: user#1":
			seenB++
		default:
			t.Errorf("record mixes the two policies: %+v", r)
		}
	}
	t.Logf("%d requests: %d under A, %d under B", len(recs), seenA, seenB)
}

func TestReloadRemovingAServiceStopsBrokeringItsHost(t *testing.T) {
	f := newFixture(t, setA)
	h2, h1 := f.client(false), f.client(true)
	for _, c := range []*http.Client{h2, h1} {
		if st, _ := doOn(t, c, "GET", "/repos/acme/widgets/issues"); st != 200 {
			t.Fatalf("before: %d", st)
		}
	}
	hits, secrets, connects := f.providerHits.Load(), f.secretCalls.Load(), f.broker.Stats().Intercept

	if err := f.broker.Reload(loadCfg(t, elsewhere)); err != nil {
		t.Fatal(err)
	}
	// The tunnels already open: the next request is refused, not forwarded.
	for i, c := range []*http.Client{h2, h1} {
		st, body := doOn(t, c, "GET", "/repos/acme/widgets/issues")
		if st != http.StatusForbidden || !strings.Contains(body, "no longer brokered") {
			t.Fatalf("client %d after removal: %d %q, want 403 naming the removal", i, st, body)
		}
	}
	if f.providerHits.Load() != hits || f.secretCalls.Load() != secrets {
		t.Fatalf("after removal the provider saw %d more request(s) and the secret was read %d more time(s)",
			f.providerHits.Load()-hits, f.secretCalls.Load()-secrets)
	}
	if got := f.broker.Stats().Intercept; got != connects {
		t.Fatalf("Intercept %d -> %d: the refusal was not on the open tunnel", connects, got)
	}
	recs := f.broker.Audit()
	if last := recs[len(recs)-1]; last.Service != "forge-main" || !strings.Contains(last.Status, "no longer brokered") {
		t.Errorf("last record = %+v", last)
	}
	// A new CONNECT is tunnelled blind: the client, trusting only the broker's
	// CA, now meets the provider's own certificate and fails.
	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	if resp, err := f.client(false).Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("a new tunnel to a removed service's host was still intercepted")
	}
	if st := f.broker.Stats(); st.Tunnel != 1 || st.Intercept != connects {
		t.Fatalf("Stats() = %+v, want one blind tunnel and no new interception", st)
	}
}

func TestReloadNilConfigErrors(t *testing.T) {
	f := newFixture(t, setA)
	if err := f.broker.Reload(nil); err == nil {
		t.Fatal("Reload(nil) = nil, want an error")
	}
	if st, _ := doOn(t, f.client(false), "GET", "/repos/acme/widgets/issues"); st != 200 {
		t.Fatalf("after a refused reload: GET = %d, want the old policy's 200", st)
	}
	if st, _ := doOn(t, f.client(false), "DELETE", "/repos/acme/widgets"); st != 403 {
		t.Fatalf("after a refused reload: DELETE = %d, want 403", st)
	}
}

func TestRecordCarriesTheServiceLabels(t *testing.T) {
	f := newFixture(t, setA)
	doOn(t, f.client(false), "GET", "/repos/acme/widgets/issues")
	doOn(t, f.client(false), "DELETE", "/repos/acme/widgets")
	for _, r := range f.broker.Audit() {
		if r.Labels["station"] != "a" {
			t.Errorf("record without labels: %+v", r)
		}
	}
}

func TestReloadHostReassignedToAnotherServiceIsRefusedOnAnOpenTunnel(t *testing.T) {
	f := newFixture(t, setA)
	c := f.client(false)
	if st, _ := doOn(t, c, "GET", "/repos/acme/widgets/issues"); st != 200 {
		t.Fatalf("before: %d", st)
	}
	hits, secrets, refused := f.providerHits.Load(), f.secretCalls.Load(), f.broker.Stats().Refused
	// The same host now belongs to a different service with its own credential.
	if err := f.broker.Reload(loadCfg(t, strings.Replace(setA, "forge-main:", "forge-b:", 1))); err != nil {
		t.Fatal(err)
	}
	st, body := doOn(t, c, "GET", "/repos/acme/widgets/issues")
	if st != http.StatusForbidden || !strings.Contains(body, "no longer brokered") {
		t.Fatalf("after reassignment: %d %q, want 403", st, body)
	}
	if f.providerHits.Load() != hits || f.secretCalls.Load() != secrets {
		t.Fatalf("provider +%d, secret source +%d, want 0 and 0",
			f.providerHits.Load()-hits, f.secretCalls.Load()-secrets)
	}
	if got := f.broker.Stats().Refused; got != refused+1 {
		t.Fatalf("Refused %d -> %d, want +1", refused, got)
	}
	recs := f.broker.Audit()
	if last := recs[len(recs)-1]; last.Service != "forge-main" || last.Status != "403 service no longer brokered" {
		t.Fatalf("last record = %+v", last)
	}
}
