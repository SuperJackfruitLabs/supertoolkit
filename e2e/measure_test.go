// The three roadmap items that read "untested" or "unproven".
//
// A measurement replaces an assumption or it is not worth taking. Each test
// here produces a number, and `docs/measurements.md` records it with the
// machine it came from — a benchmark without its machine is a rumour.
//
// Run with: go test ./e2e/ -run Measure -v
package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// measureRig is a broker in front of a local upstream, reachable by a Go client
// that trusts the broker. Deliberately not the `curl` rig: these measurements
// are about the broker's own behaviour, and a subprocess per request would
// drown the numbers in process startup.
type measureRig struct {
	client   *http.Client
	direct   *http.Client
	broker   *broker.Broker
	upstream string
}

func newMeasureRig(t *testing.T, handler http.Handler, clientAuth tls.ClientAuthType, clientCAs *x509.CertPool) *measureRig {
	t.Helper()

	provCA, err := broker.NewCA("measure provider CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := provCA.LeafForTest("api.github.com")
	if err != nil {
		t.Fatal(err)
	}
	provLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	prov := &http.Server{Handler: handler, TLSConfig: &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		ClientAuth:   clientAuth,
		ClientCAs:    clientCAs,
	}}
	go prov.ServeTLS(provLn, "", "")
	t.Cleanup(func() { prov.Close() })

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "supertoolkit.yaml")
	os.WriteFile(cfgPath, []byte("workspace: measure\nservices:\n  github:\n    scopes: []\n"), 0o600)
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	store, err := credential.OpenStore(filepath.Join(dir, "state"), "measure passphrase")
	if err != nil {
		t.Fatal(err)
	}
	store.Put("github", theSecret)

	ca, err := broker.NewCA("measure broker CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "api.github.com:443" {
			addr = provLn.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca, Secrets: store.Get,
		Upstream: &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: provCA.Pool()},
			DialContext:       dial,
			ForceAttemptHTTP2: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(proxyLn)
	t.Cleanup(func() { proxyLn.Close() })

	proxyURL, _ := urlParse("http://" + proxyLn.Addr().String())
	return &measureRig{
		broker:   b,
		upstream: provLn.Addr().String(),
		client: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				Proxy:           http.ProxyURL(proxyURL),
				TLSClientConfig: &tls.Config{RootCAs: ca.Pool()},
			},
		},
		// The same client without the proxy, pointed straight at the upstream.
		// This is the baseline the brokered number is compared against.
		direct: &http.Client{
			Timeout: 120 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: provCA.Pool()},
				DialContext:     dial,
			},
		},
	}
}

// --- 1. Bodies above 64 KB ---
//
// The roadmap called this "unproven rather than broken": the proxy was
// transparent at every size tested, but no endpoint ever accepted a large
// upload. X's media APPEND is multipart with segments up to 5 MB, so this is
// load-bearing for the marketing work rather than theoretical.
func TestMeasureLargeBodiesAreTransparent(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		n, err := io.Copy(h, r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		// Tab-separated: an Authorization header contains a space, and %s in
		// Sscanf stops at one — which made an earlier run of this test report
		// "Bearer" and claim the credential was wrong.
		fmt.Fprintf(w, "%d\t%s\t%s", n, hex.EncodeToString(h.Sum(nil)), r.Header.Get("Authorization"))
	})
	rig := newMeasureRig(t, echo, tls.NoClientCert, nil)

	sizes := []int{1, 64 << 10, 1 << 20, 8 << 20}
	t.Log("size        sent        received    sha256 match  credential")
	for _, size := range sizes {
		body := make([]byte, size)
		rand.Read(body)
		want := sha256.Sum256(body)

		req, _ := http.NewRequest("POST", "https://api.github.com/upload", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+broker.Placeholder("github"))
		req.ContentLength = int64(size)

		resp, err := rig.client.Do(req)
		if err != nil {
			t.Fatalf("%d bytes: %v", size, err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		parts := strings.SplitN(string(out), "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("%d bytes: upstream said %q", size, out)
		}
		gotN, _ := strconv.ParseInt(parts[0], 10, 64)
		gotHash, gotAuthz := parts[1], parts[2]

		match := gotHash == hex.EncodeToString(want[:])
		if gotN != int64(size) {
			t.Errorf("%d bytes: upstream received %d", size, gotN)
		}
		if !match {
			t.Errorf("%d bytes: the body was altered in transit", size)
		}
		// The credential must still be substituted on a large body: the
		// injection happens on headers, but a buffering bug could reorder it.
		if gotAuthz != "Bearer "+theSecret {
			t.Errorf("%d bytes: upstream saw authorization %q", size, gotAuthz)
		}
		t.Logf("%-11s %-11d %-11d %-13v %s", human(size), size, gotN, match, "substituted")
	}
}

// --- 2. Brokered mTLS ---
//
// The roadmap said "untested", which is not the same as broken. This records
// what actually happens and, if it cannot work, which layer refuses — so the
// limitation is a fact rather than a suspicion.
func TestMeasureBrokeredMutualTLS(t *testing.T) {
	// An upstream that demands a client certificate signed by a CA it names.
	clientCA, err := broker.NewCA("measure client CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "mtls ok")
	})
	rig := newMeasureRig(t, ok, tls.RequireAndVerifyClientCert, clientCA.Pool())

	req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+broker.Placeholder("github"))
	resp, err := rig.client.Do(req)

	// This is a measurement, not an assertion of success. Whatever happens is
	// the finding, and it is recorded in docs/measurements.md.
	switch {
	case err != nil:
		t.Logf("FINDING: brokered mTLS fails at the broker→upstream leg: %v", err)
		t.Log("  the broker holds no client certificate, so the upstream refuses it.")
		t.Log("  a tunnelled host keeps its own mTLS intact; a brokered one cannot,")
		t.Log("  until the broker can be given a client certificate per service.")
	case resp.StatusCode == http.StatusBadGateway:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("FINDING: the broker reports 502 rather than hanging: %s", firstLine(string(body)))
		t.Log("  this is the safe outcome: the failure is visible to the client.")
	default:
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("FINDING: brokered mTLS succeeded unexpectedly (%d): %s", resp.StatusCode, body)
	}

	// Whatever the outcome, it must not be a silent success with no credential.
	if err == nil && resp.StatusCode == 200 {
		t.Error("an mTLS upstream accepted a request the broker could not have authenticated")
	}
}

// --- 3. Latency ---
//
// The repository is about to claim speed in public. The broker's overhead has
// never been isolated, so this measures it against a local upstream: direct
// versus brokered, enough iterations for a median and a p99.
func TestMeasureBrokerLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement takes a few seconds")
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":true}`)
	})
	rig := newMeasureRig(t, ok, tls.NoClientCert, nil)

	const n = 300
	measure := func(c *http.Client, label string) (median, p99 time.Duration) {
		// Warm the connection: the first request pays TLS and, for the brokered
		// path, a CONNECT. Measuring that once as if it were steady state is
		// how a proxy gets blamed for a handshake.
		for i := 0; i < 10; i++ {
			req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
			req.Header.Set("Authorization", "Bearer "+broker.Placeholder("github"))
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("%s warmup: %v", label, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		times := make([]time.Duration, 0, n)
		for i := 0; i < n; i++ {
			req, _ := http.NewRequest("GET", "https://api.github.com/user", nil)
			req.Header.Set("Authorization", "Bearer "+broker.Placeholder("github"))
			start := time.Now()
			resp, err := c.Do(req)
			if err != nil {
				t.Fatalf("%s iteration %d: %v", label, i, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			times = append(times, time.Since(start))
		}
		sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
		return times[len(times)/2], times[int(float64(len(times))*0.99)]
	}

	dMed, dP99 := measure(rig.direct, "direct")
	bMed, bP99 := measure(rig.client, "brokered")

	t.Logf("n=%d against a local upstream on %s", n, hardware())
	t.Logf("  direct    median %v   p99 %v", dMed.Round(time.Microsecond), dP99.Round(time.Microsecond))
	t.Logf("  brokered  median %v   p99 %v", bMed.Round(time.Microsecond), bP99.Round(time.Microsecond))
	t.Logf("  overhead  median %v   p99 %v", (bMed - dMed).Round(time.Microsecond), (bP99 - dP99).Round(time.Microsecond))

	// The only assertion worth making: the overhead is a fraction of a
	// millisecond on loopback, so it is below the noise of any real network.
	// A regression that made the broker ten times slower than the direct path
	// would be a design change, not a slow afternoon.
	if bMed > dMed*10+time.Millisecond {
		t.Errorf("brokered median %v against direct %v — the overhead is no longer a rounding error", bMed, dMed)
	}
}

func human(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MB", n>>20)
	case n >= 1<<10:
		return fmt.Sprintf("%d KB", n>>10)
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func hardware() string {
	return fmt.Sprintf("%s/%s, %d cpus, go %s", runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version())
}

func firstLine(s string) string {
	for i, r := range s {
		if r == '\n' {
			return s[:i]
		}
	}
	return s
}

func urlParse(s string) (*neturl.URL, error) { return neturl.Parse(s) }
