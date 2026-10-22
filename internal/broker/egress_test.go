package broker

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// The public address the fake resolver hands out for public.test. Nothing real
// is ever dialled: the fake dialler maps this address to local servers, and
// records every address it is asked for, so a test can prove a refused address
// was never connected to.
const fakePublic = "93.184.215.14"

type egressFixture struct {
	b        *Broker
	proxy    string // host:port
	clientCA *tls.Config
	// secretHits counts requests to a real server on loopback that stands for
	// an internal service; any hit is an SSRF.
	secretHits *atomic.Int64
	secretAddr string
	dialsMu    sync.Mutex
	dials      []string
	lookups    *atomic.Int64
}

func (f *egressFixture) dialed() []string {
	f.dialsMu.Lock()
	defer f.dialsMu.Unlock()
	return append([]string(nil), f.dials...)
}

const fetchEgress = `
workspace: t
servers:
  fetch:
    command: mcp-server-fetch
    network: host
    egress:
      preset: public-only
      schemes: [https, http]
      methods: [GET]
`

func newEgressFixture(t *testing.T, cfgBody string) *egressFixture {
	t.Helper()
	f := &egressFixture{secretHits: &atomic.Int64{}, lookups: &atomic.Int64{}}

	// An internal service on loopback: the thing SSRF reaches for.
	secretLn, _ := net.Listen("tcp", "127.0.0.1:0")
	secretSrv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.secretHits.Add(1)
		io.WriteString(w, "internal secret")
	})}
	go secretSrv.Serve(secretLn)
	t.Cleanup(func() { secretSrv.Close() })
	f.secretAddr = secretLn.Addr().String()

	// The "public" origin, over HTTPS and plain HTTP.
	originCA, _ := NewCA("origin CA", time.Hour)
	leaf, _ := originCA.leafFor("public.test")
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "public %s %s", r.Method, r.URL.Path) })
	mux.HandleFunc("/to-loopback", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+f.secretAddr+"/secret", http.StatusFound)
	})
	mux.HandleFunc("/to-private-name", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://intranet.test/secret", http.StatusFound)
	})
	tlsLn, _ := net.Listen("tcp", "127.0.0.1:0")
	tlsSrv := &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}}}
	go tlsSrv.ServeTLS(tlsLn, "", "")
	plainLn, _ := net.Listen("tcp", "127.0.0.1:0")
	plainSrv := &http.Server{Handler: mux}
	go plainSrv.Serve(plainLn)
	t.Cleanup(func() { tlsSrv.Close(); plainSrv.Close() })

	var rebind atomic.Int64
	resolve := func(_ context.Context, host string) ([]netip.Addr, error) {
		f.lookups.Add(1)
		switch host {
		case "public.test":
			return []netip.Addr{netip.MustParseAddr(fakePublic)}, nil
		case "intranet.test":
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		case "localhost":
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		case "rebind.test":
			// Public the first time, loopback after: the rebinding attack.
			if rebind.Add(1) == 1 {
				return []netip.Addr{netip.MustParseAddr(fakePublic)}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return nil, fmt.Errorf("no such host %s", host)
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		f.dialsMu.Lock()
		f.dials = append(f.dials, addr)
		f.dialsMu.Unlock()
		switch addr {
		case fakePublic + ":443":
			addr = tlsLn.Addr().String()
		case fakePublic + ":80":
			addr = plainLn.Addr().String()
		}
		// Anything else is dialled for real: if a guard is removed, the
		// loopback secret server is reachable and the test sees the hit.
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	cfg, err := policy.Parse("t.yaml", []byte(cfgBody))
	if err != nil {
		t.Fatal(err)
	}
	brokerCA, _ := NewCA("broker CA", time.Hour)
	b, err := New(Options{
		Config: cfg, CA: brokerCA,
		Secrets:  func(string) (string, error) { return "", fmt.Errorf("no secrets here") },
		Upstream: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: originCA.Pool()}},
		Dial:     dial, Resolve: resolve,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go b.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	// The client trusts the broker, and the origin too, so a blind tunnel
	// (which shows the origin's own certificate) also completes.
	pool := brokerCA.Pool()
	pool.AppendCertsFromPEM(originCA.CertPEM())
	f.b, f.proxy, f.clientCA = b, ln.Addr().String(), &tls.Config{RootCAs: pool}
	return f
}

// client follows redirects, as mcp-server-fetch does.
func (f *egressFixture) client(ident string) *http.Client {
	pu, _ := url.Parse(ProxyURLFor(f.proxy, "", ident))
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: f.clientCA, DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
}

func (f *egressFixture) get(t *testing.T, ident, u string) (int, string, error) {
	t.Helper()
	resp, err := f.client(ident).Get(u)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func (f *egressFixture) lastRecord(t *testing.T) Record {
	t.Helper()
	a := f.b.Audit()
	if len(a) == 0 {
		t.Fatal("nothing was recorded")
	}
	return a[len(a)-1]
}

func (f *egressFixture) assertNoSSRF(t *testing.T) {
	t.Helper()
	if n := f.secretHits.Load(); n != 0 {
		t.Fatalf("the internal service was reached %d time(s)", n)
	}
	for _, d := range f.dialed() {
		if !strings.HasPrefix(d, fakePublic+":") {
			t.Fatalf("the broker dialled %s, which is not the decided public address", d)
		}
	}
}

func TestEgressRefusesInternalAddresses(t *testing.T) {
	f := newEgressFixture(t, fetchEgress)
	cases := []struct{ url, rule string }{
		{"http://" + "127.0.0.1:3101/health", "egress:public-only/loopback"},
		{"https://127.0.0.1:3101/health", "egress:public-only/loopback"},
		{"http://169.254.169.254/latest/meta-data/", "egress:public-only/link-local"},
		{"https://169.254.169.254/", "egress:public-only/link-local"},
		{"http://100.78.52.87/", "egress:public-only/cgnat"},
		{"http://10.1.2.3/", "egress:public-only/private"},
		{"http://[::1]:3101/", "egress:public-only/loopback"},
		{"http://[fd00:ec2::254]/", "egress:public-only/ula"},
		{"http://[::ffff:127.0.0.1]:3101/", "egress:public-only/loopback"},
		// A hostname that resolves to a refused address.
		{"https://intranet.test/", "egress:public-only/private"},
		{"http://localhost:3101/", "egress:public-only/loopback"},
	}
	for _, c := range cases {
		code, _, err := f.get(t, "fetch", c.url)
		if err == nil && code != http.StatusForbidden {
			t.Errorf("%s: status %d, want refused", c.url, code)
		}
		rec := f.lastRecord(t)
		if rec.Rule != c.rule || !strings.HasPrefix(rec.Status, "403 denied") || rec.Kind != KindEgress || rec.Service != "fetch" {
			t.Errorf("%s: record %+v, want denied by %s", c.url, rec, c.rule)
		}
	}
	f.assertNoSSRF(t)
	if f.b.Stats().Denied != int64(len(cases)) {
		t.Errorf("denied counter %d, want %d", f.b.Stats().Denied, len(cases))
	}
}

func TestEgressRefusesTheLoopbackSecretDirectly(t *testing.T) {
	// The control for the redirect test below: the secret server is really
	// listening, and a request for it is refused by the broker, not by chance.
	f := newEgressFixture(t, fetchEgress)
	code, _, err := f.get(t, "fetch", "http://"+f.secretAddr+"/secret")
	if err != nil || code != http.StatusForbidden {
		t.Fatalf("direct loopback: %d %v", code, err)
	}
	f.assertNoSSRF(t)
}

func TestEgressAllowsPublicAndRecordsTheDialledAddress(t *testing.T) {
	f := newEgressFixture(t, fetchEgress)
	for _, u := range []string{"https://public.test/page", "http://public.test/page"} {
		code, body, err := f.get(t, "fetch", u)
		if err != nil || code != 200 || body != "public GET /page" {
			t.Fatalf("%s: %d %q %v", u, code, body, err)
		}
		rec := f.lastRecord(t)
		if rec.Rule != "egress:public-only" || rec.Status != "200 OK" || rec.Method != "GET" || rec.Path != "/page" ||
			!strings.HasPrefix(rec.Addr, fakePublic+":") || rec.Host != "public.test" {
			t.Errorf("%s: record %+v", u, rec)
		}
	}
	f.assertNoSSRF(t)
}

func TestEgressRedirectToLoopbackIsRefusedAtTheSecondHop(t *testing.T) {
	for _, scheme := range []string{"https", "http"} {
		f := newEgressFixture(t, fetchEgress)
		code, _, err := f.get(t, "fetch", scheme+"://public.test/to-loopback")
		if err == nil && code != http.StatusForbidden {
			t.Fatalf("%s: redirect followed to %d", scheme, code)
		}
		a := f.b.Audit()
		var hop1, hop2 bool
		for _, r := range a {
			hop1 = hop1 || (r.Path == "/to-loopback" && r.Status == "302 Found")
			hop2 = hop2 || (r.Rule == "egress:public-only/loopback" && strings.HasPrefix(r.Status, "403"))
		}
		if !hop1 || !hop2 {
			t.Errorf("%s: both hops not recorded: %+v", scheme, a)
		}
		f.assertNoSSRF(t)
	}
}

func TestEgressRedirectToAPrivateNameIsRefused(t *testing.T) {
	f := newEgressFixture(t, fetchEgress)
	if code, _, err := f.get(t, "fetch", "https://public.test/to-private-name"); err == nil && code != 403 {
		t.Fatalf("status %d", code)
	}
	if r := f.lastRecord(t); r.Host != "intranet.test" || r.Rule != "egress:public-only/private" {
		t.Fatalf("record %+v", r)
	}
	f.assertNoSSRF(t)
}

func TestEgressPinsTheResolvedAddress(t *testing.T) {
	// rebind.test answers public, then loopback. The broker must resolve once
	// and connect to what it decided; a second lookup at dial time is the hole.
	f := newEgressFixture(t, fetchEgress)
	code, _, err := f.get(t, "fetch", "https://rebind.test/x")
	if err != nil {
		t.Fatalf("%v", err)
	}
	_ = code // the origin's leaf is for public.test, so TLS may fail upstream; what matters is where it went
	if n := f.lookups.Load(); n != 1 {
		t.Errorf("%d lookups, want exactly one", n)
	}
	f.assertNoSSRF(t)
}

func TestEgressMethodsAreChecked(t *testing.T) {
	f := newEgressFixture(t, fetchEgress)
	for _, u := range []string{"https://public.test/form", "http://public.test/form"} {
		resp, err := f.client("fetch").Post(u, "text/plain", strings.NewReader("x"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("%s: POST got %d", u, resp.StatusCode)
		}
		if r := f.lastRecord(t); r.Rule != "egress:method" || r.Method != "POST" {
			t.Errorf("%s: record %+v", u, r)
		}
	}
}

func TestEgressSchemesAreChecked(t *testing.T) {
	f := newEgressFixture(t, strings.Replace(fetchEgress, "[https, http]", "[https]", 1))
	if code, _, _ := f.get(t, "fetch", "http://public.test/"); code != http.StatusForbidden {
		t.Fatalf("plain http with https-only egress: %d", code)
	}
	if r := f.lastRecord(t); r.Rule != "egress:scheme" {
		t.Fatalf("record %+v", r)
	}
	f.assertNoSSRF(t)
	if len(f.dialed()) != 0 {
		t.Fatal("dialled for a refused scheme")
	}
}

func TestWorkspaceEgressDecidesACallerWithNoIdentity(t *testing.T) {
	f := newEgressFixture(t, "workspace: t\negress: { preset: public-only }\n")
	if code, _, err := f.get(t, "", "https://169.254.169.254/"); err == nil && code != 403 {
		t.Fatalf("status %d", code)
	}
	if r := f.lastRecord(t); r.Service != "egress" || r.Rule != "egress:public-only/link-local" {
		t.Fatalf("record %+v", r)
	}
	// No methods set: an allowed host is tunnelled unopened, to the decided address.
	if code, body, err := f.get(t, "", "https://public.test/x"); err != nil || code != 200 || body != "public GET /x" {
		t.Fatalf("public via workspace egress: %d %q %v", code, body, err)
	}
	if r := f.lastRecord(t); r.Rule != "egress:public-only" || r.Status != "tunnelled to "+fakePublic+":443" {
		t.Fatalf("record %+v", r)
	}
	f.assertNoSSRF(t)
}

func TestATunnelWithNoEgressIsStillRecorded(t *testing.T) {
	f := newEgressFixture(t, "workspace: t\n")
	f.get(t, "", "https://public.test/x") // the fixture cannot resolve it for real; the record is the point
	r := f.lastRecord(t)
	if r.Kind != KindTunnel || r.Status != "tunnelled, not decided" || r.Host != "public.test" {
		t.Fatalf("record %+v", r)
	}
}

func TestIdentityTravelsInTheProxyUser(t *testing.T) {
	// With a key, stk+<server> is accepted and selects that server's egress;
	// a stranger's user name is refused.
	f := newEgressFixture(t, fetchEgress)
	f.b.proxyKey = "k"
	for user, want := range map[string]bool{"stk": true, "stk+fetch": true, "admin": false} {
		r, _ := http.NewRequest(http.MethodConnect, "http://x", nil)
		r.SetBasicAuth(user, "k")
		r.Header.Set("Proxy-Authorization", r.Header.Get("Authorization"))
		ok, ident := f.b.authorized(r)
		if ok != want {
			t.Errorf("%s: authorized %v", user, ok)
		}
		if user == "stk+fetch" && ident != "fetch" {
			t.Errorf("identity %q", ident)
		}
	}
}
