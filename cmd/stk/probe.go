package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// probeHost is deliberately in the .invalid TLD, which RFC 2606 reserves and
// guarantees will never resolve.
//
// That guarantee is the detector. A client that honours the proxy never
// resolves anything — it asks the broker for the host by name over CONNECT. A
// client that ignores the proxy must resolve it itself, and fails. So a DNS
// failure is proof of a bypass rather than a guess at one, which is what makes
// this probe worth more than checking that the environment looks right.
const probeHost = "probe.supertoolkit.invalid"

// probeResult is one client's verdict.
type probeResult struct {
	client string
	// state is honoured | bypassed | refused-ca | missing | failed
	state  string
	detail string
}

func (p probeResult) ok() bool { return p.state == "honoured" }

// cmdProbe proves the brokered path works, which is a different claim from
// `doctor`'s leak check.
//
// The leak check proves no credential is reachable from a child's environment.
// That is necessary and not sufficient: the Phase 0 spikes found clients that
// ignore proxy configuration entirely and fail *silently*, reaching the
// provider with a worthless placeholder and getting a plausible 401 back. A
// broker that cannot detect its own bypass is a broker you cannot trust, so
// this drives a real request through a real broker with each client on this
// machine and reports which ones actually went through it.
func cmdProbe(out io.Writer, o doctorOpts) error {
	dir, err := home()
	if err != nil {
		return err
	}
	rig, err := newRigFn(dir, o.withProxyKey)
	if err != nil {
		return err
	}
	defer rig.close()

	// With --json stdout carries exactly one JSON document; the human text
	// goes to stderr.
	human := out
	if o.json {
		human = os.Stderr
	}
	fmt.Fprintf(human, "\n  probing the brokered path with a local stand-in for %s\n", probeHost)
	fmt.Fprintf(human, "  the host is in .invalid and can never resolve, so a DNS failure proves a bypass\n")
	if rig.keyed {
		fmt.Fprintf(human, "  the broker under probe requires a proxy key, sent in the proxy URL\n")
	}
	fmt.Fprintln(human)

	results := probeClients(rig)
	honoured := 0
	for i := range results {
		results[i].detail = rig.redact(results[i].detail)
		if results[i].state == "honoured" {
			honoured++
		}
	}

	// worst: 0 clean, 1 a CA refusal (loud, safe), 2 a bypass, 3 a client that
	// failed. 2 and 3 fail the exit status.
	worst := 0
	bump := func(n int) {
		if n > worst {
			worst = n
		}
	}
	for _, r := range results {
		mark := "✗"
		switch r.state {
		case "honoured":
			mark = "✓"
		case "missing":
			mark = "–"
		case "bypassed":
			mark = "!"
			bump(2)
		case "refused-ca":
			bump(1)
		default:
			bump(3)
		}
		fmt.Fprintf(human, "  %s %-18s %-11s %s\n", mark, r.client, r.state, r.detail)
	}

	fmt.Fprintln(human)
	fmt.Fprintf(human, "  the broker saw %d request(s) and substituted %d credential(s)\n",
		rig.b.Stats().Intercept, rig.b.Stats().Swap)
	fmt.Fprintln(human)
	switch worst {
	case 0, 1:
		if honoured == 0 {
			fmt.Fprintln(human, "  no client was exercised; nothing is proven.")
			break
		}
		if worst == 0 {
			fmt.Fprintln(human, "  every client present here goes through the broker.")
			break
		}
		fmt.Fprintln(human, "  a client refused the broker's CA. That fails loudly, which is the safe class:")
		fmt.Fprintln(human, "  the request does not happen rather than happening unbrokered. Trust the CA for")
		fmt.Fprintln(human, "  that client, or run it where `stk run` can set its trust store.")
	case 2:
		fmt.Fprintln(human, "  ! a client reached past the broker. This is the one failure mode that is silent:")
		fmt.Fprintln(human, "  such a client sends the placeholder to the provider and gets a plausible 401,")
		fmt.Fprintln(human, "  which looks like a credential problem rather than a routing one.")
		fmt.Fprintln(human, "  Do not broker that client. See docs/limitations.md.")
	case 3:
		fmt.Fprintln(human, "  a client failed in a way that is neither a bypass nor a CA refusal; see the detail above.")
	}

	if o.json {
		type row struct {
			Client  string `json:"client"`
			Outcome string `json:"outcome"`
			Detail  string `json:"detail"`
		}
		rows := make([]row, 0, len(results))
		for _, r := range results {
			rows = append(rows, row{r.client, r.state, r.detail})
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return err
		}
	}
	// Exit status: bypassed and failed fail the command. refused-ca (loud, safe)
	// and missing (client not installed here) do not.
	switch worst {
	case 2:
		return fmt.Errorf("probe: a client bypassed the broker")
	case 3:
		return fmt.Errorf("probe: a client failed")
	}
	// A pass must be earned: with no client honoured, nothing was shown.
	if honoured == 0 {
		return fmt.Errorf("no client was exercised; nothing is proven")
	}
	return nil
}

type probeRig struct {
	b        *broker.Broker
	proxyURL string
	caPath   string
	provider *http.Server
	provLn   net.Listener
	proxyLn  net.Listener
	dir      string
	// keyed is true when the broker under probe requires a proxy key; proxyURL
	// then carries it as userinfo.
	keyed bool
	key   string
}

// newProbeRig stands up a broker and a local provider for probeHost. Nothing
// here touches the real config or the real store: a probe must not depend on
// any service being connected, and must never put a real credential at risk.
var probeClients = func(rig *probeRig) []probeResult {
	return []probeResult{rig.probeCurl(), rig.probePython(), rig.probeNode(), rig.probeGoDefault()}
}

// newRigFn is a seam so tests can make the rig fail to start.
var newRigFn = newProbeRigKeyed

func newProbeRig(home string) (*probeRig, error) { return newProbeRigKeyed(home, false) }

// newProbeRigKeyed optionally starts the broker with a proxy key, as a station
// service does, so the probe also proves each client sends proxy credentials.
func newProbeRigKeyed(home string, keyed bool) (*probeRig, error) {
	dir, err := os.MkdirTemp("", "stk-probe-")
	if err != nil {
		return nil, err
	}
	r := &probeRig{dir: dir, keyed: keyed}
	var proxyKey string
	if keyed {
		kb := make([]byte, 32)
		if _, err := rand.Read(kb); err != nil {
			return nil, err
		}
		proxyKey = base64.RawURLEncoding.EncodeToString(kb)
		r.key = proxyKey
	}

	// The provider: its certificate is minted by a CA the client never trusts,
	// so a client that reaches it directly also fails — only the broker's
	// re-signed leaf is acceptable.
	provCA, err := broker.NewCA("stk probe provider CA", time.Hour)
	if err != nil {
		return nil, err
	}
	leaf, err := provCA.LeafForTest(probeHost)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		// Report back what arrived, so the probe can tell a swapped credential
		// from a placeholder that got through.
		fmt.Fprintln(w, req.Header.Get("Authorization"))
	})
	r.provLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	r.provider = &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}}}
	go r.provider.ServeTLS(r.provLn, "", "")

	// A config holding one service, which exists only in memory.
	cfgPath := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(cfgPath, []byte(probeConfig), 0o600); err != nil {
		return nil, err
	}
	cfg, err := policy.Load(cfgPath)
	if err != nil {
		return nil, err
	}

	ca, err := broker.NewCA("stk probe CA", time.Hour)
	if err != nil {
		return nil, err
	}
	// Into the probe's own temporary directory: writing the install's ca.pem
	// here destroyed the certificate clients had been told to trust.
	r.caPath, err = ca.WriteCert(r.dir)
	if err != nil {
		return nil, err
	}
	r.b, err = broker.New(broker.Options{
		Config: cfg, CA: ca, ProxyKey: proxyKey,
		// The probe host is not in the catalogue, deliberately: a name that can
		// never resolve is what makes a bypass provable rather than guessed at.
		Intercept: []string{probeHost},
		// A value that is not a credential and never was: the probe proves
		// substitution happened without a real secret being anywhere near it.
		Secrets: func(string) (string, error) { return probeSecret, nil },
		Upstream: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: provCA.Pool()},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.HasPrefix(addr, probeHost+":") {
					addr = r.provLn.Addr().String()
				}
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
			},
		},
	})
	if err != nil {
		return nil, err
	}
	r.proxyLn, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go r.b.Serve(r.proxyLn)
	r.proxyURL = "http://" + r.proxyLn.Addr().String()
	if keyed {
		r.proxyURL = broker.ProxyURL(r.proxyLn.Addr().String(), proxyKey)
	}
	return r, nil
}

const probeSecret = "stk-probe-substituted-value"

// probeService is a real catalogue entry, because policy refuses an unknown
// one. Which entry does not matter: the broker's dialler sends its host to the
// local stand-in, and the probe never reads the real store.
const probeService = "github"

// probeConfig names a service whose host is the .invalid probe host. It is a
// real catalogue service so policy loads, with its host overridden by the
// broker's dialler rather than by the catalogue.
var probeConfig = "workspace: probe\nservices:\n  " + probeService + ":\n    scopes: []\n"

func (r *probeRig) close() {
	if r.proxyLn != nil {
		r.proxyLn.Close()
	}
	if r.provider != nil {
		r.provider.Close()
	}
	os.RemoveAll(r.dir)
}

// env is what `stk run` hands a child, so the probe tests the real contract.
func (r *probeRig) env(extra ...string) []string {
	e := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"HTTPS_PROXY=" + r.proxyURL,
		"https_proxy=" + r.proxyURL,
		"SSL_CERT_FILE=" + r.caPath,
		"CURL_CA_BUNDLE=" + r.caPath,
		"REQUESTS_CA_BUNDLE=" + r.caPath,
		"NODE_EXTRA_CA_CERTS=" + r.caPath,
		"NODE_USE_ENV_PROXY=1",
	}
	return append(e, extra...)
}

// classify turns a client's exit into a verdict.
//
// The three outcomes that matter are distinguishable from the output: the
// provider echoed our substituted value (honoured), the client could not
// resolve a .invalid name (bypassed — it never asked the proxy), or TLS was
// refused (the CA was not trusted, which fails loudly and is therefore safe).
func classify(client string, out string, err error) probeResult {
	low := strings.ToLower(out)
	switch {
	case strings.Contains(out, probeSecret):
		return probeResult{client, "honoured", "the provider received the substituted credential"}
	case strings.Contains(low, "could not resolve") || strings.Contains(low, "name or service not known") ||
		strings.Contains(low, "nodename nor servname") || strings.Contains(low, "no such host") ||
		strings.Contains(low, "getaddrinfo") || strings.Contains(low, "enotfound"):
		return probeResult{client, "bypassed", "it resolved the host itself, so it never asked the broker"}
	case strings.Contains(low, "certificate") || strings.Contains(low, "self-signed") ||
		strings.Contains(low, "unable to get local issuer") || strings.Contains(low, "ssl"):
		return probeResult{client, "refused-ca", "it would not trust the broker's certificate — fails loudly, so safe"}
	case err != nil:
		return probeResult{client, "failed", firstLine(out)}
	default:
		return probeResult{client, "failed", "reached something, but not with the substituted credential: " + firstLine(out)}
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 110 {
		s = s[:110] + "…"
	}
	return s
}

func (r *probeRig) run(client string, env []string, name string, args ...string) probeResult {
	if _, err := exec.LookPath(name); err != nil {
		return probeResult{client, "missing", "not installed here"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return r.classify(client, string(out), err)
}

// redact removes the ephemeral proxy key, and any URL carrying it, from text
// that is about to be printed.
func (r *probeRig) redact(s string) string {
	if r.key == "" {
		return s
	}
	s = strings.ReplaceAll(s, r.proxyURL, "http://[redacted]@"+r.proxyLn.Addr().String())
	return strings.ReplaceAll(s, r.key, "[redacted]")
}

// proxyAuthRequired matches a client's own report of a 407 from the proxy,
// never bare digits (a port such as 40712 contains them).
var proxyAuthRequired = regexp.MustCompile(`(?i)(\bresponse 407\b|\bstatuscode=407\b|\b407 proxy authentication required\b|proxy authentication required)`)

// classify is the package classify plus the one verdict only a keyed broker
// can produce: a 407 means the client dropped the proxy URL's userinfo. The
// honoured case is decided first, so output that merely contains "407" cannot
// demote it.
func (r *probeRig) classify(client, out string, err error) probeResult {
	got := classify(client, out, err)
	if r.keyed && got.state != "honoured" && proxyAuthRequired.MatchString(out) {
		return probeResult{client, "failed", "proxy credential not honoured"}
	}
	return got
}

func (r *probeRig) probeCurl() probeResult {
	return r.run("curl", r.env(), "curl", "-sS", "-m", "15",
		"-H", "Authorization: Bearer "+broker.Placeholder(probeService),
		"https://"+probeHost+"/")
}

func (r *probeRig) probePython() probeResult {
	script := fmt.Sprintf(`import urllib.request,sys
req=urllib.request.Request("https://%s/",headers={"Authorization":"Bearer %s"})
try: sys.stdout.write(urllib.request.urlopen(req,timeout=15).read().decode())
except Exception as e: sys.stdout.write(str(e))
`, probeHost, broker.Placeholder(probeService))
	return r.run("python3 urllib", r.env(), "python3", "-c", script)
}

// Node's default fetch ignores proxy environment variables unless
// NODE_USE_ENV_PROXY is set, which is exactly the silent class this probe
// exists to surface. `stk run` sets it; a client run outside `stk run` does not
// have it, and this reports what the current environment actually does.
func (r *probeRig) probeNode() probeResult {
	script := fmt.Sprintf(`fetch("https://%s/",{headers:{Authorization:"Bearer %s"}})
  .then(r=>r.text()).then(t=>process.stdout.write(t))
  .catch(e=>process.stdout.write(String(e&&e.cause||e)))`,
		probeHost, broker.Placeholder(probeService))
	return r.run("node fetch", r.env(), "node", "-e", script)
}

// A Go program with a zero-value http.Transport honours proxy environment
// variables; one that builds its own Transport without ProxyFromEnvironment
// does not. The second kind cannot be detected from outside, so this probes the
// first and the limitation is documented rather than implied.
func (r *probeRig) probeGoDefault() probeResult {
	if _, err := exec.LookPath("go"); err != nil {
		return probeResult{"go net/http", "missing", "no toolchain here"}
	}
	src := fmt.Sprintf(`package main
import ("fmt";"io";"net/http")
func main(){
  req,_ := http.NewRequest("GET","https://%s/",nil)
  req.Header.Set("Authorization","Bearer %s")
  resp,err := http.DefaultClient.Do(req)
  if err != nil { fmt.Print(err); return }
  defer resp.Body.Close()
  b,_ := io.ReadAll(resp.Body)
  fmt.Print(string(b))
}`, probeHost, broker.Placeholder(probeService))
	path := filepath.Join(r.dir, "probe_go")
	if err := os.MkdirAll(path, 0o700); err != nil {
		return probeResult{"go net/http", "failed", err.Error()}
	}
	os.WriteFile(filepath.Join(path, "main.go"), []byte(src), 0o600)
	os.WriteFile(filepath.Join(path, "go.mod"), []byte("module probe\n\ngo 1.21\n"), 0o600)
	env := append(r.env(), "GOCACHE="+filepath.Join(r.dir, "gocache"), "GOFLAGS=-mod=mod")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", ".")
	cmd.Dir = path
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return r.classify("go net/http", string(out), err)
}
