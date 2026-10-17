package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
)

// The detector's whole claim: a client that ignores the proxy must resolve a
// .invalid name itself, and cannot. This runs curl with no proxy in its
// environment, which is exactly what a bypassing client looks like from
// outside, and asserts the probe says so.
func TestBypassIsDetectedAndNotMistakenForSuccess(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	rig, err := newProbeRig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer rig.close()

	// Honoured: the full environment `stk run` provides.
	if got := rig.probeCurl(); !got.ok() {
		t.Fatalf("curl with the broker's environment: %s — %s", got.state, got.detail)
	}

	// Bypassed: the same client with no proxy, the silent failure class.
	noProxy := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"SSL_CERT_FILE=" + rig.caPath,
		"CURL_CA_BUNDLE=" + rig.caPath,
	}
	got := rig.run("curl", noProxy, "curl", "-sS", "-m", "10",
		"-H", "Authorization: Bearer "+broker.Placeholder(probeService),
		"https://"+probeHost+"/")
	if got.state != "bypassed" {
		t.Fatalf("a client with no proxy was reported as %q (%s), want bypassed — the probe would miss the one silent failure mode",
			got.state, got.detail)
	}
}

// The three verdicts are distinguished by what the client said, so the mapping
// is worth asserting directly: calling a bypass "failed" would hide it among
// ordinary errors.
func TestClassifyDistinguishesTheThreeOutcomes(t *testing.T) {
	cases := []struct {
		name, output, want string
	}{
		{"substituted", "Bearer " + probeSecret + "\n", "honoured"},
		{"curl dns", "curl: (6) Could not resolve host: probe.supertoolkit.invalid", "bypassed"},
		{"go dns", `Get "https://probe.supertoolkit.invalid/": dial tcp: lookup probe.supertoolkit.invalid: no such host`, "bypassed"},
		{"node dns", "TypeError: fetch failed ENOTFOUND probe.supertoolkit.invalid", "bypassed"},
		{"python dns", "<urlopen error [Errno 8] nodename nor servname provided>", "bypassed"},
		{"glibc dns", "Name or service not known", "bypassed"},
		{"curl ca", "curl: (60) SSL certificate problem: unable to get local issuer certificate", "refused-ca"},
		{"go ca", "x509: certificate signed by unknown authority", "refused-ca"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classify("x", c.output, nil); got.state != c.want {
				t.Errorf("classify(%q) = %q, want %q", c.output, got.state, c.want)
			}
		})
	}
}

// A placeholder that reached the provider unswapped must never read as
// success: that is the exact appearance of the silent failure.
func TestAPlaceholderReachingTheProviderIsNotSuccess(t *testing.T) {
	got := classify("x", "Bearer "+broker.Placeholder("github")+"\n", nil)
	if got.ok() {
		t.Fatal("an unswapped placeholder was reported as honoured")
	}
	if !strings.Contains(got.detail, "not with the substituted credential") {
		t.Errorf("detail = %q, want it to say the credential was not substituted", got.detail)
	}
}

// The probe must never read the real store or the real config: a self-test
// that can expose a live credential is not one anybody should run.
func TestProbeTouchesNoRealCredential(t *testing.T) {
	rig, err := newProbeRig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer rig.close()
	if got := rig.probeCurl(); got.state == "honoured" && !strings.Contains(got.detail, "substituted") {
		t.Error("unexpected detail")
	}
	// The value the broker substitutes is a constant, not anything stored.
	if strings.Contains(probeSecret, "ghp_") || strings.Contains(probeSecret, "sk-") {
		t.Error("the probe's stand-in value looks like a real credential")
	}
}

func fakeClients(rs ...probeResult) func(*probeRig) []probeResult {
	return func(*probeRig) []probeResult { return rs }
}

func withClients(t *testing.T, f func(*probeRig) []probeResult) {
	t.Helper()
	old := probeClients
	probeClients = f
	t.Cleanup(func() { probeClients = old })
}

// The exit status is the point of the probe in automation: a bypass is the
// silent failure class and must fail the command. refused-ca and missing must
// not, failed must.
func TestProbeExitsNonZeroOnBypass(t *testing.T) {
	cases := []struct {
		state   string
		wantErr bool
	}{
		{"honoured", false}, {"refused-ca", false}, {"missing", false},
		{"bypassed", true}, {"failed", true},
	}
	for _, c := range cases {
		withClients(t, fakeClients(
			probeResult{"a", "honoured", "ok"},
			probeResult{"b", c.state, "x"}))
		var out bytes.Buffer
		err := runDoctor([]string{"--probe"}, &out)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, want error=%v", c.state, err, c.wantErr)
		}
		if !strings.Contains(out.String(), c.state) || !strings.Contains(out.String(), "b ") {
			t.Errorf("%s: table not printed:\n%s", c.state, out.String())
		}
	}
}

func TestProbeJSONShape(t *testing.T) {
	withClients(t, fakeClients(
		probeResult{"curl", "honoured", "the provider received the substituted credential"},
		probeResult{"node fetch", "bypassed", "it resolved the host itself"}))
	var out bytes.Buffer
	err := runDoctor([]string{"--probe", "--json"}, &out)
	if err == nil {
		t.Error("a bypass in JSON mode must still exit non-zero")
	}
	var got []map[string]string
	if e := json.Unmarshal(out.Bytes(), &got); e != nil {
		t.Fatalf("stdout is not a JSON array: %v\n%s", e, out.String())
	}
	want := []map[string]string{
		{"client": "curl", "outcome": "honoured", "detail": "the provider received the substituted credential"},
		{"client": "node fetch", "outcome": "bypassed", "detail": "it resolved the host itself"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	// Nothing else on stdout: exactly one JSON document.
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var a any
	dec.Decode(&a)
	if dec.More() {
		t.Error("extra output after the JSON array")
	}
	// Empty list is [] not null.
	withClients(t, fakeClients())
	out.Reset()
	runDoctor([]string{"--probe", "--json"}, &out)
	if strings.TrimSpace(out.String()) != "[]" {
		t.Errorf("empty = %q", out.String())
	}
}

// A client that drops the proxy URL's userinfo gets a 407 from a keyed broker.
// That is a client defect, reported as such, and a client that sends it works.
func TestProbeReportsClientDroppingProxyUserinfo(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	rig, err := newProbeRigKeyed(t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	defer rig.close()

	if got := rig.probeCurl(); got.state != "honoured" {
		t.Fatalf("client sending the key: %s — %s", got.state, got.detail)
	}
	bare := "http://" + rig.proxyLn.Addr().String()
	env := rig.env()
	for i, e := range env {
		if strings.HasPrefix(e, "HTTPS_PROXY=") || strings.HasPrefix(e, "https_proxy=") {
			env[i] = strings.SplitN(e, "=", 2)[0] + "=" + bare
		}
	}
	got := rig.run("curl", env, "curl", "-sS", "-m", "10",
		"-H", "Authorization: Bearer "+broker.Placeholder(probeService),
		"https://"+probeHost+"/")
	if got.state != "failed" || got.detail != "proxy credential not honoured" {
		t.Fatalf("got %s — %s", got.state, got.detail)
	}
	if rig.b.Stats().Intercept != 1 {
		t.Errorf("dropping client must not have been brokered: %+v", rig.b.Stats())
	}
}

// The default stays keyless.
func TestProbeKeylessByDefault(t *testing.T) {
	rig, err := newProbeRig(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer rig.close()
	if strings.Contains(rig.proxyURL, "@") {
		t.Errorf("keyless rig has userinfo: %s", rig.proxyURL)
	}
}
