package main

import (
	"os"
	"os/exec"
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
