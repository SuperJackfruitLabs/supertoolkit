// The audit trail, end to end.
//
// Until Phase 6 the audit screen returned an empty list: the broker recorded
// effects in memory and `stk ui` was a different process. This proves the chain
// a real operator depends on — a brokered request lands in a durable ledger,
// named the way they named it in policy, with no credential in it.
package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// observer is the same mapping cmd/stk installs: a wire record becomes an audit
// entry, with the catalogue turning a method and a path into a capability name.
type observer struct {
	cfg *policy.Config
	led *ledger.Ledger
}

func (o observer) Observe(r broker.Record) {
	e := ledger.Entry{
		When: r.When.UTC(), Service: r.Service, Host: r.Host,
		Method: r.Method, Path: r.Path, Outcome: r.Status, Caller: "e2e",
	}
	if svc, ok := o.cfg.Service(r.Service); ok {
		if c, known := svc.Entry().CapabilityFor(r.Method, r.Path); known {
			e.Capability = c.Name
			e.Policy = svc.Policy(c.Name).String()
		}
		if r.Injected != "" {
			e.Credential = r.AuthzFP
		} else {
			e.Credential = svc.Entry().Auth.String()
		}
	}
	o.led.Append(e)
}

func TestBrokeredRequestLandsInTheLedgerWithNoCredential(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	dir := t.TempDir()
	led, err := ledger.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := newRigWithObserver(t, func(cfg *policy.Config) broker.Observer {
		return observer{cfg: cfg, led: led}
	})

	cmd := exec.Command("curl", "-s", "-m", "20", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Authorization: Bearer "+broker.Placeholder("github"),
		"https://api.github.com/user")
	cmd.Env = r.childEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the brokered request failed: %v (%q)", err, out)
	}
	if code := strings.TrimSpace(string(out)); code != "200" {
		t.Fatalf("the brokered request returned %s", code)
	}

	entries, err := led.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("the brokered request left no audit entry; the screen would still be empty")
	}
	e := entries[0]

	// Named the way the operator named it in policy, not as a raw path.
	if e.Capability != "get_user" {
		t.Errorf("capability = %q, want get_user — a path is not a name anyone set policy on", e.Capability)
	}
	if e.Service != "github" {
		t.Errorf("service = %q", e.Service)
	}
	if e.Policy != "agent" {
		t.Errorf("policy = %q, want agent — a read is agent-callable by default", e.Policy)
	}
	if !strings.HasPrefix(e.Outcome, "200") {
		t.Errorf("outcome = %q, want the provider's status", e.Outcome)
	}

	// The whole file, not only the entry: nothing anywhere holds the secret.
	raw, err := os.ReadFile(led.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), theSecret) {
		t.Error("the ledger contains the credential")
	}
	// And it says something useful about what was sent.
	if !strings.Contains(e.Credential, "sha256:") {
		t.Errorf("credential = %q, want a fingerprint of what went on the wire", e.Credential)
	}
}
