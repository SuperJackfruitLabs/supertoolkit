package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/webui"
)

// observer turns a wire record into an audit entry.
//
// The broker sees a method and a path; an operator wants the name they chose a
// policy for. The translation needs the catalogue, which lives here and not in
// the broker, so this is where the two meet.
type observer struct {
	cfg *policy.Config
	led *ledger.Ledger
	// caller identifies this process in the ledger: a profile for an MCP
	// server, `run` for a brokered child.
	caller string
}

func (o observer) Observe(r broker.Record) {
	e := ledger.Entry{
		When: r.When.UTC(), Service: r.Service, Host: r.Host,
		Method: r.Method, Path: r.Path, Outcome: r.Status, Caller: o.caller,
		Rule: r.Rule,
	}
	// A denied request never fetched a credential, so it must not carry a
	// credential fingerprint; the rule that refused it is the evidence.
	denied := r.Rule != "" && strings.HasPrefix(r.Status, "403 denied")
	if svc, ok := o.cfg.Service(r.Service); ok {
		if denied {
			e.Capability, e.Policy = "(denied)", "deny"
			e.Credential = svc.Entry().Auth.String()
		} else if c, known := svc.Entry().CapabilityFor(r.Method, r.Path); known {
			e.Capability = c.Name
			e.Policy = svc.Policy(c.Name).String()
		}
		// What was sent, described without being it. A substituted token is
		// identified by fingerprint; a signed request carries no token at all,
		// so naming the operation is the honest answer.
		if !denied {
			if r.Injected != "" {
				e.Credential = r.AuthzFP
			} else {
				e.Credential = svc.Entry().Auth.String()
			}
		}
	}
	if denied {
		e.Capability, e.Policy = "(denied)", "deny"
	}
	if e.Capability == "" {
		// A request the catalogue never named. Recording it matters more than
		// naming it: an unexpected path through the broker is exactly what an
		// operator wants to see.
		e.Capability = "(not in the catalogue)"
	}
	// A failed append must not fail the request the operator is making. It is
	// reported once, on stderr, rather than swallowed.
	if err := o.led.Append(e); err != nil {
		fmt.Fprintln(os.Stderr, "stk: could not write the audit ledger:", err)
	}
}

// newObserver wires a broker to the durable ledger.
func newObserver(cfg *policy.Config, dir, caller string) (observer, error) {
	led, err := ledger.Open(dir)
	if err != nil {
		return observer{}, err
	}
	return observer{cfg: cfg, led: led, caller: caller}, nil
}

func cmdAudit(args []string) error {
	limit, asJSON := 50, false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--limit", "-n":
			if i+1 >= len(args) {
				return fmt.Errorf("--limit needs a number")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n <= 0 {
				return fmt.Errorf("--limit wants a positive number, got %q", args[i+1])
			}
			limit = n
			i++
		default:
			return fmt.Errorf("usage: stk audit [--limit n] [--json]")
		}
	}
	dir, err := home()
	if err != nil {
		return err
	}
	led, err := ledger.Open(dir)
	if err != nil {
		return err
	}
	entries, err := led.Read(limit)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	if len(entries) == 0 {
		fmt.Printf("  nothing recorded yet · %s\n", led.Path())
		fmt.Println("  effects appear here once a brokered request runs: stk run -- <command>")
		return nil
	}
	fmt.Printf("  %d most recent effect(s) · %s\n\n", len(entries), led.Path())
	for _, e := range entries {
		fmt.Printf("  %s  %-10s %-24s %-8s %s\n",
			e.When.Local().Format("Jan 02 15:04:05"), e.Service, e.Capability, e.Policy, e.Outcome)
		fmt.Printf("  %18s%s %s · credential: %s\n", "", e.Method, e.Path, e.Credential)
		if e.Rule != "" {
			fmt.Printf("  %18srule: %s\n", "", e.Rule)
		}
	}
	fmt.Println()
	fmt.Println("  no credential is recorded here — a fingerprint or the operation that replaced it")
	return nil
}

// auditForUI reads the same file the CLI reads, so the two cannot disagree
// about what happened.
func auditForUI(dir string) func(int) []webui.Effect {
	return func(limit int) []webui.Effect {
		led, err := ledger.Open(dir)
		if err != nil {
			return nil
		}
		entries, err := led.Read(limit)
		if err != nil {
			return nil
		}
		out := make([]webui.Effect, 0, len(entries))
		for _, e := range entries {
			out = append(out, webui.Effect{
				When: e.When, Category: e.Service, Action: e.Capability,
				Policy: e.Policy, Caller: e.Caller,
				Credential: e.Credential, Outcome: e.Outcome,
			})
		}
		return out
	}
}

// fingerprint describes a credential without being it, the same way the broker
// does: a short SHA-256 prefix. Two requests carrying the same credential show
// the same fingerprint, which is enough to tell them apart without the value.
func fingerprint(s string) string {
	if s == "" {
		return "(absent)"
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}
