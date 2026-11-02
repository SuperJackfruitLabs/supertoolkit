package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/webui"
)

// Observer turns a wire record into an audit entry.
//
// The broker sees a method and a path; an operator wants the name they chose a
// policy for. The translation needs the catalogue, which lives here and not in
// the broker, so this is where the two meet.
type Observer struct {
	// live is read per record, so a reload reaches the audit too.
	live *livepolicy.Config
	Led  *ledger.Ledger
	// Caller identifies this process in the ledger: a profile for an MCP
	// server, `run` for a brokered child.
	Caller string
}

func (o Observer) Observe(r broker.Record) {
	e := ledger.Entry{
		When: r.When.UTC(), Service: r.Service, Host: EscapeControl(r.Host),
		Method: EscapeControl(r.Method), Path: EscapeControl(r.Path), Outcome: EscapeControl(r.Status), Caller: o.Caller,
		Rule: EscapeControl(r.Rule),
	}
	if r.Kind != "" {
		// A host outside policy: no service, no credential, and the evidence
		// is the rule and the address actually dialled.
		e.Addr = EscapeControl(r.Addr)
		e.Capability, e.Credential, e.Policy = "(egress)", "none", "allow"
		if r.Kind == broker.KindTunnel {
			e.Capability, e.Policy = "(tunnel, not decided)", ""
		} else if strings.HasPrefix(r.Status, "403 denied") {
			e.Policy = "deny"
		}
		if err := o.Led.Append(e); err != nil {
			fmt.Fprintln(os.Stderr, "stk: could not write the audit ledger:", err)
		}
		return
	}
	// A denied request never fetched a credential, so it must not carry a
	// credential fingerprint; the rule that refused it is the evidence.
	denied := r.Rule != "" && strings.HasPrefix(r.Status, "403 denied")
	if r.Labels != nil {
		// Labels from the broker's snapshot: the policy that decided this
		// request, not whatever is current when the row is written.
		e.Labels = r.Labels
	}
	if svc, ok := o.live.Config().Service(r.Service); ok {
		if e.Labels == nil {
			e.Labels = svc.Labels()
		}
		if denied {
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
	if err := o.Led.Append(e); err != nil {
		fmt.Fprintln(os.Stderr, "stk: could not write the audit ledger:", err)
	}
}

// NewObserver wires a broker to the durable ledger.
func NewObserver(cfg *policy.Config, dir, caller string) (Observer, error) {
	return NewObserverLive(livepolicy.Static(cfg), dir, caller)
}

// NewObserverLive is newObserver over a reloadable policy.
func NewObserverLive(live *livepolicy.Config, dir, caller string) (Observer, error) {
	led, err := ledger.Open(dir)
	if err != nil {
		return Observer{}, err
	}
	return Observer{live: live, Led: led, Caller: caller}, nil
}

func Command(args []string) error {
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
	dir, err := localstate.Home()
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
			e.When.Local().Format("Jan 02 15:04:05"), EscapeControl(e.Service), EscapeControl(e.Capability),
			EscapeControl(e.Policy), EscapeControl(e.Outcome))
		fmt.Printf("  %18s%s %s · credential: %s\n", "", EscapeControl(e.Method), EscapeControl(e.Path), EscapeControl(e.Credential))
		if e.Rule != "" {
			fmt.Printf("  %18srule: %s\n", "", EscapeControl(e.Rule))
		}
		if e.Addr != "" {
			fmt.Printf("  %18saddress: %s\n", "", EscapeControl(e.Addr))
		}
		if len(e.Labels) > 0 {
			fmt.Printf("  %18slabels: %s\n", "", formatLabels(e.Labels))
		}
	}
	fmt.Println()
	fmt.Println("  no credential is recorded here — a fingerprint or the operation that replaced it")
	return nil
}

// ForUI reads the same file the CLI reads, so the two cannot disagree
// about what happened.
func ForUI(dir string) func(int) []webui.Effect {
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

// Fingerprint describes a credential without being it, the same way the broker
// does: a short SHA-256 prefix. Two requests carrying the same credential show
// the same fingerprint, which is enough to tell them apart without the value.
func Fingerprint(s string) string {
	if s == "" {
		return "(absent)"
	}
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])[:12]
}

// escapeControl makes request-derived text safe to print on a terminal: C0
// controls and DEL become \xNN, C1 controls become \u00NN. A request path is
// attacker-chosen, and its decoded form can carry an ESC or a newline.
func EscapeControl(s string) string {
	clean := true
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// formatLabels prints labels as sorted key=value pairs. Labels are set by the
// operator and validated at load, but a ledger line is just a file: escape
// them on print like every other field.
func formatLabels(l map[string]string) string {
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, EscapeControl(k)+"="+EscapeControl(l[k]))
	}
	return strings.Join(parts, " ")
}

// CallerKey carries the per-request caller through to the audit observer.
type CallerKey struct{}

// WithCallerUID attributes effects performed under ctx to a kernel-reported
// uid, which is the only identity on the control socket that is not a claim.
func WithCallerUID(ctx context.Context, uid int) context.Context {
	return context.WithValue(ctx, CallerKey{}, fmt.Sprintf("uid:%d", uid))
}
