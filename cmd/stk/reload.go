package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// liveState is one policy and the acquirers built for it, replaced whole.
type liveState struct {
	cfg  *policy.Config
	acqs *acquirers
}

// liveConfig is the one current policy of a running `stk serve`, shared by
// the daemon path, the audit observer and the proxy's secret source, so a
// reload reaches all three through one swap. The broker keeps its own
// snapshot (it also holds a host map) and is swapped in the same reload.
type liveConfig struct {
	p atomic.Pointer[liveState]
}

func newLive(cfg *policy.Config, store *credential.Store, client *http.Client) *liveConfig {
	l := &liveConfig{}
	// The OAuth 2.0 refresh reads the policy through l, so it follows reloads.
	l.p.Store(&liveState{cfg: cfg})
	l.p.Store(&liveState{cfg: cfg, acqs: newAcquirersFn(l.config, store, client)})
	return l
}

// staticLive holds a policy that is never reloaded, for entry points such as
// `stk run`, `stk mcp` and tests that only have a *policy.Config.
func staticLive(cfg *policy.Config) *liveConfig {
	l := &liveConfig{}
	l.p.Store(&liveState{cfg: cfg})
	return l
}

func (l *liveConfig) config() *policy.Config { return l.p.Load().cfg }
func (l *liveConfig) state() *liveState      { return l.p.Load() }

// reloadResult is what a reload did, and the `stk reload --json` shape.
type reloadResult struct {
	OK      bool     `json:"ok"`
	Removed []string `json:"removed,omitempty"`
	Added   []string `json:"added,omitempty"`
	Changed []string `json:"changed,omitempty"`
	// KeptCredentials are removed services whose credential is still stored.
	// A reload never deletes a credential; `stk revoke` does.
	KeptCredentials []string `json:"credentials_kept,omitempty"`
	Error           string   `json:"error,omitempty"`
}

// MarshalJSON always emits the three lists on success, empty rather than
// absent, so a caller can index them without a nil check.
func (r reloadResult) MarshalJSON() ([]byte, error) {
	type plain reloadResult
	if !r.OK {
		return json.Marshal(struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}{false, r.Error})
	}
	nz := func(s []string) []string {
		if s == nil {
			return []string{}
		}
		return s
	}
	return json.Marshal(struct {
		OK              bool     `json:"ok"`
		Removed         []string `json:"removed"`
		Added           []string `json:"added"`
		Changed         []string `json:"changed"`
		KeptCredentials []string `json:"credentials_kept,omitempty"`
	}{true, nz(r.Removed), nz(r.Added), nz(r.Changed), r.KeptCredentials})
}

// summary is the text-mode report.
func (r reloadResult) summary() string {
	if !r.OK {
		return "reload failed, the previous policy is still in force: " + r.Error
	}
	if len(r.Removed)+len(r.Added)+len(r.Changed) == 0 {
		return "policy reloaded; no service changed"
	}
	var b strings.Builder
	b.WriteString("policy reloaded")
	for _, part := range []struct {
		label string
		names []string
	}{{"added", r.Added}, {"removed", r.Removed}, {"changed", r.Changed}} {
		if len(part.names) > 0 {
			fmt.Fprintf(&b, " · %s: %s", part.label, strings.Join(part.names, ", "))
		}
	}
	if len(r.KeptCredentials) > 0 {
		fmt.Fprintf(&b, "\n  still stored, a credential for removed service(s): %s (reload deletes none; `stk revoke <service>` does)",
			strings.Join(r.KeptCredentials, ", "))
	}
	return b.String()
}

// reloader re-reads the policy file and applies it to a running serve.
type reloader struct {
	mu     sync.Mutex // one reload at a time
	path   string
	live   *liveConfig
	broker *broker.Broker
	store  *credential.Store
	client *http.Client
}

func newReloader(path string, live *liveConfig, b *broker.Broker, store *credential.Store) *reloader {
	return &reloader{path: path, live: live, broker: b, store: store, client: &http.Client{Timeout: 60 * time.Second}}
}

// reload validates the whole file with policy.Load before touching anything.
// A file that does not load leaves the old policy in force everywhere.
//
// The broker and the shared holder are two stores, not one: in the instant
// between them a request may see the new rules in the proxy while the daemon
// path still sees the old policy. Each request is still decided by exactly one
// policy, and the mismatch can only refuse (an unknown service has no
// credential), never send under a removed service.
func (r *reloader) reload() reloadResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	next, err := policy.Load(r.path)
	if err != nil {
		return reloadResult{Error: err.Error()}
	}
	old := r.live.state()
	state := &liveState{cfg: next}
	if old.acqs != nil {
		state.acqs = &acquirers{
			githubApp: old.acqs.githubApp,
			oauth2:    old.acqs.oauth2,
			forgeApp:  forgeAppAcquirers(next, r.store, r.client, old.acqs.forgeApp),
		}
	}
	if r.broker != nil {
		if err := r.broker.Reload(next); err != nil {
			return reloadResult{Error: err.Error()}
		}
	}
	r.live.p.Store(state)

	res := diffServices(old.cfg, next)
	for _, name := range res.Removed {
		if r.store != nil && r.store.Has(name) {
			res.KeptCredentials = append(res.KeptCredentials, name)
		}
	}
	return res
}

// diffServices names services removed, added and changed. Changed means a
// difference in host, repositories, preset, rules, allow_graphql or labels.
func diffServices(old, next *policy.Config) reloadResult {
	res := reloadResult{OK: true}
	for _, name := range old.Services() {
		o, _ := old.Service(name)
		n, ok := next.Service(name)
		switch {
		case !ok:
			res.Removed = append(res.Removed, name)
		case serviceChanged(o, n):
			res.Changed = append(res.Changed, name)
		}
	}
	for _, name := range next.Services() {
		if _, ok := old.Service(name); !ok {
			res.Added = append(res.Added, name)
		}
	}
	sort.Strings(res.Removed)
	sort.Strings(res.Added)
	sort.Strings(res.Changed)
	return res
}

func serviceChanged(o, n *policy.Service) bool {
	oe, ne := o.Entry(), n.Entry()
	return oe.Host != ne.Host ||
		!reflect.DeepEqual(oe.Hosts(), ne.Hosts()) ||
		oe.Auth != ne.Auth ||
		!reflect.DeepEqual(oe.Forge, ne.Forge) ||
		!reflect.DeepEqual(o.Rules(), n.Rules()) ||
		o.AllowGraphQL() != n.AllowGraphQL() ||
		!reflect.DeepEqual(o.Labels(), n.Labels())
}

// errReported is returned when the command has already written its outcome:
// main still exits non-zero.
type errReported struct{ msg string }

func (e errReported) Error() string { return e.msg }

func cmdReload(args []string) error {
	return runReload(os.Stdout, args)
}

// runReload asks the running `stk serve` to reload its policy file.
func runReload(w io.Writer, args []string) error {
	asJSON := false
	for _, a := range args {
		if a != "--json" {
			return fmt.Errorf("usage: stk reload [--json]")
		}
		asJSON = true
	}
	res := func() reloadResult {
		dir, err := home()
		if err != nil {
			return reloadResult{Error: err.Error()}
		}
		c, err := dialDaemon(dir)
		if err != nil {
			return reloadResult{Error: "no daemon is running: start `stk serve` first (" + err.Error() + ")"}
		}
		defer c.Close()
		raw, err := c.Call("reload", nil, "")
		if err != nil {
			return reloadResult{Error: "the daemon did not reload: " + err.Error()}
		}
		var r reloadResult
		if err := json.Unmarshal(raw, &r); err != nil {
			return reloadResult{Error: "unreadable answer from the daemon: " + err.Error()}
		}
		return r
	}()
	if asJSON {
		out, _ := json.Marshal(res)
		fmt.Fprintln(w, string(out))
	} else {
		fmt.Fprintln(w, "  "+res.summary())
	}
	if !res.OK {
		return errReported{res.Error}
	}
	return nil
}

// newServiceLive is newService over a reloadable policy.
func newServiceLive(live *liveConfig, store *credential.Store, dir, caller string) (*service, error) {
	return newServiceWith(live, store, dir, caller)
}
