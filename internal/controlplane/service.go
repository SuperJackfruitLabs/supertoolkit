package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/audit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/native"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// approvalTTL is how long an effect waits for a person before it expires.
// Expiry is not approval, so a long wait is safe and a short one is merely
// inconvenient.
const approvalTTL = 30 * time.Minute

// service bundles what the daemon serves: policy, credentials, the broker that
// performs effects, the approval queue, and any fronted MCP servers.
type Service struct {
	// live is the policy in force, read per call so `stk reload` reaches it.
	live  *livepolicy.Config
	store *credential.Store
	Queue *approval.Queue
	// Perform makes the real call with the credential attached. It is a closure
	// over the store so no credential is ever returned to a caller.
	Perform mcp.Executor

	// hosts are children we did not write, started lazily and kept running.
	hostsMu sync.Mutex
	hosts   map[string]*mcphost.Host
	// ChildEnvFor builds a child's environment. Set by the caller, because the
	// proxy address is only known once the broker is listening.
	ChildEnvFor func(server string) []string
	// Reload re-reads the policy file; nil where reloading is not offered.
	Reload func() livepolicy.Result

	// obs is the durable audit, for rows the proxy does not write: decisions
	// on a fronted server's direct tool calls.
	obs audit.Observer
	// ProxyAddr, proxyKey and caPath are what a `stk mcp serve` child needs to
	// reach this broker. The key gates use of the proxy and unlocks no secret.
	ProxyAddr, ProxyKey, CAPath string
}

// config is the policy in force now.
func (s *Service) config() *policy.Config { return s.live.Config() }

// FrontedServer starts a child on first use and reuses it after.
//
// Lazy on purpose: a workspace may declare servers an agent never touches in a
// session, and starting them all at boot would spend memory and processes on
// tools nobody asked for.
func (s *Service) FrontedServer(name string) (mcp.FrontedServer, error) {
	srv, ok := s.config().Server(name)
	if !ok {
		return nil, fmt.Errorf("unknown server %q", name)
	}
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()
	if h, ok := s.hosts[name]; ok {
		return h, nil
	}
	env := []string{}
	if s.ChildEnvFor != nil {
		env = s.ChildEnvFor(name)
	}
	h := mcphost.New(mcphost.Spec{Name: name, Command: srv.Command, Args: srv.Args, Env: env})
	if err := h.Start(context.Background()); err != nil {
		return nil, err
	}
	s.hosts[name] = h
	return h, nil
}

// CloseHosts stops every child.
func (s *Service) CloseHosts() {
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()
	for _, h := range s.hosts {
		h.Close()
	}
	s.hosts = map[string]*mcphost.Host{}
}

// New wires the pieces every entry point needs.
//
// dir is where the shared approval queue lives. It is a parameter rather than
// something looked up here because every caller already has it, and because a
// queue that quietly chose its own directory is how three processes ended up
// with three private queues.
//
// version is stk's own, sent as the User-Agent of every effect performed here.
func New(cfg *policy.Config, store *credential.Store, dir, caller, version string) (*Service, error) {
	return NewWith(livepolicy.New(cfg, store, &http.Client{Timeout: 60 * time.Second}), store, dir, caller, version)
}

func effectHTTPClient(caller string) *http.Client {
	if caller == "publish" {
		return native.ManagedClient()
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// NewWith wires a service over a shared, reloadable policy holder.
func NewWith(live *livepolicy.Config, store *credential.Store, dir, caller, version string) (*Service, error) {
	client := effectHTTPClient(caller)
	queue, err := approval.Open(dir, approvalTTL)
	if err != nil {
		return nil, err
	}
	// Effects performed here do not pass through the egress proxy, so the
	// broker's observer never sees them. Without this, the audit ledger held
	// only proxied reads and **not a single approved write** — the effects that
	// mattered enough to need a person were exactly the ones missing from the
	// record of what happened.
	obs, err := audit.NewObserverLive(live, dir, caller)
	if err != nil {
		return nil, err
	}
	return &Service{
		live: live, store: store, Queue: queue, obs: obs,
		hosts: map[string]*mcphost.Host{},
		Perform: func(ctx context.Context, svcName string, req *http.Request) (*http.Response, error) {
			ctx = context.WithValue(ctx, audit.CallerKey{}, caller)
			svc, ok := live.Config().Service(svcName)
			if !ok {
				return nil, fmt.Errorf("unknown service %q", svcName)
			}
			if svc.NativeOnly() && caller != "publish" {
				return nil, fmt.Errorf("service %q is reserved for the native publisher", svcName)
			}
			prepared, err := native.Prepare(ctx, live, store, client, obs, version, svcName, req)
			if err != nil {
				return nil, err
			}
			return prepared.Send()
		},
	}, nil
}

// Handle answers control-plane calls. Each one resolves the caller's profile
// first, so narrowing applies to every method rather than being remembered.
func (s *Service) Handle(uid int, r daemon.Request) daemon.Response {
	cfg := s.config()
	prof, ok := cfg.Profile(r.Profile)
	if !ok {
		return daemon.Response{Error: fmt.Sprintf("unknown profile %q", r.Profile)}
	}
	srv, err := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: s.Queue, Exec: s.Perform,
		Servers:      s.FrontedServer,
		ApprovalWait: 0, // the MCP caller gets `pending`; a human decides out of band
	})
	if err != nil {
		return daemon.Response{Error: err.Error()}
	}
	switch r.Method {
	case "status":
		out, _ := json.Marshal(map[string]any{
			"workspace": cfg.Workspace,
			"services":  cfg.Services(),
			"profiles":  cfg.Profiles(),
			"pending":   len(s.Queue.Pending()),
			"tools":     mcp.ToolNames,
		})
		return daemon.Response{Result: out}
	case "reload":
		// Subject to the same socket gates as every method: the file mode and
		// the uid allowlist. It can only apply what the operator's file says.
		if s.Reload == nil {
			return daemon.Response{Error: "this process does not reload its policy"}
		}
		out, _ := json.Marshal(s.Reload())
		return daemon.Response{Result: out}
	case "mcp.spec", "mcp.decide", "mcp.visible", "mcp.done", "mcp.violation":
		out, err := s.handleMCPServe(uid, cfg, prof, r)
		if err != nil {
			return daemon.Response{Error: err.Error()}
		}
		return daemon.Response{Result: out}
	case "approvals.list":
		out, _ := json.Marshal(s.Queue.List())
		return daemon.Response{Result: out}
	case "approvals.decide":
		var p struct {
			ID    string `json:"id"`
			Allow bool   `json:"allow"`
			Who   string `json:"who"`
		}
		// Unreadable params leave p zero: an empty id, which matches no waiting effect.
		_ = json.Unmarshal(r.Params, &p)
		e, err := s.decideAndPerformCtx(audit.WithCallerUID(context.Background(), uid), p.ID, p.Allow, p.Who)
		if err != nil && e == nil {
			return daemon.Response{Error: err.Error()}
		}
		res := map[string]string{"id": p.ID, "state": string(e.State), "outcome": e.Outcome}
		if e.Error != "" {
			res["error"] = e.Error
		}
		out, _ := json.Marshal(res)
		return daemon.Response{Result: out}
	default:
		// The four meta-tools are forwarded to the MCP layer, so there is one
		// implementation and one enforcement point.
		var args map[string]string
		// The error was discarded here. A caller sending `args` as an object
		// rather than a JSON string failed to decode, left args nil, and the
		// daemon queued an approval carrying no arguments — which a person was
		// then shown as "Open an issue." with no detail and asked to approve.
		// A request we cannot read is one we must not act on.
		if err := json.Unmarshal(r.Params, &args); err != nil {
			return daemon.Response{Error: fmt.Sprintf(
				"could not read the parameters: %v — `args` must be a JSON *string*, not an object", err)}
		}
		result := srv.CallTool(audit.WithCallerUID(context.Background(), uid), r.Method, args)
		out, _ := json.Marshal(result)
		return daemon.Response{Result: out}
	}
}

// performApproved carries out an effect a person has just approved.
//
// This is the step that did not exist. Approving wrote a decision and nothing
// anywhere acted on it, so on the daemon path an approval was permanently a
// no-op, and on the stdio path it worked only while the agent happened to still
// be waiting. Both recorded `approved` either way, which made the audit trail
// assert something that had not happened.
//
// Performing here — in whichever process the person decided in — means an
// approval causes its effect regardless of who is still listening.
func (s *Service) performApproved(ctx context.Context, e *approval.Effect) (string, error) {
	cfg := s.config()
	if cfg.IsServer(e.Service) {
		// A fronted server's action is executed by its own child process, which
		// this process may not be running. Saying so is better than a silent
		// nothing, which is the bug being fixed here.
		return "", fmt.Errorf(
			"%s is a fronted MCP server; its approved actions are carried out by the agent's own session, so approve it there",
			e.Service)
	}
	svc, ok := cfg.Service(e.Service)
	if !ok {
		return "", fmt.Errorf("unknown service %q", e.Service)
	}
	req, err := svc.Entry().Request(e.Capability, e.Args)
	if err != nil {
		return "", err
	}
	resp, err := s.Perform(ctx, e.Service, req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	// Drained only so the connection can be reused; the status is the outcome.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	return resp.Status, nil
}

// DecideAndPerform is the one place a decision is acted on, so the daemon and
// the web UI cannot drift about what approving means.
func (s *Service) DecideAndPerform(id string, allow bool, who string) (*approval.Effect, error) {
	return s.decideAndPerformCtx(context.Background(), id, allow, who)
}

// decideAndPerformCtx is decideAndPerform with the caller's context, so the
// effect's audit row names who asked.
func (s *Service) decideAndPerformCtx(parent context.Context, id string, allow bool, who string) (*approval.Effect, error) {
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	// The outcome is recorded whether it succeeded or not: "approved, and it
	// failed" is a true record, and the previous behaviour — approved with no
	// outcome at all — is the one that misleads.
	return s.Queue.DecideAndPerform(id, allow, who, func(e *approval.Effect) (string, error) {
		return s.performApproved(ctx, e)
	})
}
