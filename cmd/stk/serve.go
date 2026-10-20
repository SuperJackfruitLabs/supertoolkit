package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// approvalTTL is how long an effect waits for a person before it expires.
// Expiry is not approval, so a long wait is safe and a short one is merely
// inconvenient.
const approvalTTL = 30 * time.Minute

// service bundles what the daemon serves: policy, credentials, the broker that
// performs effects, the approval queue, and any fronted MCP servers.
type service struct {
	// live is the policy in force, read per call so `stk reload` reaches it.
	live  *liveConfig
	store *credential.Store
	queue *approval.Queue
	// perform makes the real call with the credential attached. It is a closure
	// over the store so no credential is ever returned to a caller.
	perform mcp.Executor

	// hosts are children we did not write, started lazily and kept running.
	hostsMu sync.Mutex
	hosts   map[string]*mcphost.Host
	// childEnvFor builds a child's environment. Set by the caller, because the
	// proxy address is only known once the broker is listening.
	childEnvFor func(server string) []string
	// reload re-reads the policy file; nil where reloading is not offered.
	reload func() reloadResult
}

// config is the policy in force now.
func (s *service) config() *policy.Config { return s.live.config() }

// frontedServer starts a child on first use and reuses it after.
//
// Lazy on purpose: a workspace may declare servers an agent never touches in a
// session, and starting them all at boot would spend memory and processes on
// tools nobody asked for.
func (s *service) frontedServer(name string) (mcp.FrontedServer, error) {
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
	if s.childEnvFor != nil {
		env = s.childEnvFor(name)
	}
	h := mcphost.New(mcphost.Spec{Name: name, Command: srv.Command, Args: srv.Args, Env: env})
	if err := h.Start(context.Background()); err != nil {
		return nil, err
	}
	s.hosts[name] = h
	return h, nil
}

// closeHosts stops every child.
func (s *service) closeHosts() {
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()
	for _, h := range s.hosts {
		h.Close()
	}
	s.hosts = map[string]*mcphost.Host{}
}

// newService wires the pieces every entry point needs.
//
// dir is where the shared approval queue lives. It is a parameter rather than
// something looked up here because every caller already has it, and because a
// queue that quietly chose its own directory is how three processes ended up
// with three private queues.
func newService(cfg *policy.Config, store *credential.Store, dir, caller string) (*service, error) {
	return newServiceWith(newLive(cfg, store, &http.Client{Timeout: 60 * time.Second}), store, dir, caller)
}

// newServiceWith wires a service over a shared, reloadable policy holder.
func newServiceWith(live *liveConfig, store *credential.Store, dir, caller string) (*service, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	queue, err := approval.Open(dir, approvalTTL)
	if err != nil {
		return nil, err
	}
	// Effects performed here do not pass through the egress proxy, so the
	// broker's observer never sees them. Without this, the audit ledger held
	// only proxied reads and **not a single approved write** — the effects that
	// mattered enough to need a person were exactly the ones missing from the
	// record of what happened.
	obs, err := newObserverLive(live, dir, caller)
	if err != nil {
		return nil, err
	}
	return &service{
		live: live, store: store, queue: queue,
		hosts: map[string]*mcphost.Host{},
		perform: func(ctx context.Context, svcName string, req *http.Request) (*http.Response, error) {
			prepared, err := prepareNative(ctx, live, store, client, obs, svcName, req)
			if err != nil {
				return nil, err
			}
			return prepared.send()
		},
	}, nil
}

// authorize attaches whatever this service's scheme requires.
//
// One switch, dispatching on the catalogue's declared operation, so there is a
// single place where a credential meets a request and no second path to drift.
// Three of the four arms never put a long-lived secret on the wire.
func authorize(ctx context.Context, name string, e *catalog.Entry, req *http.Request,
	store *credential.Store, acqs *acquirers) error {
	// A device/browser grant can make a catalogue token service renewable.
	// Match the actual stored material, as the egress proxy's secretSource does.
	if refreshable(store, name) {
		tok, err := acqs.oauth2.Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}
	switch e.Auth {
	case catalog.AuthSigV4:
		m, err := store.Material(name)
		if err != nil {
			return err
		}
		return credential.SignSigV4(req, m, e.Region, e.AWSService, time.Now())

	case catalog.AuthGitHubApp:
		// The private key stays in the broker; a short-lived installation token
		// goes out, and twenty concurrent callers cause one exchange.
		tok, err := acqs.app(name).Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
		return nil

	case catalog.AuthOAuth2:
		// The refresh token stays in the broker and only ever reaches the
		// provider's own token endpoint; a short-lived access token goes to
		// the API.
		tok, err := acqs.oauth2.Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil

	default:
		secret, err := store.Get(name)
		if err != nil {
			return err
		}
		// The placeholder is written in and immediately substituted, so this
		// shares the proxy's injection path rather than duplicating it.
		if e.Placement == catalog.BearerHeader {
			req.Header.Set("Authorization", "Bearer "+broker.Placeholder(name))
		}
		credential.Inject(req, broker.Placeholder(name), secret, e.Placement, e.Field)
		return nil
	}
}

// handle answers control-plane calls. Each one resolves the caller's profile
// first, so narrowing applies to every method rather than being remembered.
func (s *service) handle(uid int, r daemon.Request) daemon.Response {
	cfg := s.config()
	prof, ok := cfg.Profile(r.Profile)
	if !ok {
		return daemon.Response{Error: fmt.Sprintf("unknown profile %q", r.Profile)}
	}
	srv, err := mcp.NewServer(mcp.Options{
		Config: cfg, Profile: prof, Queue: s.queue, Exec: s.perform,
		Servers:      s.frontedServer,
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
			"pending":   len(s.queue.Pending()),
			"tools":     mcp.ToolNames,
		})
		return daemon.Response{Result: out}
	case "reload":
		// Subject to the same socket gates as every method: the file mode and
		// the uid allowlist. It can only apply what the operator's file says.
		if s.reload == nil {
			return daemon.Response{Error: "this process does not reload its policy"}
		}
		out, _ := json.Marshal(s.reload())
		return daemon.Response{Result: out}
	case "approvals.list":
		out, _ := json.Marshal(s.queue.List())
		return daemon.Response{Result: out}
	case "approvals.decide":
		var p struct {
			ID    string `json:"id"`
			Allow bool   `json:"allow"`
			Who   string `json:"who"`
		}
		json.Unmarshal(r.Params, &p)
		e, err := s.decideAndPerformCtx(withCallerUID(context.Background(), uid), p.ID, p.Allow, p.Who)
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
		result := srv.CallTool(withCallerUID(context.Background(), uid), r.Method, args)
		out, _ := json.Marshal(result)
		return daemon.Response{Result: out}
	}
}

// callerKey carries the per-request caller through to the audit observer.
type callerKey struct{}

// withCallerUID attributes effects performed under ctx to a kernel-reported
// uid, which is the only identity on the control socket that is not a claim.
func withCallerUID(ctx context.Context, uid int) context.Context {
	return context.WithValue(ctx, callerKey{}, fmt.Sprintf("uid:%d", uid))
}

type serveArgs struct {
	listen    string
	allowUIDs []int
	// socketMode is the control socket's file mode. 0600 by default; an
	// install under its own user passes 0660 so the agent's group can reach
	// the socket at all, while --allow-uid stays the authorisation.
	socketMode os.FileMode
}

const serveUsage = "usage: stk serve [--proxy-listen <loopback host:port>] [--allow-uid <n>]... [--socket-mode 0600|0660]"

// parseSocketMode accepts only owner rw, optionally plus group rw. Anything
// reachable by other users, or with execute or special bits, is refused: the
// filesystem mode is the first gate and must never be the open one.
func parseSocketMode(v string) (os.FileMode, error) {
	n, err := strconv.ParseUint(v, 8, 32)
	if err != nil || (n != 0o600 && n != 0o660) {
		return 0, fmt.Errorf("--socket-mode must be 0600 or 0660, got %q", v)
	}
	return os.FileMode(n), nil
}

func parseServeArgs(args []string) (serveArgs, error) {
	o := serveArgs{socketMode: 0o600}
	setMode := func(v string) error {
		m, err := parseSocketMode(v)
		if err != nil {
			return err
		}
		o.socketMode = m
		return nil
	}
	addUID := func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return fmt.Errorf("--allow-uid wants a non-negative integer, got %q", v)
		}
		o.allowUIDs = append(o.allowUIDs, n)
		return nil
	}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--proxy-listen":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--proxy-listen needs a loopback host:port")
			}
			i++
			o.listen = args[i]
		case strings.HasPrefix(a, "--proxy-listen="):
			o.listen = strings.TrimPrefix(a, "--proxy-listen=")
		case a == "--allow-uid":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--allow-uid needs a uid")
			}
			i++
			if err := addUID(args[i]); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "--allow-uid="):
			if err := addUID(strings.TrimPrefix(a, "--allow-uid=")); err != nil {
				return o, err
			}
		case a == "--socket-mode":
			if i+1 >= len(args) {
				return o, fmt.Errorf("--socket-mode needs 0600 or 0660")
			}
			i++
			if err := setMode(args[i]); err != nil {
				return o, err
			}
		case strings.HasPrefix(a, "--socket-mode="):
			if err := setMode(strings.TrimPrefix(a, "--socket-mode=")); err != nil {
				return o, err
			}
		default:
			return o, fmt.Errorf("serve: unknown argument %q (%s)", a, serveUsage)
		}
	}
	return o, nil
}

func cmdServe(args []string) error {
	sa, err := parseServeArgs(args)
	if err != nil {
		return err
	}
	listen := sa.listen
	var opts brokerOpts
	if listen != "" {
		ap, err := parseProxyListen(listen)
		if err != nil {
			return err
		}
		opts.Listen = ap.String()
	}
	// SIGHUP's default action kills the process, so it is caught before any
	// startup work: a reload signal sent while serve is still starting is
	// held (one is enough) and applied once the loop below runs.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	cfg, store, dir, err := loadForRun()
	if err != nil {
		return err
	}
	if listen != "" {
		if opts.Key, err = loadOrCreateProxyKey(dir); err != nil {
			return err
		}
	}
	// One policy holder for the daemon path, the observer and the proxy's
	// secret source, so a reload reaches all of them.
	live := newLive(cfg, store, &http.Client{Timeout: 60 * time.Second})
	svc, err := newServiceWith(live, store, dir, "serve")
	if err != nil {
		return err
	}
	defer svc.closeHosts()
	opts.Live = live

	// Fronted children need the broker's address, so the broker starts first
	// and the child environment is built from it.
	sess, err := startBrokerWith(cfg, store, dir, opts)
	if err != nil {
		return err
	}
	defer sess.stop()
	if listen != "" {
		if err := writeProxyAddr(dir, sess.addr); err != nil {
			return err
		}
		defer removeProxyAddr(dir)
	}
	svc.childEnvFor = sess.childEnvFor
	rl := newReloader(configPath(), live, sess.broker, store)
	svc.reload = rl.reload

	sock := socketPath(dir)
	d, err := daemon.ListenWith(sock, svc.handle, daemon.Options{AllowUIDs: sa.allowUIDs, SocketMode: sa.socketMode})
	if err != nil {
		return err
	}
	defer d.Close()

	fmt.Printf("  listening on %s (%04o, owner uid %d)\n", sock, sa.socketMode, os.Getuid())
	if len(sa.allowUIDs) > 0 {
		fmt.Printf("  callers limited to uid(s) %v\n", sa.allowUIDs)
	}
	fmt.Printf("  workspace %q · %d service(s) · %d profile(s)\n", cfg.Workspace, len(cfg.Services()), len(cfg.Profiles()))
	if listen != "" {
		fmt.Printf("  proxy on %s (key required; `stk env` prints the settings)\n", sess.addr)
	}
	fmt.Printf("  %d meta-tools exposed to agents\n", len(mcp.ToolNames))
	fmt.Println("  ctrl-C to stop")

	errc := make(chan error, 1)
	go func() { errc <- d.Serve() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	for {
		select {
		case err := <-errc:
			return err
		case <-hup:
			// The same reload `stk reload` asks for.
			res := rl.reload()
			if res.OK {
				fmt.Println("  SIGHUP: " + res.summary())
			} else {
				fmt.Fprintln(os.Stderr, "  SIGHUP: "+res.summary())
			}
		case <-sig:
			fmt.Println("\n  stopping")
			return nil
		}
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
func (s *service) performApproved(ctx context.Context, e *approval.Effect) (string, error) {
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
	resp, err := s.perform(ctx, e.Service, req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	return resp.Status, nil
}

// decideAndPerform is the one place a decision is acted on, so the daemon and
// the web UI cannot drift about what approving means.
func (s *service) decideAndPerform(id string, allow bool, who string) (*approval.Effect, error) {
	return s.decideAndPerformCtx(context.Background(), id, allow, who)
}

// decideAndPerformCtx is decideAndPerform with the caller's context, so the
// effect's audit row names who asked.
func (s *service) decideAndPerformCtx(parent context.Context, id string, allow bool, who string) (*approval.Effect, error) {
	ctx, cancel := context.WithTimeout(parent, 60*time.Second)
	defer cancel()
	// The outcome is recorded whether it succeeded or not: "approved, and it
	// failed" is a true record, and the previous behaviour — approved with no
	// outcome at all — is the one that misleads.
	return s.queue.DecideAndPerform(id, allow, who, func(e *approval.Effect) (string, error) {
		return s.performApproved(ctx, e)
	})
}
