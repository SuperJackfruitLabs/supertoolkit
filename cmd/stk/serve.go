package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
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
	cfg   *policy.Config
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
}

// frontedServer starts a child on first use and reuses it after.
//
// Lazy on purpose: a workspace may declare servers an agent never touches in a
// session, and starting them all at boot would spend memory and processes on
// tools nobody asked for.
func (s *service) frontedServer(name string) (mcp.FrontedServer, error) {
	srv, ok := s.cfg.Server(name)
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
	client := &http.Client{Timeout: 60 * time.Second}
	acqs := newAcquirers(cfg, store, client)
	queue, err := approval.Open(dir, approvalTTL)
	if err != nil {
		return nil, err
	}
	// Effects performed here do not pass through the egress proxy, so the
	// broker's observer never sees them. Without this, the audit ledger held
	// only proxied reads and **not a single approved write** — the effects that
	// mattered enough to need a person were exactly the ones missing from the
	// record of what happened.
	obs, err := newObserver(cfg, dir, caller)
	if err != nil {
		return nil, err
	}
	return &service{
		cfg: cfg, store: store, queue: queue,
		hosts: map[string]*mcphost.Host{},
		perform: func(ctx context.Context, svcName string, req *http.Request) (*http.Response, error) {
			svc, ok := cfg.Service(svcName)
			if !ok {
				return nil, fmt.Errorf("unknown service %q", svcName)
			}
			if err := authorize(ctx, svcName, svc.Entry(), req, store, acqs); err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", "supertoolkit/"+version)
			resp, err := client.Do(req)

			rec := broker.Record{
				When: time.Now(), Service: svcName, Host: req.URL.Host,
				Method: req.Method, Path: req.URL.Path,
				AuthzFP: fingerprint(req.Header.Get("Authorization")),
			}
			switch {
			case err != nil:
				rec.Status = "request failed"
			default:
				rec.Status = resp.Status
			}
			// Injected marks that a credential was put on this request, which
			// is what makes the observer record a fingerprint rather than the
			// scheme's name.
			if rec.AuthzFP != "(absent)" {
				rec.Injected = "Authorization header"
			}
			obs.Observe(rec)
			return resp, err
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
		tok, err := acqs.githubApp.Token(ctx, name)
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
	prof, ok := s.cfg.Profile(r.Profile)
	if !ok {
		return daemon.Response{Error: fmt.Sprintf("unknown profile %q", r.Profile)}
	}
	srv, err := mcp.NewServer(mcp.Options{
		Config: s.cfg, Profile: prof, Queue: s.queue, Exec: s.perform,
		Servers:      s.frontedServer,
		ApprovalWait: 0, // the MCP caller gets `pending`; a human decides out of band
	})
	if err != nil {
		return daemon.Response{Error: err.Error()}
	}
	switch r.Method {
	case "status":
		out, _ := json.Marshal(map[string]any{
			"workspace": s.cfg.Workspace,
			"services":  s.cfg.Services(),
			"profiles":  s.cfg.Profiles(),
			"pending":   len(s.queue.Pending()),
			"tools":     mcp.ToolNames,
		})
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
		e, err := s.decideAndPerform(p.ID, p.Allow, p.Who)
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
		result := srv.CallTool(context.Background(), r.Method, args)
		out, _ := json.Marshal(result)
		return daemon.Response{Result: out}
	}
}

func cmdServe() error {
	cfg, store, dir, err := loadForRun()
	if err != nil {
		return err
	}
	svc, err := newService(cfg, store, dir, "serve")
	if err != nil {
		return err
	}
	defer svc.closeHosts()

	// Fronted children need the broker's address, so the broker starts first
	// and the child environment is built from it.
	sess, err := startBroker(cfg, store, dir)
	if err != nil {
		return err
	}
	defer sess.stop()
	svc.childEnvFor = sess.childEnvFor

	sock := socketPath(dir)
	d, err := daemon.Listen(sock, svc.handle)
	if err != nil {
		return err
	}
	defer d.Close()

	fmt.Printf("  listening on %s (0600, uid %d only)\n", sock, os.Getuid())
	fmt.Printf("  workspace %q · %d service(s) · %d profile(s)\n", cfg.Workspace, len(cfg.Services()), len(cfg.Profiles()))
	fmt.Printf("  %d meta-tools exposed to agents\n", len(mcp.ToolNames))
	fmt.Println("  ctrl-C to stop")

	errc := make(chan error, 1)
	go func() { errc <- d.Serve() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		return err
	case <-sig:
		fmt.Println("\n  stopping")
		return nil
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
	if s.cfg.IsServer(e.Service) {
		// A fronted server's action is executed by its own child process, which
		// this process may not be running. Saying so is better than a silent
		// nothing, which is the bug being fixed here.
		return "", fmt.Errorf(
			"%s is a fronted MCP server; its approved actions are carried out by the agent's own session, so approve it there",
			e.Service)
	}
	svc, ok := s.cfg.Service(e.Service)
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// The outcome is recorded whether it succeeded or not: "approved, and it
	// failed" is a true record, and the previous behaviour — approved with no
	// outcome at all — is the one that misleads.
	return s.queue.DecideAndPerform(id, allow, who, func(e *approval.Effect) (string, error) {
		return s.performApproved(ctx, e)
	})
}
