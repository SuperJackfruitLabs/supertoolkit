package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/approval"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/catalog"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// approvalTTL is how long an effect waits for a person before it expires.
// Expiry is not approval, so a long wait is safe and a short one is merely
// inconvenient.
const approvalTTL = 30 * time.Minute

// service bundles what the daemon serves: policy, credentials, the broker that
// performs effects, and the approval queue.
type service struct {
	cfg   *policy.Config
	store *credential.Store
	queue *approval.Queue
	// perform makes the real call with the credential attached. It is a closure
	// over the store so no credential is ever returned to a caller.
	perform mcp.Executor
}

func newService(cfg *policy.Config, store *credential.Store) *service {
	client := &http.Client{Timeout: 60 * time.Second}
	acq := &credential.Acquirer{
		Material: store.Material,
		Exchange: credential.ExchangeGitHubApp("https://api.github.com", client),
	}
	return &service{
		cfg: cfg, store: store, queue: approval.New(approvalTTL),
		perform: func(ctx context.Context, svcName string, req *http.Request) (*http.Response, error) {
			svc, ok := cfg.Service(svcName)
			if !ok {
				return nil, fmt.Errorf("unknown service %q", svcName)
			}
			if err := authorize(ctx, svcName, svc.Entry(), req, store, acq); err != nil {
				return nil, err
			}
			req.Header.Set("User-Agent", "supertoolkit/"+version)
			return client.Do(req)
		},
	}
}

// authorize attaches whatever this service's scheme requires.
//
// One switch, dispatching on the catalogue's declared operation, so there is a
// single place where a credential meets a request and no second path to drift.
// Three of the four arms never put a long-lived secret on the wire.
func authorize(ctx context.Context, name string, e *catalog.Entry, req *http.Request,
	store *credential.Store, acq *credential.Acquirer) error {
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
		tok, err := acq.Token(ctx, name)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/vnd.github+json")
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
		if err := s.queue.Decide(p.ID, p.Allow, p.Who); err != nil {
			return daemon.Response{Error: err.Error()}
		}
		out, _ := json.Marshal(map[string]string{"id": p.ID, "state": map[bool]string{true: "approved", false: "refused"}[p.Allow]})
		return daemon.Response{Result: out}
	default:
		// The four meta-tools are forwarded to the MCP layer, so there is one
		// implementation and one enforcement point.
		var args map[string]string
		json.Unmarshal(r.Params, &args)
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
	svc := newService(cfg, store)
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
