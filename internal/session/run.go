package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/audit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/secrets"
)

// Session is a running broker plus the environment a child needs to reach it.
type Session struct {
	Broker *broker.Broker
	Env    []string
	Stop   func()
	// ChildEnvFor builds the environment for one fronted server: the same
	// proxy and CA as any other child, with that server's placeholder.
	ChildEnvFor func(server string) []string
	// Addr is where the proxy listens.
	Addr string
	// CAPath is the broker CA's certificate, which a child must trust.
	CAPath string
}

// Options are the choices `stk serve --proxy-listen` adds. The zero value is
// what `stk run` has always done: a random loopback port and no key.
type Options struct {
	// Listen is a loopback host:port; empty means 127.0.0.1:0.
	Listen string
	// Key, when set, is demanded of every proxy client.
	Key string
	// Live, when set, is the shared policy holder (stk serve).
	Live *livepolicy.Config
}

// Start brings up a broker on a loopback port.
//
// Phase 0 starts one per `stk run` rather than running a daemon. The long-lived
// daemon on a Unix socket, with its own OS user, is Phase 1 — this is enough to
// prove the invariant and avoids inventing lifecycle management first.
func Start(cfg *policy.Config, store *credential.Store, dir string) (*Session, error) {
	return StartWith(cfg, store, dir, Options{})
}

// StartWith is Start with a chosen listen address and proxy key.
func StartWith(cfg *policy.Config, store *credential.Store, dir string, o Options) (*Session, error) {
	// One CA per install, not per session: a fresh one here overwrote the
	// certificate every other session and `stk init` had told clients to trust.
	ca, err := broker.LoadOrCreateCA(dir, "supertoolkit local CA", 365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	caPath, err := ca.WriteCert(dir)
	if err != nil {
		return nil, err
	}
	// Every brokered effect is recorded durably, so `stk audit` and the web UI
	// can answer what happened after this process is gone.
	live := o.Live
	if live == nil {
		live = livepolicy.New(cfg, store, &http.Client{Timeout: 60 * time.Second})
	}
	obs, err := audit.NewObserverLive(live, dir, "run")
	if err != nil {
		return nil, err
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca,
		// The only inbound path for a secret, and the one place every scheme
		// is dispatched: two of them acquire a short-lived token first. It
		// reads the policy in force per call, so a reload reaches it.
		Secrets: func(service string) (string, error) {
			st := live.State()
			return secrets.SecretSource(st.Cfg, store, st.Acqs)(service)
		},
		Observer: obs,
		ProxyKey: o.Key,
	})
	if err != nil {
		return nil, err
	}
	listen := o.Listen
	if listen == "" {
		listen = "127.0.0.1:0"
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", listen)
	if err != nil {
		return nil, err
	}
	go b.Serve(ln)

	proxy := "http://" + ln.Addr().String()
	if o.Key != "" {
		proxy = broker.ProxyURL(ln.Addr().String(), o.Key)
	}
	env := ChildEnv(cfg, proxy, caPath)
	forServer := func(name string) []string {
		srv, ok := live.Config().Server(name)
		if !ok {
			return env
		}
		ph := map[string]string{}
		if srv.EnvVar != "" {
			ph[srv.EnvVar] = broker.Placeholder(name)
		}
		return broker.ChildEnv(broker.OSEnv(), proxy, caPath, ph, srv.Env)
	}
	return &Session{Broker: b, Env: env, Stop: func() { ln.Close() }, ChildEnvFor: forServer, Addr: ln.Addr().String(), CAPath: caPath}, nil
}

// ChildEnv builds the environment for a command run under `stk run`, using the
// shared implementation so the placeholder, proxy and CA rules cannot drift
// from the ones a fronted MCP server gets.
func ChildEnv(cfg *policy.Config, proxyURL, caPath string) []string {
	return ChildEnvFrom(broker.OSEnv(), cfg, proxyURL, caPath)
}

// ChildEnvFrom is childEnv over a chosen base. `stk env` passes nil so that it
// prints only what the broker sets, not the parent's environment.
func ChildEnvFrom(base []string, cfg *policy.Config, proxyURL, caPath string) []string {
	placeholders := map[string]string{}
	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		if v := svc.Entry().EnvVar; v != "" {
			placeholders[v] = broker.Placeholder(name)
		}
	}
	for _, name := range cfg.Servers() {
		srv, _ := cfg.Server(name)
		if srv.EnvVar != "" {
			placeholders[srv.EnvVar] = broker.Placeholder(name)
		}
	}
	return broker.ChildEnv(base, proxyURL, caPath, placeholders, nil)
}

func Command(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: stk run -- <command> [args...]")
	}
	cfg, store, dir, err := localstate.LoadForRun()
	if err != nil {
		return err
	}
	sess, err := Start(cfg, store, dir)
	if err != nil {
		return err
	}
	defer sess.Stop()

	bin, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	cmd := exec.CommandContext(context.Background(), bin, args[1:]...)
	cmd.Env = sess.Env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir, _ = os.Getwd()

	runErr := cmd.Run()

	st := sess.Broker.Stats()
	if st.Intercept == 0 && st.Tunnel == 0 {
		fmt.Fprintf(os.Stderr, "\nstk: warning — %s made no request through the broker.\n", filepath.Base(bin))
		fmt.Fprintf(os.Stderr, "     Some clients ignore proxy settings entirely. Run `stk doctor`.\n")
	}
	if runErr != nil {
		// Run returns an *exec.ExitError itself, never wrapped, so errors.As matches the same.
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			os.Exit(ee.ExitCode())
		}
		return runErr
	}
	return nil
}
