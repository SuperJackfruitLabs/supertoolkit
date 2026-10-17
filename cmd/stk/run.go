package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// session is a running broker plus the environment a child needs to reach it.
type session struct {
	broker *broker.Broker
	env    []string
	stop   func()
	// childEnvFor builds the environment for one fronted server: the same
	// proxy and CA as any other child, with that server's placeholder.
	childEnvFor func(server string) []string
	// addr is where the proxy listens.
	addr string
}

// brokerOpts are the choices `stk serve --proxy-listen` adds. The zero value is
// what `stk run` has always done: a random loopback port and no key.
type brokerOpts struct {
	// Listen is a loopback host:port; empty means 127.0.0.1:0.
	Listen string
	// Key, when set, is demanded of every proxy client.
	Key string
	// Live, when set, is the shared policy holder (stk serve).
	Live *liveConfig
}

// startBroker brings up a broker on a loopback port.
//
// Phase 0 starts one per `stk run` rather than running a daemon. The long-lived
// daemon on a Unix socket, with its own OS user, is Phase 1 — this is enough to
// prove the invariant and avoids inventing lifecycle management first.
func startBroker(cfg *policy.Config, store *credential.Store, dir string) (*session, error) {
	return startBrokerWith(cfg, store, dir, brokerOpts{})
}

// startBrokerWith is startBroker with a chosen listen address and proxy key.
func startBrokerWith(cfg *policy.Config, store *credential.Store, dir string, o brokerOpts) (*session, error) {
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
		live = newLive(cfg, store, &http.Client{Timeout: 60 * time.Second})
	}
	obs, err := newObserverLive(live, dir, "run")
	if err != nil {
		return nil, err
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca,
		// The only inbound path for a secret, and the one place every scheme
		// is dispatched: two of them acquire a short-lived token first. It
		// reads the policy in force per call, so a reload reaches it.
		Secrets: func(service string) (string, error) {
			st := live.state()
			return secretSource(st.cfg, store, st.acqs)(service)
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
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	go b.Serve(ln)

	proxy := "http://" + ln.Addr().String()
	if o.Key != "" {
		proxy = broker.ProxyURL(ln.Addr().String(), o.Key)
	}
	env := childEnv(cfg, proxy, caPath)
	forServer := func(name string) []string {
		srv, ok := live.config().Server(name)
		if !ok {
			return env
		}
		ph := map[string]string{}
		if srv.EnvVar != "" {
			ph[srv.EnvVar] = broker.Placeholder(name)
		}
		return broker.ChildEnv(broker.OSEnv(), proxy, caPath, ph, srv.Env)
	}
	return &session{broker: b, env: env, stop: func() { ln.Close() }, childEnvFor: forServer, addr: ln.Addr().String()}, nil
}

// childEnv builds the environment for a command run under `stk run`, using the
// shared implementation so the placeholder, proxy and CA rules cannot drift
// from the ones a fronted MCP server gets.
func childEnv(cfg *policy.Config, proxyURL, caPath string) []string {
	return childEnvFrom(broker.OSEnv(), cfg, proxyURL, caPath)
}

// childEnvFrom is childEnv over a chosen base. `stk env` passes nil so that it
// prints only what the broker sets, not the parent's environment.
func childEnvFrom(base []string, cfg *policy.Config, proxyURL, caPath string) []string {
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

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func cmdRun(args []string) error {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		return fmt.Errorf("usage: stk run -- <command> [args...]")
	}
	cfg, store, dir, err := loadForRun()
	if err != nil {
		return err
	}
	sess, err := startBroker(cfg, store, dir)
	if err != nil {
		return err
	}
	defer sess.stop()

	bin, err := exec.LookPath(args[0])
	if err != nil {
		return fmt.Errorf("%s: %w", args[0], err)
	}
	cmd := exec.Command(bin, args[1:]...)
	cmd.Env = sess.env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Dir, _ = os.Getwd()

	runErr := cmd.Run()

	st := sess.broker.Stats()
	if st.Intercept == 0 && st.Tunnel == 0 {
		fmt.Fprintf(os.Stderr, "\nstk: warning — %s made no request through the broker.\n", filepath.Base(bin))
		fmt.Fprintf(os.Stderr, "     Some clients ignore proxy settings entirely. Run `stk doctor`.\n")
	}
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return runErr
	}
	return nil
}
