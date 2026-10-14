package main

import (
	"fmt"
	"net"
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
}

// startBroker brings up a broker on a loopback port.
//
// Phase 0 starts one per `stk run` rather than running a daemon. The long-lived
// daemon on a Unix socket, with its own OS user, is Phase 1 — this is enough to
// prove the invariant and avoids inventing lifecycle management first.
func startBroker(cfg *policy.Config, store *credential.Store, dir string) (*session, error) {
	ca, err := broker.NewCA("supertoolkit session CA", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	caPath, err := ca.WriteCert(dir)
	if err != nil {
		return nil, err
	}
	b, err := broker.New(broker.Options{
		Config: cfg, CA: ca,
		Secrets: store.Get, // the only inbound path for a secret
	})
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go b.Serve(ln)

	proxy := "http://" + ln.Addr().String()
	env := childEnv(cfg, proxy, caPath)
	forServer := func(name string) []string {
		srv, ok := cfg.Server(name)
		if !ok {
			return env
		}
		ph := map[string]string{}
		if srv.EnvVar != "" {
			ph[srv.EnvVar] = broker.Placeholder(name)
		}
		return broker.ChildEnv(broker.OSEnv(), proxy, caPath, ph, srv.Env)
	}
	return &session{broker: b, env: env, stop: func() { ln.Close() }, childEnvFor: forServer}, nil
}

// childEnv builds the environment for a command run under `stk run`, using the
// shared implementation so the placeholder, proxy and CA rules cannot drift
// from the ones a fronted MCP server gets.
func childEnv(cfg *policy.Config, proxyURL, caPath string) []string {
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
	return broker.ChildEnv(broker.OSEnv(), proxyURL, caPath, placeholders, nil)
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
