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
	return &session{broker: b, env: env, stop: func() { ln.Close() }}, nil
}

// childEnv builds the environment a brokered child runs with.
//
// Three things here come straight from spiking real clients:
//
//   - NODE_USE_ENV_PROXY is set, because Node's fetch ignores proxy environment
//     variables by default and would otherwise go straight out and succeed,
//     which is the silent failure this product exists to prevent.
//   - NO_PROXY is cleared, because it is a confirmed bypass: anything that can
//     set it can opt itself out of the broker.
//   - The CA is announced in four different variables, because curl, Go, Python
//     and Node each read a different one.
func childEnv(cfg *policy.Config, proxyURL, caPath string) []string {
	env := os.Environ()
	drop := map[string]bool{
		"NO_PROXY": true, "no_proxy": true, // a confirmed bypass
		"HTTPS_PROXY": true, "https_proxy": true,
		"HTTP_PROXY": true, "http_proxy": true,
	}
	out := make([]string, 0, len(env)+10)
	for _, kv := range env {
		name := kv
		if i := indexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if drop[name] {
			continue
		}
		out = append(out, kv)
	}
	out = append(out,
		"HTTPS_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"SSL_CERT_FILE="+caPath,
		"CURL_CA_BUNDLE="+caPath,
		"REQUESTS_CA_BUNDLE="+caPath,
		"NODE_EXTRA_CA_CERTS="+caPath,
		"NODE_USE_ENV_PROXY=1",
		"STK_BROKERED=1",
	)
	// The placeholder goes where each client expects its credential.
	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		if v := svc.Entry().EnvVar; v != "" {
			out = append(out, v+"="+broker.Placeholder(name))
		}
	}
	return out
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
