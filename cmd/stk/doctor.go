package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credential"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcp"
)

// check is one line of doctor output.
type check struct {
	ok    bool
	warn  bool
	label string
	note  string
}

func (c check) String() string {
	mark := "✓"
	if c.warn {
		mark = "!"
	}
	if !c.ok && !c.warn {
		mark = "✗"
	}
	s := fmt.Sprintf("  %s %s", mark, c.label)
	if c.note != "" {
		s += "  " + c.note
	}
	return s
}

// doctorChecks runs every check and returns them, so a test can assert on the
// results rather than on printed text.
func doctorChecks() []check {
	var out []check

	dir, err := home()
	if err != nil {
		return []check{{label: "local state directory", note: err.Error()}}
	}

	if fi, err := os.Stat(dir); err == nil {
		perm := fi.Mode().Perm()
		out = append(out, check{ok: perm == 0o700, label: "local state directory",
			note: fmt.Sprintf("%s mode %o", dir, perm)})
	} else {
		out = append(out, check{label: "local state directory", note: "missing — run `stk init`"})
	}

	cfg, store, _, err := loadForRun()
	if err != nil {
		out = append(out, check{label: "policy file", note: err.Error()})
		return out
	}
	out = append(out, check{ok: true, label: "policy file",
		note: fmt.Sprintf("%s · %d service(s)", configPath(), len(cfg.Services()))})

	for _, name := range cfg.Services() {
		svc, _ := cfg.Service(name)
		// What the stored credential actually does, not what the catalogue
		// expected it to be.
		auth := effectiveAuth(svc.Entry(), store, name)
		note := auth.String()
		if !store.Has(name) {
			// On a machine with no browser, `stk connect` means pasting a
			// token by hand — the habit this product exists to replace. Where
			// the headless path is available, name it here, because doctor is
			// where someone looks when a service is not working yet.
			advice := "missing — run `stk connect " + name + "`"
			if svc.Device().Supported() {
				advice += " or `stk connect " + name + " --device` with no browser here"
			}
			out = append(out, check{label: "credential for " + name, note: advice})
			continue
		}
		note += " — " + auth.Reassurance()
		out = append(out, check{ok: true, label: "credential for " + name, note: note})
	}

	// NO_PROXY is a confirmed bypass: a client that honours it goes straight
	// past the broker and returns a plausible result.
	np := os.Getenv("NO_PROXY") + os.Getenv("no_proxy")
	out = append(out, check{ok: np == "", warn: np != "", label: "NO_PROXY is unset",
		note: map[bool]string{true: "", false: "set to " + np + " — a confirmed bypass; stk run clears it for children"}[np == ""]})

	// Report where the store key really comes from, since that is how well
	// protected the credentials actually are.
	if dir2, err := home(); err == nil {
		if _, src, err := credential.StoreKey(dir2); err == nil {
			weak := src == credential.KeyFromFile
			note := string(src)
			if weak {
				note += " — anything that can read one file can read the other; an OS keychain is not wired on this platform"
			}
			out = append(out, check{ok: !weak, warn: weak, label: "credential store key", note: note})
		}
	}

	// Platform-specific CA trust, measured by spiking rather than assumed.
	if runtime.GOOS == "darwin" {
		out = append(out, check{warn: true, label: "CA trust for Go binaries",
			note: "macOS Go programs ignore SSL_CERT_FILE and read the keychain; add the CA there for tools like gh"})
	} else {
		out = append(out, check{ok: true, label: "CA trust", note: "SSL_CERT_FILE covers Go, curl, Python and Node here"})
	}

	// The four meta-tools, asserted rather than assumed, since the whole point
	// is that the catalogue never reaches an agent's context.
	out = append(out, check{ok: len(mcp.ToolNames) == 4, label: "meta-tools",
		note: fmt.Sprintf("%d exposed to agents: %s", len(mcp.ToolNames), strings.Join(mcp.ToolNames, ", "))})

	if n := len(cfg.Profiles()); n > 0 {
		out = append(out, check{ok: true, label: "profiles", note: fmt.Sprintf("%d declared: %s", n, strings.Join(cfg.Profiles(), ", "))})
	} else {
		out = append(out, check{ok: true, label: "profiles", note: "none declared, so every caller sees what policy allows"})
	}

	// Is a daemon up?
	if d, err := home(); err == nil {
		sock := socketPath(d)
		if fi, serr := os.Stat(sock); serr == nil {
			out = append(out, check{ok: fi.Mode().Perm() == 0o600, label: "daemon socket",
				note: fmt.Sprintf("%s mode %o", sock, fi.Mode().Perm())})
		} else {
			out = append(out, check{ok: true, label: "daemon socket", note: "not running; `stk run` works without it"})
		}
	}

	// The leak check: the invariant, asserted rather than claimed.
	out = append(out, leakCheck(cfg, store))
	return out
}

// leakCheck confirms no real credential is reachable from the environment a
// brokered child would run with. It is the product's promise, as a test.
func leakCheck(cfg servicesLister, store secretGetter) check {
	return leakCheckAgainst(cfg, store, childEnvForLeakCheck())
}

type servicesLister interface{ Services() []string }
type secretGetter interface{ Get(string) (string, error) }

// leakCheckAgainst takes the environment explicitly so it can be tested against
// one that really does hold a credential. A check that cannot fail is not a
// check.
func leakCheckAgainst(cfg servicesLister, store secretGetter, env []string) check {
	var secrets []string
	for _, name := range cfg.Services() {
		if s, err := store.Get(name); err == nil && s != "" {
			secrets = append(secrets, s)
		}
	}
	if len(secrets) == 0 {
		return check{ok: true, label: "leak check", note: "no credentials stored yet, so nothing is proven"}
	}
	for _, kv := range env {
		for _, s := range secrets {
			if strings.Contains(kv, s) {
				name := kv
				if i := indexByte(kv, '='); i >= 0 {
					name = kv[:i]
				}
				return check{label: "leak check", note: "a credential is present in " + name}
			}
		}
	}
	return check{ok: true, label: "leak check",
		note: fmt.Sprintf("no credential reachable from a child's environment (%d checked)", len(secrets))}
}

func childEnvForLeakCheck() []string {
	cfg, _, dir, err := loadForRun()
	if err != nil {
		return os.Environ()
	}
	return childEnv(cfg, "http://127.0.0.1:0", dir+"/ca.pem")
}

func cmdDoctor(args []string) error { return runDoctor(args, os.Stdout) }

// probeCurl proves the path end to end if curl is available, because a
// configuration that looks right and does not work is the thing doctor exists
// to catch.
func probeCurl() check {
	if _, err := exec.LookPath("curl"); err != nil {
		return check{}
	}
	cfg, store, dir, err := loadForRun()
	if err != nil {
		return check{}
	}
	sess, err := startBroker(cfg, store, dir)
	if err != nil {
		return check{label: "live probe", note: err.Error()}
	}
	defer sess.stop()

	cmd := exec.Command("curl", "-s", "-o", "/dev/null", "-m", "10", "https://example.com/")
	cmd.Env = sess.env
	_ = cmd.Run()
	st := sess.broker.Stats()
	if st.Tunnel == 0 && st.Intercept == 0 {
		return check{label: "live probe", note: "curl did not reach the broker — check HTTPS_PROXY handling"}
	}
	return check{ok: true, label: "live probe",
		note: fmt.Sprintf("curl reached the broker (%d tunnelled, %d intercepted)", st.Tunnel, st.Intercept)}
}

var _ = broker.Placeholder
