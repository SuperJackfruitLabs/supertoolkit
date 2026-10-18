package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/install"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/isolation"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

// doctorProbe is the live curl probe; a variable so tests do not reach the
// network.
var doctorProbe = probeCurl

// Seams for tests of the rendering.
var (
	doctorCheckFn   = doctorChecks
	doctorIsolation = isolationReport
)

type doctorOpts struct {
	json  bool
	probe bool
	// withProxyKey runs the probe through a broker that requires a proxy key.
	withProxyKey bool
	agentUIDs    []int
	// asUIDProbe is the hidden child mode of the root access attempt: try to
	// open each path and print the ones that opened.
	asUIDProbe []string
}

func parseDoctorArgs(args []string) (doctorOpts, error) {
	var o doctorOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--json":
			o.json = true
		case a == "--probe":
			o.probe = true
		case a == "--with-proxy-key":
			o.withProxyKey = true
		case a == "--as-uid-probe":
			o.asUIDProbe = append([]string{}, args[i+1:]...)
			return o, nil
		case a == "--agent-uid" || strings.HasPrefix(a, "--agent-uid="):
			v, ok := strings.CutPrefix(a, "--agent-uid=")
			if !ok {
				if i+1 >= len(args) {
					return o, fmt.Errorf("--agent-uid needs a uid")
				}
				i++
				v = args[i]
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				return o, fmt.Errorf("--agent-uid %q is not a uid", v)
			}
			o.agentUIDs = append(o.agentUIDs, n)
		default:
			return o, fmt.Errorf("stk doctor: unknown argument %q (want --probe, --with-proxy-key, --json, --agent-uid <uid>)", a)
		}
	}
	return o, nil
}

// isolationPaths lists every path whose reach decides isolation: the state
// directory and each file in it that holds or unlocks a secret (present or
// not; absent ones are skipped by the checker), the policy file and the
// daemon socket. ca.pem is public and deliberately absent.
func isolationPaths(dir, cfgPath, sock string) []string {
	out := []string{dir}
	creds, _ := filepath.Glob(filepath.Join(dir, "*.cred"))
	sort.Strings(creds)
	out = append(out, creds...)
	for _, name := range []string{"salt", "handover.key", proxyKeyFile, proxyAddrFile,
		install.PassphraseFile, "machine.key", "ca.key", "audit.log", "approvals"} {
		out = append(out, filepath.Join(dir, name))
	}
	if cfgPath != "" {
		out = append(out, absPath(cfgPath))
	}
	return append(out, sock)
}

// secretPaths are the ones the access attempt tries to open: everything but
// the policy file (group-readable by design) and the socket.
func secretPaths(paths []string, cfgPath, sock string) []string {
	cfgPath = absPath(cfgPath)
	var out []string
	for _, p := range paths {
		if p == sock || p == cfgPath {
			continue
		}
		out = append(out, p)
	}
	return out
}

// absPath is how isolationPaths records the config path, so comparisons
// against it are exact.
func absPath(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// accessAttempt runs the opener as each agent uid. A path that opened is a
// reason; an attempt that could not run is a reason too, since it showed
// nothing.
func accessAttempt(paths []string, uids []int, run func(uid int, paths []string) ([]string, error)) []string {
	var reasons []string
	for _, uid := range uids {
		opened, err := run(uid, paths)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("access attempt as agent uid %d could not run: %v", uid, err))
			continue
		}
		for _, p := range opened {
			reasons = append(reasons, fmt.Sprintf("agent uid %d opened %s", uid, p))
		}
	}
	return reasons
}

// uidProbeChild is the child side: open each path for reading and print the
// ones that opened. Existence alone is not a reason; only a successful open.
func uidProbeChild(paths []string, out io.Writer) {
	for _, p := range paths {
		if f, err := os.Open(p); err == nil {
			f.Close()
			fmt.Fprintln(out, p)
		}
	}
}

func parseOpened(out []byte) []string {
	var opened []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			opened = append(opened, l)
		}
	}
	return opened
}

// isolationReport builds the verdict for this host.
func isolationReport(uids []int) isolation.Report {
	if len(uids) == 0 {
		return isolation.NoAgents()
	}
	dir, err := home()
	if err != nil {
		return isolation.Report{Level: isolation.SameUser, Method: isolation.MethodModeBits,
			Reasons: []string{"no state directory: " + err.Error()}}
	}
	cfgPath, sock := configPath(), socketPath(dir)
	paths := isolationPaths(dir, cfgPath, sock)
	r := isolation.CheckWith(paths, uids, isolation.Lstat,
		isolation.Options{ConfigPath: absPath(cfgPath), GOOS: runtime.GOOS, ACL: isolation.HasACL})
	// Mode bits are what the kernel will enforce, but an actual attempt is
	// stronger evidence. Only root can switch to an agent's uid, so the
	// attempt is skipped otherwise and Method says which ran.
	if os.Geteuid() == 0 {
		exe, err := os.Executable()
		var reasons []string
		if err != nil {
			reasons = []string{"access attempt could not find the stk binary: " + err.Error()}
		} else {
			reasons = accessAttempt(secretPaths(paths, cfgPath, sock), uids, uidOpener(exe))
		}
		r = isolation.WithAccess(r, reasons)
	}
	return r
}

func agentUIDsFor(o doctorOpts) []int {
	seen := map[int]bool{}
	var uids []int
	add := func(u int) {
		if !seen[u] {
			seen[u] = true
			uids = append(uids, u)
		}
	}
	if cfg, err := policy.Load(configPath()); err == nil {
		for _, u := range cfg.AgentUIDs() {
			add(u)
		}
	}
	for _, u := range o.agentUIDs {
		add(u)
	}
	return uids
}

type jsonCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Warn   bool   `json:"warn,omitempty"`
	Detail string `json:"detail"`
}

func runDoctor(args []string, out io.Writer) error {
	o, err := parseDoctorArgs(args)
	if err != nil {
		return err
	}
	if o.asUIDProbe != nil {
		uidProbeChild(o.asUIDProbe, out)
		return nil
	}
	if o.probe {
		return cmdProbe(out, o)
	}
	checks := doctorCheckFn()
	if probe := doctorProbe(); probe.label != "" {
		checks = append(checks, probe)
	}
	iso := doctorIsolation(agentUIDsFor(o))
	bad := 0
	for _, c := range checks {
		if !c.ok && !c.warn {
			bad++
		}
	}

	if o.json {
		doc := struct {
			Checks    []jsonCheck      `json:"checks"`
			Isolation isolation.Report `json:"isolation"`
		}{Isolation: iso}
		if doc.Isolation.Reasons == nil {
			doc.Isolation.Reasons = []string{}
		}
		for _, c := range checks {
			// ok means "not failed": a warning does not fail doctor.
			doc.Checks = append(doc.Checks, jsonCheck{Name: c.label, OK: c.ok || c.warn, Warn: c.warn, Detail: c.note})
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(doc); err != nil {
			return err
		}
	} else {
		for _, c := range checks {
			fmt.Fprintln(out, c)
		}
		fmt.Fprintln(out)
		// Informational: the exit code is unchanged by the isolation level.
		note := iso.Level
		if iso.Method != "" {
			note += " (" + iso.Method + ")"
		}
		if len(iso.Reasons) > 0 {
			note += " — " + strings.Join(iso.Reasons, "; ")
		}
		fmt.Fprintln(out, check{ok: iso.Level == isolation.SeparateUser, warn: iso.Level != isolation.SeparateUser,
			label: "isolation", note: note})
		fmt.Fprintln(out, "    ACLs are examined only on Linux; elsewhere they are a reason, and an ACL can grant access mode bits do not show.")
		fmt.Fprintln(out)
	}
	if bad > 0 {
		return fmt.Errorf("%d check(s) failed", bad)
	}
	if !o.json {
		fmt.Fprintln(out, doctorFooter(iso))
	}
	return nil
}

// doctorFooter claims the credential is out of reach only when isolation was
// actually shown; otherwise it says what is missing.
func doctorFooter(iso isolation.Report) string {
	if iso.Level == isolation.SeparateUser {
		return "  the agent cannot reach a credential."
	}
	return fmt.Sprintf("  isolation is not proven: %d reason(s) above (level %s).", len(iso.Reasons), iso.Level)
}
