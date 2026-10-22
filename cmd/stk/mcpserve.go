package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/broker"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcpserve"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/netjail"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
)

const mcpServeUsage = "usage: stk mcp serve <server> [--profile <p>] [--socket <path>] [--standalone]"

// serveSpec is what the daemon tells `stk mcp serve` about one server: how to
// start it and how its child reaches the broker. No credential is in it — the
// proxy key gates use of the proxy only, and the CA is public.
type serveSpec struct {
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env,omitempty"`
	EnvVar    string            `json:"env_var,omitempty"`
	Network   string            `json:"network"`
	ProxyAddr string            `json:"proxy_addr"`
	ProxyKey  string            `json:"proxy_key,omitempty"`
	CAPEM     string            `json:"ca_pem"`
}

type mcpServeParams struct {
	Server  string          `json:"server"`
	Tool    string          `json:"tool,omitempty"`
	Hint    policy.ToolHint `json:"hint,omitempty"`
	Rule    string          `json:"rule,omitempty"`
	Outcome string          `json:"outcome,omitempty"`
	Remote  string          `json:"remote,omitempty"`
}

// handleMCPServe answers the daemon side of `stk mcp serve`. Decisions are made
// here, from the policy this daemon holds, and recorded in its ledger: the
// caller only learns the answer.
func (s *service) handleMCPServe(uid int, cfg *policy.Config, prof *policy.Profile, r daemon.Request) (json.RawMessage, error) {
	var p mcpServeParams
	if err := json.Unmarshal(r.Params, &p); err != nil || p.Server == "" {
		return nil, fmt.Errorf("%s needs a server", r.Method)
	}
	srv, ok := cfg.Server(p.Server)
	if !ok {
		return nil, fmt.Errorf("unknown server %q; declared: %s", p.Server, strings.Join(cfg.Servers(), ", "))
	}
	caller := fmt.Sprintf("uid:%d mcp serve", uid)
	switch r.Method {
	case "mcp.spec":
		if s.proxyAddr == "" || s.caPath == "" {
			return nil, fmt.Errorf("this broker has no proxy for a fronted server to use")
		}
		ca, err := os.ReadFile(s.caPath)
		if err != nil {
			return nil, err
		}
		return json.Marshal(serveSpec{
			Command: srv.Command, Args: srv.Args, Env: srv.Env, EnvVar: srv.EnvVar, Network: srv.Network,
			ProxyAddr: s.proxyAddr, ProxyKey: s.proxyKey, CAPEM: string(ca),
		})
	case "mcp.decide":
		d := mcpserve.Decide(cfg, prof, p.Server, p.Tool, p.Hint)
		if err := s.obs.led.Append(mcpserve.DecisionEntry(p.Server, p.Tool, caller, d)); err != nil {
			// Not recorded, so not allowed.
			d = mcpserve.Decision{Policy: "deny", Rule: "audit:unwritable", Reason: err.Error()}
		}
		return json.Marshal(d)
	case "mcp.visible":
		return json.Marshal(mcpserve.Decide(cfg, prof, p.Server, p.Tool, p.Hint))
	case "mcp.done":
		return nil, s.obs.led.Append(mcpserve.DoneEntry(p.Server, p.Tool, caller, p.Rule, p.Outcome))
	case "mcp.violation":
		return nil, s.obs.led.Append(violationEntry(p.Server, caller, p.Remote))
	}
	return nil, fmt.Errorf("unknown method %s", r.Method)
}

func violationEntry(server, caller, remote string) ledger.Entry {
	return ledger.Entry{
		When: time.Now().UTC(), Service: server, Capability: "(egress)", Method: "CONNECT", Host: remote, Addr: remote,
		Policy: "deny", Caller: caller, Credential: "none", Rule: "netwatch:direct",
		Outcome: "bypass detected: the child connected around the broker and was stopped",
	}
}

// remoteGate is a Gate whose every answer comes from the daemon.
type remoteGate struct {
	c       daemonClient
	server  string
	profile string
}

func (g *remoteGate) call(method string, p mcpServeParams, out any) error {
	p.Server = g.server
	raw, _ := json.Marshal(p)
	res, err := g.c.Call(method, raw, g.profile)
	if err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(res, out)
	}
	return nil
}

func (g *remoteGate) Decide(_ context.Context, tool string, hint policy.ToolHint) (mcpserve.Decision, error) {
	var d mcpserve.Decision
	err := g.call("mcp.decide", mcpServeParams{Tool: tool, Hint: hint}, &d)
	return d, err
}

func (g *remoteGate) Done(_ context.Context, tool, rule, outcome string) error {
	return g.call("mcp.done", mcpServeParams{Tool: tool, Rule: rule, Outcome: outcome}, nil)
}

// Visible asks the daemon, which records nothing for it.
func (g *remoteGate) Visible(_ context.Context, tool string, hint policy.ToolHint) bool {
	var d mcpserve.Decision
	return g.call("mcp.visible", mcpServeParams{Tool: tool, Hint: hint}, &d) == nil && d.Allowed
}

func (g *remoteGate) violation(remote string) error {
	return g.call("mcp.violation", mcpServeParams{Remote: remote}, nil)
}

func cmdMCPServe(args []string) error {
	var server, profile, sock string
	standalone := false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; a {
		case "--profile", "-p", "--socket":
			if i+1 >= len(args) {
				return fmt.Errorf("%s needs a value (%s)", a, mcpServeUsage)
			}
			i++
			if a == "--socket" {
				sock = args[i]
			} else {
				profile = args[i]
			}
		case "--standalone":
			standalone = true
		default:
			if strings.HasPrefix(a, "-") || server != "" {
				return fmt.Errorf("unknown argument %q (%s)", a, mcpServeUsage)
			}
			server = a
		}
	}
	if server == "" {
		return fmt.Errorf(mcpServeUsage)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var (
		spec      serveSpec
		gate      mcpserve.Gate
		violation func(remote string)
	)
	if !standalone {
		if sock == "" {
			dir, err := home()
			if err != nil {
				return err
			}
			sock = socketPath(dir)
		}
		dc, err := daemon.Dial(sock)
		if err != nil {
			return fmt.Errorf("no broker daemon at %s (%v); start `stk serve`, pass --socket, or run --standalone", sock, err)
		}
		c := realClient{c: dc}
		defer c.Close()
		g := &remoteGate{c: c, server: server, profile: profile}
		raw, _ := json.Marshal(mcpServeParams{Server: server})
		res, err := c.Call("mcp.spec", raw, profile)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(res, &spec); err != nil {
			return err
		}
		gate = g
		violation = func(remote string) {
			if err := g.violation(remote); err != nil {
				fmt.Fprintln(os.Stderr, "stk: could not record a bypass:", err)
			}
		}
	} else {
		cfg, store, dir, err := loadForRun()
		if err != nil {
			return err
		}
		srv, ok := cfg.Server(server)
		if !ok {
			return fmt.Errorf("unknown server %q; declared: %s", server, strings.Join(cfg.Servers(), ", "))
		}
		if _, ok := cfg.Profile(profile); !ok {
			return fmt.Errorf("unknown profile %q", profile)
		}
		sess, err := startBroker(cfg, store, dir)
		if err != nil {
			return err
		}
		defer sess.stop()
		ca, err := os.ReadFile(sess.caPath)
		if err != nil {
			return err
		}
		spec = serveSpec{Command: srv.Command, Args: srv.Args, Env: srv.Env, EnvVar: srv.EnvVar,
			Network: srv.Network, ProxyAddr: sess.addr, CAPEM: string(ca)}
		led, err := ledger.Open(dir)
		if err != nil {
			return err
		}
		caller := fmt.Sprintf("pid:%d mcp serve", os.Getpid())
		gate = &mcpserve.Local{Config: func() *policy.Config { return cfg }, Profile: profile, Server: server, Caller: caller, Ledger: led}
		violation = func(remote string) { led.Append(violationEntry(server, caller, remote)) }
	}

	host, cleanup, err := launchFronted(ctx, server, spec, violation)
	if err != nil {
		return err
	}
	defer cleanup()
	srv := &mcpserve.Server{Name: server, Version: version, Child: host, Gate: gate}
	return srv.Serve(ctx, os.Stdin, os.Stdout)
}

// jailPort is where a confined child finds the broker, inside its own
// namespace, where nothing else listens.
const jailPort = 8899

// launchFronted prepares the child: its environment, and its network — confined
// to the broker, watched, or left alone, as policy says. It does not start it;
// the host starts it on first use.
func launchFronted(ctx context.Context, server string, spec serveSpec, violation func(string)) (*mcphost.Host, func(), error) {
	tmp, err := os.MkdirTemp("", "stk-mcp-serve-")
	if err != nil {
		return nil, nil, err
	}
	cleanups := []func(){func() { os.RemoveAll(tmp) }}
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	caPath := filepath.Join(tmp, "ca.pem")
	if err := os.WriteFile(caPath, []byte(spec.CAPEM), 0o644); err != nil {
		cleanup()
		return nil, nil, err
	}
	placeholders := map[string]string{}
	if spec.EnvVar != "" {
		placeholders[spec.EnvVar] = broker.Placeholder(server)
	}
	hs := mcphost.Spec{Name: server, Command: spec.Command, Args: spec.Args, Stderr: os.Stderr}
	proxyAddr := spec.ProxyAddr
	var host *mcphost.Host

	switch spec.Network {
	case policy.NetworkConfined:
		self, err := os.Executable()
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		// Refuse rather than start the child unconfined.
		if err := netjail.Probe(self); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("%s is declared `network: confined`, and this host cannot confine it: %w", server, err)
		}
		j, err := netjail.Open(spec.ProxyAddr)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		cleanups = append(cleanups, func() { j.Close() })
		proxyAddr = fmt.Sprintf("127.0.0.1:%d", jailPort)
		hs.Build = func() *exec.Cmd { return j.Command(self, jailPort, spec.Command, spec.Args...) }
	case policy.NetworkWatched:
		allowed, err := netip.ParseAddrPort(spec.ProxyAddr)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("the proxy address %q cannot be watched for: %v", spec.ProxyAddr, err)
		}
		hs.OnStart = func(pid int) {
			go netjail.Watch(ctx, pid, []netip.AddrPort{allowed}, 50*time.Millisecond, func(v netjail.Violation) {
				fmt.Fprintf(os.Stderr, "stk: %s connected around the broker (%s); stopping it\n", server, v)
				violation(v.Remote.String())
				host.Kill(errors.New(server + " was stopped: it connected to " + v.Remote.String() + " around the broker"))
			})
		}
	case policy.NetworkHost, "":
	default:
		cleanup()
		return nil, nil, fmt.Errorf("%s: unknown network mode %q", server, spec.Network)
	}
	hs.Env = broker.ChildEnv(broker.OSEnv(), broker.ProxyURLFor(proxyAddr, spec.ProxyKey, server), caPath, placeholders, spec.Env)
	host = mcphost.New(hs)
	cleanups = append(cleanups, func() { host.Close() })
	return host, cleanup, nil
}
