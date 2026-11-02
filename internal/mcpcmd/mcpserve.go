package mcpcmd

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
	"github.com/SuperJackfruitLabs/supertoolkit/internal/controlplane"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/daemon"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/ledger"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcphost"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcpserve"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/netjail"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/policy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/session"
)

const mcpServeUsage = "usage: stk mcp serve <server> [--profile <p>] [--socket <path>] [--standalone]"

// remoteGate is a Gate whose every answer comes from the daemon.
type remoteGate struct {
	c       localstate.DaemonClient
	server  string
	profile string
}

func (g *remoteGate) call(method string, p controlplane.MCPServeParams, out any) error {
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
	err := g.call("mcp.decide", controlplane.MCPServeParams{Tool: tool, Hint: hint}, &d)
	return d, err
}

func (g *remoteGate) Done(_ context.Context, tool, rule, outcome string) error {
	return g.call("mcp.done", controlplane.MCPServeParams{Tool: tool, Rule: rule, Outcome: outcome}, nil)
}

// Visible asks the daemon, which records nothing for it.
func (g *remoteGate) Visible(_ context.Context, tool string, hint policy.ToolHint) bool {
	var d mcpserve.Decision
	return g.call("mcp.visible", controlplane.MCPServeParams{Tool: tool, Hint: hint}, &d) == nil && d.Allowed
}

func (g *remoteGate) violation(remote string) error {
	return g.call("mcp.violation", controlplane.MCPServeParams{Remote: remote}, nil)
}

func cmdMCPServe(args []string, version string) error {
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
		spec      controlplane.ServeSpec
		gate      mcpserve.Gate
		violation func(remote string)
	)
	if !standalone {
		if sock == "" {
			dir, err := localstate.Home()
			if err != nil {
				return err
			}
			sock = localstate.SocketPath(dir)
		}
		dc, err := daemon.Dial(sock)
		if err != nil {
			return fmt.Errorf("no broker daemon at %s (%v); start `stk serve`, pass --socket, or run --standalone", sock, err)
		}
		c := localstate.RealClient{C: dc}
		defer c.Close()
		g := &remoteGate{c: c, server: server, profile: profile}
		raw, _ := json.Marshal(controlplane.MCPServeParams{Server: server})
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
		cfg, store, dir, err := localstate.LoadForRun()
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
		sess, err := session.Start(cfg, store, dir)
		if err != nil {
			return err
		}
		defer sess.Stop()
		ca, err := os.ReadFile(sess.CAPath)
		if err != nil {
			return err
		}
		spec = controlplane.ServeSpec{Command: srv.Command, Args: srv.Args, Env: srv.Env, EnvVar: srv.EnvVar,
			Network: srv.Network, ProxyAddr: sess.Addr, CAPEM: string(ca)}
		led, err := ledger.Open(dir)
		if err != nil {
			return err
		}
		caller := fmt.Sprintf("pid:%d mcp serve", os.Getpid())
		gate = &mcpserve.Local{Config: func() *policy.Config { return cfg }, Profile: profile, Server: server, Caller: caller, Ledger: led}
		// The child is stopped whether or not the row is written; stopping it is what matters.
		violation = func(remote string) { _ = led.Append(controlplane.ViolationEntry(server, caller, remote)) }
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
func launchFronted(ctx context.Context, server string, spec controlplane.ServeSpec, violation func(string)) (*mcphost.Host, func(), error) {
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
