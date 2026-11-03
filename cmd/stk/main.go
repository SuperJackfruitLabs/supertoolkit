// Command stk is supertoolkit's CLI and broker.
//
// The agent never holds a credential. `stk run` starts a broker, hands the child
// a worthless placeholder, and substitutes the real credential on the wire.
package main

import (
	"fmt"
	"os"

	"github.com/SuperJackfruitLabs/supertoolkit/internal/audit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/credcmd"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/doctor"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/livepolicy"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/localstate"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/managedtoolkit"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/mcpcmd"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/netjail"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/proxyenv"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/publishcmd"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/serve"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/session"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/setup"
	"github.com/SuperJackfruitLabs/supertoolkit/internal/uicmd"
)

// version is a var, not a const, because the release build stamps it with
// -ldflags "-X main.version=...". As a const the linker flag is silently
// ignored and every released binary reports the development version — which is
// exactly what happened the first time scripts/release.sh ran.
var version = "0.0.1-dev"

func usage() {
	fmt.Fprint(os.Stderr, `stk — supertoolkit

  stk init                    create the local CA and a starter supertoolkit.yaml
  stk add <service>...        add services, with safe default policy
  stk connect <service>       store a credential, read from stdin
  stk connect <service> --device
                              connect with no browser on this machine (RFC 8628)
  stk connect <service> --browser
                              connect via OAuth 2.0 authorization code + PKCE
  stk handover key|seal|open  move a credential to a broker that has no browser
  stk run -- <command>        run a command with the broker in front of it
  stk serve                   run the broker daemon on a Unix socket
  stk serve --proxy-listen <loopback host:port>
                              also keep the egress proxy on a fixed port, key required
  stk reload [--json]         re-read supertoolkit.yaml into the running serve (also SIGHUP)
  stk env [--json]            print the proxy URL, CA and placeholders for that proxy
  stk mcp [--profile <p>]     speak MCP on stdio, four meta-tools
  stk mcp serve <server> [--profile <p>] [--socket <path>] [--standalone]
                              serve one fronted MCP server's own tools, each call
                              decided and audited, its egress through the broker
  stk install --user <name>    run stk as its own OS user under systemd (Linux)
  stk mcp install <host>       print the client configuration (no secret in it)
  stk verify <service> [--expect-login <login>] [--json]
                              prove a stored credential works, and as whom
  stk revoke <service> [--local]
                              withdraw a credential, here and at the provider
  stk audit [--limit n] [--json]
                              what the broker actually did, newest first
  stk approvals [allow|refuse <id>]
                              what is waiting on you, and decide it
  stk publish submit|perform <id>|recover
                              durable SuperPipeline-gated automatic X publishing
  stk ui [--bind addr] [--no-open]
                              the five screens, on a one-time link
  stk doctor                  check the setup, and prove no credential leaks
  stk doctor --probe          prove each client here actually goes through the broker
                              (exit 1 on a bypass; --json for a machine-readable list;
                              --with-proxy-key probes through a keyed broker)
  stk doctor --json [--agent-uid <uid>]...  checks and the isolation verdict as JSON
  stk version

The agent never holds a credential. Known services: `)
	fmt.Fprintln(os.Stderr, localstate.KnownServices())
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case netjail.ShimCommand:
		// Inside a confined child's namespace; never typed by a person.
		code, serr := netjail.Shim(os.Args[2:])
		if serr != nil {
			fmt.Fprintln(os.Stderr, "stk:", serr)
		}
		os.Exit(code)
	case netjail.ShimCommand + "-probe":
		if perr := netjail.ProbeChild(); perr != nil {
			fmt.Fprintln(os.Stderr, perr)
			os.Exit(1)
		}
		os.Exit(0)
	case "init":
		err = setup.Init()
	case "add":
		err = setup.Add(os.Args[2:])
	case "connect":
		err = setup.Connect(os.Args[2:])
	case "handover":
		err = setup.Handover(os.Args[2:])
	case "run":
		err = session.Command(os.Args[2:])
	case "serve":
		err = serve.Command(os.Args[2:], version)
	case "reload":
		err = livepolicy.Command(os.Args[2:])
	case "install":
		err = cmdInstall(os.Args[2:])
	case "env":
		err = proxyenv.Command(os.Args[2:])
	case "mcp":
		err = mcpcmd.Command(os.Args[2:], version)
	case "managed-mcp-v1":
		err = managedtoolkit.MCP(os.Args[2:], version)
	case "managed-evidence-v1":
		err = managedtoolkit.Evidence(os.Args[2:])
	case "managed-control-v1":
		err = managedtoolkit.Control(os.Args[2:])
	case "verify":
		err = credcmd.Verify(os.Args[2:])
	case "revoke", "forget":
		err = credcmd.Revoke(os.Args[2:])
	case "audit":
		err = audit.Command(os.Args[2:])
	case "approvals", "approval":
		err = mcpcmd.Approvals(os.Args[2:])
	case "publish":
		err = publishcmd.Command(os.Args[2:], version)
	case "ui":
		err = uicmd.Command(os.Args[2:], version)
	case "doctor":
		err = doctor.Command(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("stk", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "stk: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "stk:", err)
		os.Exit(1)
	}
}
