// Command stk is supertoolkit's CLI and broker.
//
// The agent never holds a credential. `stk run` starts a broker, hands the child
// a worthless placeholder, and substitutes the real credential on the wire.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.1-dev"

func usage() {
	fmt.Fprint(os.Stderr, `stk — supertoolkit

  stk init                    create the local CA and a starter supertoolkit.yaml
  stk add <service>...        add services, with safe default policy
  stk connect <service>       store a credential, read from stdin
  stk connect <service> --device
                              connect with no browser on this machine (RFC 8628)
  stk handover key|seal|open  move a credential to a broker that has no browser
  stk run -- <command>        run a command with the broker in front of it
  stk serve                   run the broker daemon on a Unix socket
  stk mcp [--profile <p>]     speak MCP on stdio, four meta-tools
  stk mcp install <host>       print the client configuration (no secret in it)
  stk approvals [allow|refuse <id>]
                              what is waiting on you, and decide it
  stk ui [--bind addr] [--no-open]
                              the five screens, on a one-time link
  stk doctor                  check the setup, and prove no credential leaks
  stk version

The agent never holds a credential. Known services: `)
	fmt.Fprintln(os.Stderr, knownServices())
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit()
	case "add":
		err = cmdAdd(os.Args[2:])
	case "connect":
		err = cmdConnect(os.Args[2:])
	case "handover":
		err = cmdHandover(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "serve":
		err = cmdServe()
	case "mcp":
		err = cmdMCP(os.Args[2:])
	case "approvals", "approval":
		err = cmdApprovals(os.Args[2:])
	case "ui":
		err = cmdUI(os.Args[2:])
	case "doctor":
		err = cmdDoctor()
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
