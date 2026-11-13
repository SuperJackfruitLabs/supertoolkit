---
title: Commands
description: Every stk command and flag, with the page that explains it.
---

Every command and flag `stk` has. `stk help` (or `--help`, `-h`) prints the same
list; `stk version` (or `--version`, `-v`) prints the version.

## Set up and connect

| Command | |
|---|---|
| `stk init` | create the local CA, the sealed store and a starter `supertoolkit.yaml` ([Install](/install/#first-run)) |
| `stk add <service>...` | add services, with safe default policy ([Services](/use/services/)) |
| `stk connect <service>` | store a credential, read from stdin ([Connect](/connect/)) |
| `stk connect <service> --browser` | OAuth 2.0 authorization code with PKCE |
| `stk connect <service> --device` | the device grant, for a machine with no browser |
| `stk handover key [--json]` | print this broker's hand-over key, which can only seal |
| `stk handover seal <service> --to <key> [--stdin]` | seal a credential for another broker, from this machine's store or, with `--stdin`, from a pipe, so this machine needs no store |
| `stk handover open <service>` | open a sealed envelope into this broker's store |
| `stk verify <service> [--expect-login <login>] [--json]` | make one read call as the stored credential and print the login it acts as, or why it failed; non-zero on failure, and on a login other than `--expect-login`. For a GitHub App it also checks every configured repository is in the installation |
| `stk revoke <service> [--local]` | withdraw a credential, here and, where the provider offers it, at the provider. `--local` (or `--forget`) removes only the local copy. `stk forget` is the same command |

## Run an agent

| Command | |
|---|---|
| `stk run -- <command>` | run a command with a broker in front of it ([From an agent](/use/from-an-agent/)) |
| `stk mcp [--profile <p>]` | MCP on stdio, the four meta-tools. `-p` is `--profile` |
| `stk mcp install claude-code\|cursor` | print the client configuration; no secret in it |
| `stk mcp serve <server> [--profile <p>] [--socket <path>] [--standalone]` | serve one fronted server's own tools ([Fronted servers](/use/mcp-serve/)) |
| `stk approvals` | what is waiting on you ([Approvals](/use/approvals/)). `stk approval` is the same command |
| `stk approvals allow <id>` | approve and perform it; `stk approvals approve <id>` too |
| `stk approvals refuse <id>` | refuse it; `stk approvals deny <id>` too |
| `stk audit [--limit <n>] [--json]` | what the broker did, newest first ([Audit](/use/audit/)). `-n` is `--limit` |
| `stk ui [--bind <addr>] [--no-open]` | the web interface on a one-time link ([Web interface](/reference/web-ui/)) |
| `stk publish submit\|perform <id>\|recover` | SuperPipeline-gated publishing to X; exit 3 means the gate awaits a person ([Gated publishing](/use/publish/)) |

## Run the broker for agents

| Command | |
|---|---|
| `stk serve` | the broker daemon, with `--proxy-listen`, `--allow-uid`, `--operator-uid`, `--socket-mode`, `--local-commands-socket`, `--local-commands-mode` ([Run as a service](/run/serve/)) |
| `stk install --user <name>` | run stk as its own OS user under systemd (Linux), with `--group`, `--state-dir`, `--runtime-dir`, `--config`, `--agent-uid`, `--operator-uid`, `--proxy-port`, `--unit-name`, `--dry-run` |
| `stk reload [--json]` | re-read `supertoolkit.yaml` into the running `stk serve` (or send it `SIGHUP`) |
| `stk env [--json]` | print the proxy URL, CA and placeholders for the fixed proxy |

## Check it

| Command | |
|---|---|
| `stk doctor` | check the setup, and prove no credential is reachable by a child |
| `stk doctor --probe [--json] [--with-proxy-key]` | prove each client here actually goes through the broker; exit 1 on a bypass, or when no client was exercised. `--with-proxy-key` probes through a broker that requires a proxy key |
| `stk doctor --json [--agent-uid <uid>]...` | the checks and the isolation verdict as JSON, for the agent uids in `agent_uids:` and any `--agent-uid` |

`stk doctor` reports an isolation level for the agent uids it is told about —
the top-level `agent_uids:` list in the policy file, plus any `--agent-uid`:
`separate-user` when every checked path passed for every agent uid, `same-user`
with the reasons when one did not, and `unknown` when no agent uid is configured.
The level never changes doctor's exit status.

## Internal entry points

These are called by a supervising controller, not by people, and older binaries
reject them:

| Command | |
|---|---|
| `stk managed-mcp-v1 --manifest <absolute path> --sha256 <digest>` | the four meta-tools under a private, pinned manifest, every effect verified with the controller first |
| `stk managed-evidence-v1 --manifest <absolute path> --sha256 <digest>` | one invocation's saved receipt metadata, read-only, for an `inspect` control on stdin |
| `stk managed-control-v1 --manifest <absolute path> --sha256 <digest>` | one recovery control (inspect, fence, cancel, revoke, acknowledge), read from stdin |

The protocol, the manifest shapes and what the controller must check are in the
repository's [`docs/managed-mcp.md`](https://github.com/SuperJackfruitLabs/supertoolkit/blob/main/docs/managed-mcp.md).
