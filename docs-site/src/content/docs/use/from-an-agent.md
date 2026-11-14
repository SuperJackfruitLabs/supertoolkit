---
title: From an agent
description: Four MCP tools instead of a thousand, and running a child under the broker.
---

## As an MCP server

We can give an agent the whole brokered catalogue without dropping the whole
catalogue into its context. Install the small discovery surface for your client:

```sh
stk mcp install claude-code     # prints the configuration; no secret in it
stk mcp install cursor
```

`stk mcp` speaks MCP on stdio and exposes exactly **four** tools:

| Tool | For |
|---|---|
| `discover_server_categories` | what is available at all |
| `get_category_actions` | what one service can do, and whether each needs approval |
| `get_action_details` | the parameters of one action |
| `execute_action` | do it |

A hundred services cost four tool definitions of context instead of a thousand.
The agent discovers what it needs when it needs it, and the enforcement point is
the same one the CLI uses.

After installation, the client sees four stable tools and can discover the
service-specific actions only when it needs them. Context stays small; policy
does not move.

An effect at `approval` returns:

```json
{ "state": "pending", "id": "7637942b8594",
  "note": "a human must approve this before it happens; nothing has been done yet" }
```

The agent should report that and stop — not retry, not work around it. Tell the
person what is waiting and its id.

## Running any client under the broker

When an agent already has the client it needs, put the broker around the whole
process:

```sh
stk run -- your-agent
```

The child is started with `HTTPS_PROXY` pointing at the broker, the CA in the
four variables that cover curl, Python, Node and Go, and a placeholder in place
of each credential. `NO_PROXY` is deliberately cleared, because it is a
confirmed bypass.

The child now has proxy and trust settings plus worthless placeholders, not
credentials. It can make the same HTTP calls while the broker owns the secret
part.

Anything that speaks HTTP works unmodified. Before trusting a new client, prove
it actually goes through the broker:

```sh
stk doctor --probe
```

An `honoured` result is the proof you came for: that client reached the test
provider through the broker rather than wandering around it.

## Fronting an MCP server you did not write

A third-party MCP server can be started as a child with **no credential in its
environment** — a placeholder instead — and the substitution happens on egress:

```yaml
servers:
  slack:
    command: npx
    args: ['-y', '@modelcontextprotocol/server-slack']
    host: slack.com
    env_var: SLACK_BOT_TOKEN
```

Its tools appear as one category among the four meta-tools, under the same
policy as everything else. `env:` gives it non-secret variables; the
placeholder goes in `env_var:`, and `host:` is where the broker substitutes the
credential on its way out.

With the server declared, its tools join the same four-tool discovery surface
and inherit the same policy decisions as native actions. No separate secret
distribution scheme has appeared while we were not looking.

To serve the server's own tools under their own names instead, each call still
decided and audited, use [`stk mcp serve`](/use/mcp-serve/).
