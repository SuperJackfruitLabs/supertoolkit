---
title: From an agent
description: Four MCP tools instead of a thousand, and running a child under the broker.
---

## As an MCP server

```sh
stk mcp install claude-code     # prints the configuration; no secret in it
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

An effect at `approval` returns:

```json
{ "state": "pending", "id": "7637942b8594",
  "note": "a human must approve this before it happens; nothing has been done yet" }
```

The agent should report that and stop — not retry, not work around it. Tell the
person what is waiting and its id.

## Running any client under the broker

```sh
stk run -- your-agent
```

The child is started with `HTTPS_PROXY` pointing at the broker, the CA in the
four variables that cover curl, Python, Node and Go, and a placeholder in place
of each credential. `NO_PROXY` is deliberately cleared, because it is a
confirmed bypass.

Anything that speaks HTTP works unmodified. Before trusting a new client, prove
it actually goes through the broker:

```sh
stk doctor --probe
```

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
policy as everything else.
