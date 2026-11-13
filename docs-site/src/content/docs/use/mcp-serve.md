---
title: Fronted servers and egress
description: stk mcp serve serves one fronted MCP server's own tools, each call decided and audited; egress decides hosts outside policy by address; the local-commands socket.
---

[From an agent](/use/from-an-agent/) covers `stk mcp`, where a fronted server's
tools appear as one category behind the four meta-tools. This page covers
serving a fronted server **under its own tool names**, deciding where its
traffic may go, and the proxy socket for sandboxed local commands.

## `stk mcp serve`

```yaml
egress: { preset: public-only }       # hosts not named in policy: public addresses only
servers:
  fetch:
    command: /usr/local/bin/mcp-server-fetch
    args: [--ignore-robots-txt]
    network: confined                 # or watched (detect and stop), or host
    egress: { preset: public-only, schemes: [https, http], methods: [GET] }
    capabilities: { fetch: agent }
```

```sh
stk mcp serve fetch                              # decisions and audit by the broker daemon
stk mcp serve fetch --socket /run/stk/stk.sock   # a daemon at another socket
stk mcp serve fetch --standalone                 # an in-process broker, for a laptop
stk mcp serve fetch --profile reader
```

It speaks MCP on stdio and answers `initialize`, `ping`, `tools/list` and
`tools/call` with the server's own tools. Without `--standalone` it needs a
daemon (`stk serve`) at the default socket or `--socket`, and refuses to start
if none answers.

- **`tools/list` is filtered by policy.** A tool the profile does not allow, or
  whose policy is `deny`, is not listed.
- **Every `tools/call` is decided by stk and recorded in `stk audit`**, allowed
  or denied, with a rule id, before the server sees it. A call to an unlisted
  tool is decided too.
- **Rule ids say where the decision came from**: `server:<name>/capabilities.<tool>`
  (your word in `capabilities:`), `server:<name>/default.read-only-hint` (the
  server annotated it read-only), `server:<name>/default.unannotated` (approval,
  the safe default), `profile:<profile>`.
- **A tool at `approval` is refused**, with its rule id. Holding a direct tool
  call open for a person is not built; the meta-tools keep approval.
- **The server runs as the caller**, never as the broker's user, with a
  placeholder (`env_var:`) instead of any credential, and the non-secret
  variables in `env:`. `host:` is the host its credential is substituted on; a
  server with no credential declares `egress:` instead.

With a daemon, the decision and the audit row are the daemon's, from the policy
it holds, over the control socket (`mcp.spec`, `mcp.visible`, `mcp.decide`,
`mcp.done`, and `mcp.violation` for a detected bypass).

## Egress, decided by address

`egress:` decides connections to hosts that are not services in your policy. At
the top level it is the workspace default; on a server, that server's own.

```yaml
egress:
  preset: public-only        # or none (the default): no address is refused by class
  allow: [203.0.113.7/32]    # exceptions: CIDRs or class names
  deny:  [198.51.100.0/24]   # always wins over allow and preset
  schemes: [https, http]     # what the proxy accepts for this egress
  methods: [GET]             # empty = any; set = the tunnel is opened and each request checked
```

| Class | Ranges |
|---|---|
| `loopback` | 127.0.0.0/8, ::1 |
| `private` | 10/8, 172.16/12, 192.168/16 |
| `link-local` | 169.254/16 (cloud metadata), fe80::/10 |
| `cgnat` | 100.64/10 (tailnets) |
| `ula` | fc00::/7 |
| `unspecified` | 0.0.0.0/8, :: |
| `multicast` | 224/4, ff00::/8 |
| `reserved` | 240/4 and broadcast, 192.0.0/24, 198.18/15, the documentation ranges, 2001:db8::/32 |

IPv4-mapped, NAT64 and 6to4 addresses are classified by the IPv4 address they
carry, so they cannot launder a private one. The order is `deny`, then `allow`,
then the preset, then allow.

The broker decides **at the moment it dials**: it resolves the name itself,
every resolved address must be allowed, and the connection goes to the decided
address, not the name, so a second DNS answer cannot move it. The broker never
follows a redirect, so every hop is a new request, decided afresh. A refusal is
a `403` to the `CONNECT`, before anything reaches the destination. With `http`
in `schemes`, plain `http://` requests are accepted and decided the same way.
With `methods:`, the tunnel is opened with the broker's CA so each request's
method can be checked (`egress:method`) and its path recorded. Ports are not
rules: an allowed address is allowed on any port.

The proxy learns which server a request is for from the proxy credential's user
name, `stk+<server>`, which `stk mcp serve` gives its child. A request without
one gets the workspace `egress`.

### A hostname allowlist: `hosts:`

An address preset answers "any public host". A sandboxed `npm install` needs
"these registries and nothing else":

```yaml
egress:
  hosts:
    - registry.npmjs.org         # exactly this name, https on 443 only
    - "*.pythonhosted.org"       # every name under it, not pythonhosted.org itself
    - http://deb.debian.org      # also plain http on 80, for this host only
```

The name is checked **before DNS**, so an unlisted host is never resolved; an
IP literal is refused. A `hosts:` egress defaults to `preset: public-only`, so a
listed name that resolves to this machine or its network is still refused.
`hosts: []` refuses every host; no `hosts:` key means no hostname check.
Refusals name the rule (`egress:hosts/not-listed`, `egress:hosts/port`, …).

## A server's own network

A proxy cannot see a client that never speaks to it. For a server stk starts,
`network:` decides what happens to one that ignores the proxy:

| `network:` | |
|---|---|
| `confined` | the default for a server with `egress`. Linux only. The server runs in its own user and network namespace with only loopback, and a shim relays to the broker: a direct connection has no route, so it is **blocked**. If the namespace cannot be created, the server is not started |
| `watched` | Linux only. The server's sockets are polled; a connection to anything but the broker is **detected**, recorded as `netwatch:direct`, and the server stopped. Not prevented: the first connection happens |
| `host` | the default without `egress`, and the only mode on macOS. Configured to use the broker, not confined |

[Limitations](/limitations/#a-fronted-servers-own-network-blocked-or-only-detected)
has what each costs, and why a Go client never proxies loopback.

## The local-commands socket

A command can read its own `HTTP_PROXY`, so on the shared proxy it could rename
itself `stk+fetch` and take fetch's wider egress. Sandboxed local commands get
their own socket instead:

```sh
stk serve --local-commands-socket /run/stk/local-commands.sock --local-commands-mode 0660
```

```yaml
servers:
  local-commands:
    command: none
    network: host
    egress:
      hosts: [registry.npmjs.org, "*.pythonhosted.org"]
```

- **Every connection on it is `local-commands`**, whatever user name it sends;
  a claimed identity is ignored and recorded (`local-commands:identity-forced`).
- **Only `servers.local-commands.egress` decides**, with no fallback to the
  workspace egress. With no such egress, every request is refused
  (`local-commands:no-policy`).
- **No brokered service is reachable** through it (`local-commands:brokered-service`).
- **Its file mode is the only gate**, so no proxy key is asked for: use `0660`
  and put the sandbox's command user in stk's group, or `0600` when they are
  the same user. It serves the proxy only, never the control plane.

It is off unless `--local-commands-socket` is given.
