# Serving fronted MCP servers directly, and deciding egress by address

**Date:** 2026-10-22
**Status:** implemented (`internal/egress`, `internal/mcpserve`, `internal/netjail`, `stk mcp serve`). Added in implementation: `network: watched` (detect and stop) for hosts that cannot confine, and the matched *allow* rule id is now recorded on every brokered request, not only denials.

## Why

SuperToolkit has to manage two kinds of third-party tool for an agent: CLIs and
MCP servers. CLIs work today and are proven on staging (`git`, `auth: none`,
push denied by rule). MCP servers do not, for two reasons that
[limitations.md](limitations.md) records:

1. A fronted server (`servers:`) reaches an agent only through stk's four
   meta-tools. An agent host that wants the server's own tools, under their own
   names, cannot have them through stk.
2. stk cannot make a fetch-style server SSRF-safe. Its rules match paths on
   declared hosts. A request to a host not named in policy is tunnelled unopened
   **and not recorded**, and nothing can say "any public host, but no loopback,
   private, link-local or tailnet address".

So the reference `mcp-server-fetch`, the commonest MCP server there is, cannot be
given to an agent with a guarantee. This spec closes both gaps.

## What changes

### 1. `stk mcp serve <server>`

A new entry point speaks MCP on stdio and exposes **one fronted server's own
tools under their own names**. `stk mcp` (the four meta-tools) is unchanged.

```
stk mcp serve fetch                      # use the broker daemon if one answers
stk mcp serve fetch --standalone         # in-process broker, for a laptop
stk mcp serve fetch --socket /run/stk/stk.sock
```

- `initialize`, `ping`, `tools/list` and `tools/call` are answered.
  `tools/list` is the child's list, filtered by policy: a tool the profile does
  not allow, or whose policy is `deny`, is not listed.
- **Every `tools/call` is decided by stk and recorded**, allowed or denied, with
  a rule id, before the child is asked. The child is never consulted about
  whether it may act. A call to an unlisted tool is decided (and denied) too,
  because a client can call a name it was not shown.
- Rule ids name where the decision came from:
  `server:<name>/capabilities.<tool>` (the operator's explicit word),
  `server:<name>/default.read-only-hint` (the child annotated it read-only),
  `server:<name>/default.unannotated` (approval, the safe default),
  `profile:<profile>` (the profile does not include it).
- A tool whose policy is `approval` is refused by `mcp serve` with its rule id
  and the reason. Holding a direct tool call open for a person is a different
  interaction from the meta-tools' `pending` state and is not built here; the
  meta-tools path keeps approval as it is.
- With a daemon, the decision and the audit row are made **by the daemon**, from
  the policy it holds, over the control socket (`mcp.spec`, `mcp.decide`,
  `mcp.done`). The caller's uid is the kernel's answer, as for every socket
  method. Without one (`--standalone`) the same decision runs in process against
  the local policy and ledger.
- The child runs as the caller (the agent's user), never as the broker's user:
  it therefore cannot read the store, and no credential is in its environment —
  only a placeholder, exactly as today.
- HTTP transport is not part of this slice.

### 2. Egress decided by address

A new policy block, accepted at the top level (the workspace default for hosts
not named in policy) and on a server (that server's egress):

```yaml
egress:
  preset: public-only        # or "none" (the default): no address is refused by class
  allow: [203.0.113.7/32]    # exceptions: CIDRs or class names
  deny:  [198.51.100.0/24]   # always wins over allow and preset
  schemes: [https, http]     # what the proxy accepts for this egress
  methods: [GET]             # empty = any; set = the tunnel is opened and each request checked
```

Address classes, each usable by name in `allow`/`deny`:

| class | ranges |
|---|---|
| `loopback` | 127.0.0.0/8, ::1 |
| `private` | 10/8, 172.16/12, 192.168/16 |
| `link-local` | 169.254/16 (cloud metadata), fe80::/10 |
| `cgnat` | 100.64/10 (tailnets) |
| `ula` | fc00::/7 |
| `unspecified` | 0.0.0.0/8, :: |
| `multicast` | 224/4, ff00::/8 |
| `reserved` | 240/4 incl. broadcast, 192.0.0/24, 198.18/15, documentation ranges, 2001:db8::/32 |

IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`)
addresses are classified by the IPv4 address they carry, so they cannot launder
a private one.

Decision order: `deny` (rule `egress:deny#n`), then `allow` (`egress:allow#n`),
then the preset (`egress:public-only/<class>` refuses, `egress:public-only`
allows), then `egress:default` allows.

**Where it applies.** In the broker, at the moment it dials, never earlier:

- The hostname is resolved by the broker, and **every** resolved address must be
  allowed; one refused address refuses the request. The connection is then made
  to the decided address itself, not the name, so a second DNS answer cannot
  change where it goes (DNS rebinding).
- A literal IP in the request is decided as itself; no resolution.
- A redirect is a new request from the client — the broker never follows one —
  so every hop is decided afresh, by the same code.
- A refusal is answered before the tunnel is established (`403` to the
  `CONNECT`), so nothing reaches the destination.

**Who it applies to.** The proxy learns which server a request is for from the
proxy credential's user name: `stk+<server>` (the key is unchanged and still
optional). `stk mcp serve` gives its child that identity. A request without
one gets the workspace `egress`.

**Closing the unrecorded gap.** A `CONNECT` to a host outside policy is now
always recorded, whether or not any egress is declared. When no egress applies
it is still tunnelled unopened, and the record says `tunnelled, not decided`.
When egress applies, it is decided as above and recorded with the rule id and
the address dialled.

**Plain HTTP.** The proxy has spoken only `CONNECT`. An egress that lists `http`
in `schemes` accepts absolute-form `http://` requests too, decided the same way,
with the proxy credential stripped before forwarding. Anything else keeps the
`400`.

**Methods.** With `methods` set, an allowed `CONNECT` is intercepted with the
broker's CA (the child already trusts it) so each request's method can be
checked and its path recorded; refusals carry `egress:method`. A client that
refuses the CA fails loudly, which is the safe class.

### 3. The child's own network: blocked, not merely detected

A proxy cannot see a client that never speaks to it. For a fronted server stk
starts, that is fixable: on Linux the child is started in **its own user and
network namespace**, which has only a loopback interface. Inside it, a small shim
(`stk __netjail`, the same binary) listens on `127.0.0.1:<port>` and relays each
connection over a Unix socket to the broker. The child's `HTTPS_PROXY` points at
that port. Any connection the child makes to anything else has no route, and
DNS has no server: direct egress **fails**, it is not just reported.

- `network: confined` is the default for a server with `egress`. If the
  namespace cannot be created (for example Ubuntu's
  `kernel.apparmor_restrict_unprivileged_userns=1` with no AppArmor profile for
  stk) `mcp serve` refuses to start the child and says why — it does not fall
  back to an unconfined child.
- `network: host` opts out, explicitly; the child is then only configured, not
  confined, as every `stk run` child is today. Not available on macOS, where
  `confined` is refused.
- The staging deploy installs an AppArmor profile that grants `userns` to the
  stk binary and nothing else.

### 4. A fetch profile

A documented recipe, used verbatim on staging:

```yaml
egress: { preset: public-only }          # the workspace default
servers:
  fetch:
    command: /home/salaam/.local/bin/mcp-server-fetch   # mcp-server-fetch==2026.10.10
    args: [--ignore-robots-txt]
    egress:
      preset: public-only
      schemes: [https, http]
      methods: [GET]
    capabilities:
      fetch: agent
```

`host:` becomes optional for a server with no credential (`env_var` unset).

### 5. A hostname allowlist: `hosts:` (local commands)

Operator ruling 2026-10-30. An address preset answers "any public host". A sandboxed command
that runs `npm install` needs something narrower: "these registries and nothing else". An
`egress:` block with `hosts:` allows exactly the listed names:

```yaml
servers:
  local-commands:            # the identity Salaam's local commands present to the proxy
    command: none
    network: host
    egress:
      hosts:
        - registry.npmjs.org         # exact name, https (port 443) only
        - "*.pythonhosted.org"       # every name under it, not pythonhosted.org itself
        - http://deb.debian.org      # also plain http and port 80, for this host only
```

- **Before DNS.** The CONNECT target name is checked against the list before any lookup, so an
  unlisted host is never resolved or dialled. Names are lower-cased and IDNA-encoded, and a
  trailing dot is ignored. An IP literal is refused (`egress:hosts/ip-literal`).
- **Then the address.** A `hosts:` egress defaults to `preset: public-only`, so a listed name that
  resolves to this machine, its network or the metadata service is still refused. The dial is
  pinned to the decided address, as for every egress.
- **Ports.** Only 443, plus 80 for a host listed as `http://`. Plain `http://` requests reach only
  hosts listed that way (`egress:hosts/http-not-listed`).
- **Empty means nothing.** `hosts: []` refuses every host. With no `hosts:` key, there is no
  hostname check, which is the behaviour before this change.
- **Refusals name the fix.** `egress:hosts/not-listed`, `egress:hosts/port`, and so on. The body
  says the host operator adds the host to this server's `egress.hosts`. Every allow and deny is
  recorded with the identity, host, port and rule (`egress:hosts#N+egress:public-only` when
  allowed).
- **Who sets it.** The host operator only, in the root-owned stk policy file. There is no API.
- **Not covered.** A host that stk brokers as a *service* (a policy entry with its own rules and
  credentials) is decided by that service's rules, not by `hosts:`, for every identity.

### 6. The local-commands socket: the identity is the socket's

A command can read its own `HTTP_PROXY`. On the shared proxy, the user name `stk+<server>` only
selects an identity, so a command could rename itself `stk+fetch` and take fetch's wider egress.
Operator ruling 2026-10-30: local commands get their own socket instead.

```
stk serve --local-commands-socket /run/stk/local-commands.sock --local-commands-mode 0660
```

- **Every connection on it is `local-commands`,** whatever user name it sends. A claimed
  `stk+<other>` is ignored and recorded (rule `local-commands:identity-forced`, with the claim in
  the status).
- **Only `servers.local-commands.egress` decides,** with no fallback to the workspace egress. If the
  policy has no egress for `local-commands`, the socket stays up and refuses every request
  (`local-commands:no-policy`). That makes a missing entry fail closed, and visible in audit.
- **No brokered service is reachable.** A host that policy brokers is refused
  (`local-commands:brokered-service`) before anything is dialled or intercepted.
- **The socket's file mode is the only gate**, so no proxy key is asked for. A key handed to a
  command is a key the command can read. Use `0660` and put the sandbox's command user in stk's
  group, or `0600` when they are the same user. The policy cannot be changed through this
  socket; it serves the proxy only, never the control plane.
- **What clients set:** a command reaches it as `HTTP_PROXY=HTTPS_PROXY=http://127.0.0.1:<port>`
  inside its sandbox. On Linux that port is a netjail relay to this socket, and on macOS a local
  relay. The user name does not matter.
- It is off unless `--local-commands-socket` is given. The main proxy and the control socket are
  unchanged.

## Tests that must hold (each revert-proof: remove the guard, the test goes red)

- loopback, private, 169.254.169.254, a 100.64/10 address and `::1` refused
  through `CONNECT` and through plain HTTP;
- a hostname that resolves to a private address refused;
- a public URL that redirects to loopback: the first hop allowed, the second
  refused, both recorded;
- DNS rebinding: a resolver whose second answer is loopback cannot move an
  allowed connection;
- public allowed, recorded with its rule id and dialled address;
- a host outside policy with no egress is recorded as tunnelled;
- `GET` allowed and `POST` refused (`egress:method`);
- `tools/call` allowed and denied, each with its rule id in the ledger, and a
  denied call never reaches the child;
- a confined child's direct connection to a listening port fails while its
  proxied request succeeds.

## Staging proof (workbench)

Pinned `mcp-server-fetch` installed for `salaam`; `fetch` configured as above;
`https://example.com` allowed and audited; `http://127.0.0.1:3101/health`,
`http://169.254.169.254/`, a tailnet `100.x` address and a redirect to loopback
refused and audited. Wired into Salaam with `salaam mcp add fetch -- stk mcp
serve fetch` if that command exists; otherwise proven with a direct MCP client.

## Not in this slice

HTTP transport for `mcp serve`; approval-held direct tool calls; port rules;
egress confinement for `stk run` children; a Linux keyring.
