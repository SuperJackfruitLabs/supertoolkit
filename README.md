# supertoolkit

A toolkit for agents with credential and auth management built in. An agent asks
for an effect by name and never holds the secret that causes it.

```
stk init                     # local CA, sealed store, a starter policy file
stk add github slack x       # services, with safe defaults
stk connect github           # the credential, from stdin — never a flag
stk run -- your-agent        # the agent runs with a placeholder, not a secret
stk audit                    # what it actually did
```

## The one invariant

> **The agent never holds, reads, or receives a credential.**

Not configurable, no override. Which effects an agent may *trigger* is policy
you set. That line is the product; everything else is detail.

## The problem

The standard way to give an agent a tool is to put an API key in an MCP config
file. That file is plaintext, any process can read it, and the agent reads it to
start the server — so the credential ends up in the agent's own context, and
from there in the transcript and wherever transcripts are kept.

supertoolkit holds the credential in a process the agent cannot read, and puts
it on the wire on the way out.

## How it works

A broker runs as its own OS user on a Unix socket. Clients — CLIs, MCP servers,
anything that speaks HTTP — are started with `HTTPS_PROXY` pointing at it and a
**placeholder** where their token would be:

```
GH_TOKEN=stk:ref:github:v1
```

The broker recognises that placeholder on the wire and does whatever the service
needs: substitutes a token, decodes and re-encodes a Basic header, signs with
SigV4, mints a JWT, or refreshes an OAuth 2.0 grant into a short-lived access
token. Clients need no modification. If an agent reads the placeholder, it has
read nothing — it means nothing off this host.

Three of the five credential operations never put a long-lived secret on the
wire at all.

## Read this before trusting it

**[docs/limitations.md](docs/limitations.md)** — what it does not do, and why.
The one failure mode that cannot be fixed by design is a client that ignores
proxy configuration entirely; it goes around the broker and fails *silently*.

That is detectable from outside, and detecting it is a command:

```
$ stk doctor --probe
  ✓ curl               honoured    the provider received the substituted credential
  ✓ python3 urllib     honoured    the provider received the substituted credential
  ✓ node fetch         honoured    the provider received the substituted credential
  ✗ go net/http        refused-ca  it would not trust the broker's certificate
```

Run it before trusting a new client. A client reported as `bypassed` must not be
brokered. A client that *refuses the certificate* is the safe case: the request
does not happen, rather than happening unbrokered.

## What is measured, not assumed

Numbers and the machine they came from: [docs/measurements.md](docs/measurements.md).

- **~79 µs median overhead** (459 µs p99) against 56 µs direct, on loopback. A
  cross-region round trip is 250–1,900 times that.
- **Bodies transparent to at least 8 MB**, hashes matching end to end, credential
  still substituted.
- **Brokered mTLS does not work** — 502, loud, nothing sent. Tunnel that host.
- **On Linux the store key is a file beside the ciphertext** — there is usually
  no OS keychain, so a credential on a server is less well protected than the
  same one on a laptop. `doctor` warns; `STK_PASSPHRASE` from your init system
  avoids it.

## Policy

One file, committed to your repository, holding no secrets:

```yaml
workspace: default
services:
  github:
    capabilities:
      create_issue: approval     # the agent proposes, you decide
  x:
    oauth2:
      client_id: <your app's client id>
profiles:
  reader:                        # a profile narrows; it can never widen
    github: [get_user, list_repos]
```

Defaults come from the catalogue and fail safe: a read is agent-callable, a
write needs approval, and anything unclassified is treated as a write. Marking a
capability `deny` is a floor that no profile can lift.

## Connecting a service

Four ways, in order of preference:

| Command | When |
|---|---|
| `stk connect <svc>` | you have the credential in hand |
| `stk connect <svc> --browser` | OAuth 2.0 authorization code + PKCE, with a browser here |
| `stk connect <svc> --device` | **no browser on this machine** — RFC 8628, approve from your phone |
| `stk handover key \| seal \| open` | last resort: seal it on a machine that has a browser |

The credential travels provider → broker. Not through a hub, not through us. The
hand-over path is the exception and
[says so](docs/limitations.md#operational-limits) rather than hiding it.

## Services

Eleven, chosen so every auth scheme and placement has a live connector behind it
rather than only a constant:

| Service | Operation |
|---|---|
| `github`, `slack`, `notion`, `openai`, `cloudflare`, `resend` | substitute a token |
| `stripe` | substitute inside a Basic header (decode, replace, re-encode) |
| `aws-sts` | sign with SigV4 — the credential is an HMAC, never a value |
| `github-app` | mint a JWT, exchange it for an installation token |
| `x`, `google` | refresh an OAuth 2.0 grant into a short-lived access token |

A service we do not front directly is reachable as a fronted MCP server: the
child gets a placeholder in its environment and nothing else.

### A git forge, defined in configuration

A self-hosted Forgejo or Gitea has a host no catalogue could name, so a forge is
declared in `supertoolkit.yaml` instead of compiled in:

```yaml
services:
  forge-main:
    kind: forge
    provider: forgejo            # forgejo | gitea | github | bitbucket
    host: forge.example.com      # a bare hostname
    scheme: bearer               # or `token` for Authorization: token <t>
    env_var: FORGEJO_TOKEN
    repositories: [acme/widgets] # owner/name, required
    preset: issues               # read | issues | pull-requests | maintain | none
```

Then `stk connect forge-main` (token on stdin) and `stk verify forge-main`, which
makes one read call as that credential and prints the login it acts as, or a
reason it failed.

**Presets are enforced.** The broker decides every request to a forge before it
fetches the credential: a request no rule allows gets a `403` that names the
rule, and nothing is sent to the provider. The preset's rules come first, then
your own `rules:`; a matching `deny` always wins, and anything not allowed is
denied.

| preset | allows (cumulative) |
|---|---|
| `read` | GET on `/user` and the configured repositories |
| `issues` | read, plus creating and editing issues, comments and issue labels |
| `pull-requests` | issues, plus opening and editing pull requests, reviews and review requests |
| `maintain` | pull-requests, plus merging pull requests, releases and repository labels |
| `none` | nothing; write every rule yourself |

No preset allows `DELETE`; `none` is empty, so a `DELETE` needs an explicit
`allow` of your own. Bitbucket has no presets yet: use `preset: none`.

```yaml
    preset: read
    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/*"
        when: {state: absent}      # a JSON body must not set `state`
      - deny: "POST /repos/{owner}/{repo}/issues/*/lock"
```

Paths are written relative to `api_prefix`. `{owner}` and `{repo}` must be used
together and match the configured repositories. Paths containing `..`, `//` or
an encoded slash are refused. GraphQL is denied by default (rule
`builtin:graphql`), because one endpoint carries every operation; setting
`allow_graphql: true` on the service stops that built-in deny. The endpoint is
then still subject to the path rules (a `POST …/graphql` needs an `allow`
rule; default deny applies), but the operation inside the request body is not
inspected, so no rule can restrict which queries or mutations run; a body
condition on a `/graphql` pattern is rejected when the config loads.
`stk audit` shows the rule that denied a request. Design:
[docs/forge-broker-design.md](docs/forge-broker-design.md).
A credential can also arrive sealed, from a machine that has it:
[docs/handover-v1.md](docs/handover-v1.md).

## Using it from an agent

`stk mcp` speaks MCP on stdio with exactly four tools — categories, actions,
details, execute — so a hundred services cost four tool definitions of context
instead of a thousand:

```
stk mcp install claude     # prints the client config; no secret in it
```

## Audit

```
$ stk audit
  Oct 15 01:12:44  x          post_tweet               approval 201 Created
                   POST /2/tweets · credential: signature (OAuth 2.0 refresh)
```

Durable, append-only, owner-only. What is recorded about the credential is a
fingerprint or the name of the operation that replaced it — never the value, and
there is a test for every scheme. The web UI (`stk ui`) reads the same file, so
the two cannot disagree.

## Running as a station service

On a machine where an agent runs as one OS user, the broker can run as another,
so the agent cannot read the sealed store, its key or the approvals. The agent
still reaches the broker, over a loopback proxy it must present a key to.

### `stk install`

```
sudo stk install --user stk --group stk --agent-uid 1001 [--agent-uid 1002]
```

Linux with systemd only; on any other OS it refuses. It must run as root and
needs at least one `--agent-uid` (without one the socket allowlist would be
empty). `--dry-run` prints the plan and the unit and changes nothing. It
creates, if absent:

- a system user (no home, `nologin`) and, with `--group`, that group;
- the state directory (default `/var/lib/stk`, `0700`), the runtime directory
  (default `/run/stk`, `0700`, or `0750` with `--group`) and the config
  directory (default `/etc/stk`, `0750 root:<group>`);
- `stk-passphrase.key` in the state directory (`0400`, random, never printed);
  the unit hands it to the service with systemd `LoadCredential`, so the
  passphrase is not in an environment file;
- `/etc/systemd/system/stk.service`, running `stk serve --proxy-listen
  127.0.0.1:<port> --socket-mode … --allow-uid …` (default port 8899).

If a config file already exists its mode is set to `0640 root:<group>`; install
never creates policy. A second run changes nothing. It refuses to run when the
state directory holds a store but no `stk-passphrase.key`, rather than add a new
passphrase over a store sealed under another key. It does not add agent users
to the group: with `--group`, you run `usermod -aG <group> <agent-user>`
yourself. Then `systemctl enable --now stk`.

### The proxy, `stk serve --proxy-listen` and `stk env`

`stk serve --proxy-listen <host:port>` (loopback addresses only) publishes the
proxy at a fixed address. It creates `proxy.key` in the state directory (`0600`)
and the broker then answers `407` to any `CONNECT` that does not carry it,
before opening any tunnel. Without `--proxy-listen`, `serve` keeps its random
loopback port and no key.

`stk env [--json]` prints the variables a client needs: the proxy URL with the
key as URL userinfo, the CA path, a placeholder for each configured service,
`NODE_USE_ENV_PROXY=1` and `STK_BROKERED=1`. Run it as a user that can read the
state directory.

The proxy key is not a service credential. It gates *use of the broker* and
nothing else: holding it lets a client use the routes policy already allows, and
unlocks no secret. The agent is still never given a credential.

Before printing the key, `stk env` verifies the listener recorded in
`proxy.addr` is a live stk proxy: the recorded pid must be running, and a
keyless `CONNECT` to a dummy host must be answered `407` with stk's own realm.
A crashed `serve` leaves a stale `proxy.addr`, and another process may since
have taken the port; the key is not handed to it. This is a check against
accident, not against a local attacker who can bind the port while stk is not
running.

`stk run` is unchanged: its per-session loopback proxy is not authenticated.

### `stk reload` and `SIGHUP`

`stk reload [--json]` (or `kill -HUP` on `stk serve`) re-reads the policy file
in the running service. A file that does not load keeps the old policy and
reports why; a service removed from the file stops being brokered, and its
stored credential is kept (`stk revoke` removes a credential).

### `stk verify`

`stk verify <service> [--expect-login <login>] [--json]` makes one read call as
the stored credential and prints the login it acts as, or the reason it failed,
and exits non-zero on failure. It never prints a token. For a GitHub App grant
it checks the app with a signed JWT and then reads the installation's
repositories; it fails if any configured repository is not in the installation.

### A GitHub App forge

```yaml
services:
  acme-app:
    kind: forge
    provider: github
    host: github.example.com     # GitHub Enterprise Server; api.github.com for github.com
    auth: app
    env_var: GH_TOKEN
    repositories: [acme/widgets, acme/gadgets]   # one owner only
    preset: issues
```

`auth: app` is GitHub-only and sends the installation token as a Bearer header
(`scheme: token` is refused with it). The owner is taken from `repositories`,
which must all belong to one account; the installation token is requested
restricted to just those repositories. For any host other than `api.github.com`
the API is served under `/api/v3`, which is the default `api_prefix`. Connect it
with `app_id`, `installation_id` and `private_key` as `field=value` lines on
stdin to `stk connect acme-app`, then `stk verify acme-app`.

### `stk doctor`: isolation

`stk doctor` also reports an isolation level for the agent uids it is told about
(the top-level `agent_uids:` list in the policy file, plus any `--agent-uid`).
The level never changes doctor's exit status. It is a claim about files, and it
claims no more than was checked:

| level | meaning |
|---|---|
| `separate-user` | every checked path passed every rule below, for every agent uid |
| `same-user` | at least one reason was found; the reasons are listed |
| `unknown` | no agent uid is configured, so nothing was checked |

The rules, per path and per parent directory up to `/`: none is owned by an
agent uid (an unknown owner counts against it); no secret-holding path (state
directory, `*.cred`, `salt`, `machine.key`, `ca.key`, `handover.key`,
`proxy.key`, `stk-passphrase.key`, `audit.log`, `approvals`) has any group or
other permission bit, since agent groups are not known; no parent directory is
group- or other-writable; no symlink leads outside the checked tree; a path that
cannot be examined for a reason other than not existing is a reason. The socket
may be group-accessible, and the policy file group-readable, by design. An agent
uid of 0 is a reason.

ACLs are examined **on Linux only**, by reading the POSIX ACL attributes: any
ACL on a checked path or parent is a reason, and so is a filesystem that cannot
say (no POSIX ACL support, NFSv4, some FUSE and overlay mounts). On macOS and
other systems ACLs cannot be read, so the report always carries that reason and
**can never be `separate-user`**.

When doctor runs as root it also makes the access attempt: it re-runs itself as
each agent uid and tries to open the secret-holding paths. Anything that opens
is a reason and forces `same-user`; the method then reads `mode-bits+access`
rather than `mode-bits`. As non-root that step is skipped and the method says so.

### `stk doctor --probe`

`stk doctor --probe` starts a real broker and a stand-in provider at a hostname
that cannot resolve, and drives curl, python3, node and a default Go client
through it (a client not installed here is `missing`). Each reports one of
`honoured`, `bypassed`, `refused-ca`, `missing` or `failed`.

The exit status is non-zero when any client is `bypassed` (it never asked the
broker) or `failed`. `refused-ca` (loud, safe) and `missing` do not fail it.

`--json` writes a JSON array to stdout and nothing else; the table goes to
stderr:

```
[{"client":"curl","outcome":"honoured","detail":"the provider received the substituted credential"}]
```

`--with-proxy-key` runs the probe through a broker that requires a proxy key,
sent in the proxy URL. A client that drops the URL's credentials gets a `407`
and is reported `failed` with the detail `proxy credential not honoured`. The
probe still only tests clients as run from this environment; see
[docs/limitations.md](docs/limitations.md).

## Install

Not yet released. Build from source:

```
go build -o stk ./cmd/stk
```

## Licence

Apache-2.0.
