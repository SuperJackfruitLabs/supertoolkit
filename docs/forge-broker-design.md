# Forge broker — design

**Date:** 2026-10-17
**Status:** draft for review, not yet implemented
**Companion:** agentpod `docs/superpowers/specs/2026-10-17-forge-api-access-design.md`
(issue #725). That document says *what the fleet needs and why*; this one says
what stk must become to provide it.

## Why

agentpod wants agent stations to reach git forges (GitHub, Forgejo, Gitea,
Bitbucket) through their APIs without the agent ever holding the token. That is
this project's invariant, so stk is the broker. Today it cannot do the job. This
document lists exactly what is missing, decides the shape of each fix, and keeps
the invariant intact.

Everything here was checked against the code at `5c550cc` (`origin/main`) and
by running the binary in a scratch directory.

## What is missing

| # | Gap | Evidence |
|---|---|---|
| 1 | Services are a compiled-in Go map of 11. A policy file cannot define a service or change its host. `stk add forgejo` fails: `unknown service "forgejo"`. | `internal/catalog/catalog.go:258`, `cmd/stk/setup.go:86,145`, `internal/policy/config.go:274-277` |
| 2 | The proxy forwards any method and path to an intercepted host. Capability policy applies only on the MCP/daemon path. | `internal/broker/proxy.go:304-405` |
| 3 | The proxy listens on a random loopback TCP port; nothing publishes it. A persistent harness cannot find it. Only `stk run -- <cmd>` learns it. No peer authentication. | `cmd/stk/run.go:60`, `broker/childenv.go` |
| 4 | "Broker as its own OS user" is design intent only: no user, socket-permission or service-unit code. | `docs/design.md`, grep |
| 5 | `seal` takes the credential from a local stk store; the sealing code is `internal/`. No operator-side seal from a hub or CLI. | `internal/handover/handover.go` |
| 6 | No provider-side verify. `doctor` checks configuration, never calls the provider. | `cmd/stk/doctor.go` |
| 7 | Single tenant by construction; the ledger's `caller` is `run`/`serve`/`mcp`, not a station or principal. | `internal/ledger/ledger.go` |
| 8 | Credential replace is a plain `os.WriteFile`, not atomic. | `internal/credential/store.go:109` |
| 9 | `servers:` hosts are never intercepted (`Config.InterceptHosts()` is called only from tests), so the documented fronted-MCP feature does not reach the proxy. | `internal/broker/proxy.go:136-141`, `e2e/fronted_test.go` |
| 10 | `doctor`, `--probe` and `approvals` are text only; `--probe` exits 0 even when a client `bypassed`. | `cmd/stk/probe.go` |
| 11 | Policy loads once at start; a change needs a restart. | `internal/policy` |
| 12 | The CA has no x509 name constraints. | `internal/broker/ca.go:43-49` |

## The invariant, applied

Nothing here adds an endpoint that returns a credential. Sealing *takes* a
credential and produces ciphertext; opening writes to the sealed store;
verification reports an identity login and a status, never a token. Every
change below is tested against that sentence.

## Decisions

### 1. A generic forge service, configured not compiled

Add a service **kind** that is defined in configuration:

```yaml
services:
  forge-main:
    kind: forge
    provider: forgejo            # forgejo | gitea | github | bitbucket
    host: forge.superjackfruit.com
    api_prefix: /api/v1          # provider default if omitted
    auth: token                  # token | app
    scheme: bearer               # bearer | token
    env_var: FORGEJO_TOKEN       # where `stk run` puts the placeholder
    repositories:                # non-secret; set by the operator or agentpod
      - SuperJackfruitLabs/supertoolkit
    preset: issues               # starting rule set, see Presets
```

**What a "grant" is in stk.** There is no grant object. One `kind: forge`
service entry *is* one grant: its `repositories` list is what `{owner}/{repo}`
bind to, and its `labels` (decision 7) carry the station, principal and grant
ids agentpod assigns. A station with two grants has two entries. The
`repositories` list lives in the policy file, which agentpod writes and
`stk reload` re-reads; stk never invents it. A rule with no `{repo}` placeholder
(`GET /user`) matches whatever it says literally, so presets include the
identity endpoint explicitly and nothing like `/search/**` unless an operator
adds it.

- `provider` selects built-in knowledge: default API prefix, the read-only
  identity endpoint used by verify (`GET /user` on Forgejo, GitHub and Gitea),
  the audit capability labels, and the default rule presets.
- `host` is configuration, so one binary serves any instance, including GitHub
  Enterprise and self-hosted Gitea.
- `kind: forge` entries are copied per service in `policy.Load`; today services
  share the global catalogue pointer, so per-instance host cannot be set.
- `auth: app` reuses the existing `github-app` operation (JWT then
  installation-token exchange) with configurable host. `auth: token` is
  substitute.
- `scheme`: stk's Bearer placement rewrites `Authorization: token stk:ref:…` to
  `Authorization: Bearer <secret>` (`internal/credential/inject.go:28-33`). The
  builder **must verify Forgejo and Gitea accept `Bearer`** for API tokens. If
  not, `scheme: token` writes `token <secret>`.
- Existing built-ins stay. `unknown service` still fails for unknown names;
  `kind: forge` entries are the only way to add one by configuration.
- The agentpod fleet drives this file; operators can also write it by hand
  (stk remains useful standalone).

### 2. Request rules in the proxy

A per-service rule list is evaluated in `broker.forward` **before any
substitution or forwarding**:

```yaml
rules:
  - allow: POST  /repos/{owner}/{repo}/issues
  - allow: PATCH /repos/{owner}/{repo}/issues/*
    when: { body.state: absent }
  - deny:  DELETE /**
```

- Deny by default for `kind: forge` services. A `deny` match wins over `allow`.
  The 11 built-in services keep today's behaviour (the proxy forwards what the
  token allows); `rules:` becomes available to them as an opt-in and changes
  nothing unless written.
- **Prefix and query.** Requests are matched on the path after `api_prefix`.
  A request outside the prefix on an intercepted host (web pages, `/login`,
  git smart-HTTP) is denied. The query string is ignored for matching and
  forwarded unchanged; a rule cannot depend on it. GitHub Enterprise sets
  `api_prefix: /api/v3`; github.com has host `api.github.com` and no prefix.
- **GraphQL is denied by default** because it cannot be rule-checked
  (mutations hide in the body). `allow_graphql: true` is an explicit,
  documented opt-in for a service, because it makes the rule set advisory for
  that service. This is why many `gh` commands fail on a restricted grant.
- **Path matching** is on the normalised path after the `api_prefix`. Normalise
  before matching: reject `..`, encoded slashes (`%2f`), double slashes and
  control characters. This is the classic bypass; it needs adversarial tests.
- `{owner}` and `{repo}` bind to the grant's repositories, case-insensitively
  as the provider treats them. A rule can name a repository explicitly.
- **Body conditions** (`when:`) read the request body up to a limit (default
  64 KiB), buffer it, evaluate, and forward the same bytes. Supported: key
  present/absent, equality, one-of, on top-level and dotted JSON keys. A body
  that is not JSON, is over the limit, or uses an unsupported content type fails
  the condition (deny). Config load rejects rules that need a body condition on
  a method or endpoint class stk cannot evaluate (for example GraphQL).
- Response to a denied request: HTTP 403 with a short body naming the matching
  rule id, never the credential. The audit record carries the rule id.
- **Rules cannot widen the credential.** They are an additional filter.
- Reuse the capability-name layer for labels: a rule set may reference a named
  capability (`issues.create`) that expands to method+path, so the MCP surface
  and the proxy share one definition.
- Rule changes take effect on reload (decision 6), no restart.
- Tests: for every rule form, a denied request is not forwarded (assert the fake
  provider saw nothing), and a revert-proof test fails when the check is removed.

### 3. A stable broker listener

- `stk serve --proxy-listen <addr>` publishes the proxy on a **fixed loopback
  TCP address**. (My call: common clients take only `http://host:port` proxy
  URLs, so a Unix socket proxy would need a shim and gains nothing here.)
  The control socket stays a Unix socket.
- **Authentication is a per-station proxy credential, not peer uid.** Loopback
  TCP gives no portable peer uid. Clients present the credential through the
  standard proxy URL userinfo (`http://stk:<key>@127.0.0.1:<port>`), which curl,
  Python, Node and Go all turn into `Proxy-Authorization`. A request without
  the right credential gets 407 before any substitution. The credential only
  proves "may use the broker"; it is not a service credential, and an agent
  holding it can do exactly what its rules allow and nothing more. It is
  rotatable and written to the client's environment by `stk env`.
- `stk env` prints the environment a client needs (`HTTPS_PROXY`, CA paths,
  `NODE_USE_ENV_PROXY=1`, the placeholder variables) in shell and JSON forms, so
  a persistent harness or its service unit can be configured without `stk run`.
- **Control socket:** it reads peer uid from the kernel but `handle` ignores it
  (`cmd/stk/serve.go:198`). Fix: accept only the configured uids and record the
  uid in the audit record, or document the profile as a claimed string.
- Fail closed, never direct, remains test-covered.

### 4. Run as its own user

- `stk install --user stk --socket-dir … --credential-dir …` (Linux/systemd):
  creates the user, directories with correct modes, the service unit, and
  loads the sealed-store passphrase from the service manager's credential store
  (`LoadCredential`), so `STK_PASSPHRASE` is not on disk beside the ciphertext.
  A macOS launchd variant is optional.
- `stk doctor` reports isolation level: `separate-user` when the store, key and
  approval commands are unreachable by the agent's uid; `same-user` otherwise.
  That string is what agentpod records on the grant. It claims only what it
  checked. The agent uids come from a configured list (`agent_uids:`, written by
  agentpod). The check is ownership and mode bits along the whole path of the
  store, key and socket; when run as root it also attempts a real access as each
  agent uid in a child process. The report states which method ran. A false
  `separate-user` is treated as a security bug.
- `stk approvals allow` must not be usable by the agent's uid in separate-user
  mode (already a documented gap in `SECURITY.md:57-61`).

### 5. Sealing as a public operation

- A public `handover` package (move from `internal/`) or a small `stk seal`
  command that takes a public key and a secret on stdin and writes the
  `stk-handover-v1:` envelope. No local store needed.
- **Whose key:** the existing per-installation handover key. It is generated
  when stk is installed or first runs; the private half stays in the stk user's
  state directory and never leaves it; the public half is `stk handover key`.
  agentpod's node reports it to the hub. The existing key model is reused
  unchanged, and `stk-handover-v1` is **frozen as of this design** (any change
  is a `v2` with both versions accepted), because agentpod implements the same
  envelope in its CLI and console.
- The envelope format, and the multi-field `Material` JSON for app credentials
  (app id, installation id, private key), are specified in this repo and
  versioned so agentpod's console and CLI can implement the same sealing.
  A conformance test vector is committed.
- `stk handover open <service>` validates the material against the service's
  field list (existing behaviour) and writes **atomically** (temp file and
  rename; decision 7).
- No path returns the secret.

### 6. Verify, reload, machine output

- `stk verify <service>` calls the provider's identity endpoint with the stored
  credential and reports `ok` plus the login, or a reason (`unauthorized`,
  `forbidden`, `unreachable`, `wrong identity` when `--expect-login` is given).
  It never prints the token. Exit non-zero on failure.
  - For `auth: token`: `GET /user`.
  - For `auth: app`: an installation token cannot call `/user`. Verify calls
    `GET /app` with the signed JWT (login is `<slug>[bot]`) and then
    `GET /installation/repositories` with the installation token, checking the
    configured repositories are a subset of those returned.
  - Verify is a built-in read made by stk itself, **not** a client request, so
    it does not depend on the preset; it never bypasses rules for client
    traffic.
- `stk reload` (or `SIGHUP`) re-reads the policy file atomically; invalid
  configuration keeps the old policy and reports why.
- `--json` on `doctor`, `verify`, `status`, `approvals list`, and `--probe`.
- `--probe` exits non-zero when any client is `bypassed`.

### 7. Atomic credential replace and identity in audit

- `store.Put` writes a temp file in the same directory and renames. A concurrent
  proxy read sees the old or new value, never a torn one.
- Add a configurable `labels` block (`station`, `principal`, `grant`) written
  into every audit record. They are set by the operator or agentpod, not by the
  client. Audit still holds fingerprints, never secrets (existing test
  `TestAuditNeverContainsTheSecret`).
- Log denied requests (rule id, method, path, no query string) and tunnelled
  hosts at least as counts.

### 8. Fix or remove the fronted-server gap

The `servers:` route does not intercept its hosts. Either wire
`InterceptHosts()` into `broker.New` and key `secretSource` and `connect` by
server name, or remove the route from the docs until it works. Not needed for
forge access, and listed because it is a documented feature that does not work.
**Smallest honest fix:** remove the claim from the docs now, restore when
wired.

### 9. Harness compatibility is tested, not assumed

`stk doctor --probe` today tests curl, Python, Node and Go. Add a probe plug-in
interface so agentpod can run each supported harness's own client (and
`gh`/`tea`) against the fake provider and report `honoured`, `bypassed`,
`refused-ca`. The result is machine-readable. Known limits stay documented:
Go binaries on macOS ignore `SSL_CERT_FILE`; WebSocket, mTLS and HTTP/3 are out
of scope.

### 10. CA scope

Add x509 name constraints to the generated CA, permitting only the intercepted
hosts, so a leaked CA key cannot impersonate arbitrary hosts to a system that
trusts it. A policy reload that would add a host the current CA does not permit
is **rejected with a clear error**; the operator runs `stk ca renew`, which
issues a new CA to the same path, and harnesses restart to pick it up
(agentpod does this on a grant to a new host). Where a constraint breaks a
client, document it and prefer per-process trust via environment over system
trust.

## Presets (my call; verify each path against the provider's current API
description in tests)

A preset is a list of rules plus the provider-side scopes it needs. Forgejo,
Gitea and GitHub share the `/repos/{owner}/{repo}/…` shape; differences (for
example merge is `POST` on Forgejo and `PUT` on GitHub) are encoded per
provider. Operator `rules:` **extend** a preset, a `deny` subtracts, and
`preset: none` starts empty.

| Preset | Rules |
|---|---|
| `read` | `GET` identity endpoint; `GET /repos/{owner}/{repo}/**` |
| `issues` | `read`, plus `POST …/issues`, `PATCH …/issues/*`, `POST …/issues/*/comments`, `PATCH …/issues/comments/*`, label edits |
| `pull-requests` | `issues`, plus `POST …/pulls`, `PATCH …/pulls/*`, `POST …/pulls/*/reviews`, `POST …/pulls/*/requested_reviewers` |
| `maintain` | `pull-requests`, plus merge, release create/edit, label create |

`DELETE` is denied in every preset. Capability labels for audit (`issues.create`
and so on) are defined with the presets; they are new for Forgejo and Gitea.
Whether a GitHub-only capability layer already exists in the MCP path is to be
confirmed when the builder reads `internal/catalog`.

## Out of scope

- A multi-tenant hosted service. One stk per station, as `docs/design.md`
  already says.
- Brokering git over SSH. The git credential-helper injection point stays a
  design item; HTTPS git for providers without SSH is a later piece.
- Gitea and Bitbucket service presets, until their adapters are scheduled in
  agentpod. The generic `kind: forge` already admits them by configuration.

## Build order

1. Service kind and per-instance copy (decision 1), with verify (6) and atomic
   replace (7). This unblocks a Forgejo read call.
2. Public seal and `handover open` for `Material` (5).
3. Request rules and path normalisation (2). Highest-risk piece; adversarial
   tests first.
4. Listener, `stk env`, peer authentication (3).
5. `stk install` and isolation reporting (4).
6. Reload, JSON output, audit labels (6, 7).
7. Probe plug-ins (9), CA constraints (10), fronted-server fix or doc removal (8).

Each is its own PR on forge (this repo's primary). `gh` bypasses the push
guard; do not use it here. Tags continue from `0.0.1`.

## Tests that must exist

- Forgejo/GitHub fake providers in `e2e/`: a rule-denied request never reaches
  the provider; an allowed one arrives with the substituted credential and the
  right scheme.
- Path-traversal and encoding bypass attempts against the rule matcher.
- Body-condition tests: allow `PATCH` without `state`, deny with `state:
  closed`, deny non-JSON, deny oversize.
- Concurrent replace while the proxy serves requests.
- Audit never contains the secret, including on denied requests and `verify`.
- Seal then open round trip, and a conformance vector shared with agentpod.
- `install` produces a store the agent's uid cannot read (run under a throwaway
  user in CI where possible).
- Revert-proof for each guard above.

## Left to the builder

- Rule-language syntax details, as long as the semantics above hold.
- Package layout for the forge provider knowledge.
- macOS install variant.
- Exact limits (body size, audit rotation).

## Interface agentpod depends on

Every command takes `--json` and exits non-zero on failure. No result contains
a secret. This table is mirrored in the agentpod design.

| Command | Result |
|---|---|
| `stk handover key` | public key, `stk-handover-v1:` prefix |
| `stk handover open <service>` | `{ "service", "stored": true }` after an atomic write |
| `stk verify <service> [--expect-login L]` | `{ "ok", "login", "reason" }` |
| `stk reload` | `{ "ok", "error" }` |
| `stk doctor --json` | includes `isolation` and how it was checked |
| `stk revoke <service> --local` | `{ "service", "removed": true }` |
| `stk audit --json` | records with `station`, `principal`, `grant` labels |
| `stk env --json` | proxy address, proxy credential, CA path, placeholders |
| `stk ca renew` | `{ "ok", "ca_path" }` |

## Open items

- Whether Forgejo and Gitea accept `Authorization: Bearer` for API tokens
  (verify against a real instance before choosing `scheme` defaults).
- Gitea and Bitbucket identity endpoints and token formats (verify current docs
  when scheduled).
- How GitHub App installation tokens are scoped per repository in the exchange
  request, to confirm the repository restriction can be set at exchange time.
