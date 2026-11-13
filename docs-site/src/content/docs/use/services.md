---
title: Services
description: The thirteen services in the catalogue, what the broker does for each, and the services you declare yourself.
---

The catalogue is deliberately short. Breadth is not the product: there are
hundreds of MCP servers already, and an entry here is only needed where the
broker fronts a service directly.

The thirteen services are chosen so that every auth scheme and every credential
placement has a **live connector** behind it rather than only a constant.

| Service | Host | Operation | Placeholder in |
|---|---|---|---|
| `github` | api.github.com | substitute a token | `GH_TOKEN` |
| `github-app` | api.github.com | mint a JWT → installation token | — |
| `aws-sts` | sts.amazonaws.com | sign with SigV4 | — |
| `x` | api.x.com | refresh an OAuth 2.0 grant | `X_BEARER_TOKEN` |
| `google` | sheets · drive · oauth2 | refresh an OAuth 2.0 grant | `GOOGLE_ACCESS_TOKEN` |
| `slack` | slack.com | substitute a token | `SLACK_BOT_TOKEN` |
| `notion` | api.notion.com | substitute a token | `NOTION_TOKEN` |
| `stripe` | api.stripe.com | substitute inside a Basic header | `STRIPE_SECRET_KEY` |
| `openai` | api.openai.com | substitute a token | `OPENAI_API_KEY` |
| `cloudflare` | api.cloudflare.com | substitute a token | `CLOUDFLARE_API_TOKEN` |
| `resend` | api.resend.com | substitute a token | `RESEND_API_KEY` |
| `superpipeline-approvals-read` | app.superpipeline.dev | exchange a service credential | `SUPERPIPELINE_APPROVALS_READ_TOKEN` |
| `superpipeline-approvals-write` | app.superpipeline.dev | exchange a service credential | `SUPERPIPELINE_APPROVALS_WRITE_TOKEN` |

"Placeholder in" is the variable `stk run` and `stk env` fill with a worthless
placeholder, where the client expects its credential.

```sh
stk add github slack x
```

Adding a service prints how its capabilities are classified — how many are
agent-callable reads and how many need approval.

The two `superpipeline-approvals-*` services are **native-only**: stk uses them
itself, for [approvals hosted on SuperPipeline](/use/approvals/#approvals-hosted-on-superpipeline)
and for [gated publishing](/use/publish/). No agent profile can name them, and
their tokens are applied in stk's own transport and never returned. Each is an
Organization-plane service credential with one scope, connected with
`stk connect superpipeline-approvals-read` (or `-write`), the credential on
stdin.

## Some notes the table cannot carry

**Stripe** keeps scheme-aware substitution honest. Its secret key travels as the
Basic username, so the broker decodes the header, replaces the value and
re-encodes it. A plain string swap matches nothing there and silently does
nothing, which is exactly what it did until a review caught it.

**Google** needed more than one hostname. A credential is refreshed at
`oauth2.googleapis.com` and spent at `sheets.googleapis.com` or
`www.googleapis.com`; intercepting one of three would leave the others tunnelled
with the placeholder arriving unswapped.

**Notion** requires a dated `Notion-Version` header. It is part of the request
shape rather than something a caller should have to remember, so it lives in the
catalogue beside the paths.

**X** rotates its refresh token on every single use and invalidates the old one
immediately. The rotation is persisted before the new access token is handed
out, because a rotation that is not written back locks you out at the next
refresh — hours later, nowhere near its cause.

## What does not fit

**GraphQL APIs.** Every call is `POST /graphql` with the operation in the body,
so a method and a path cannot tell one capability from another. Policy could not
name what it was allowing and the ledger could not say what happened, which is
worse than not supporting it. Linear was dropped from the launch catalogue for
exactly this, and a test fails any entry with that shape.

**Non-HTTP protocols** — Postgres, Redis, SMTP. A CONNECT proxy cannot inject
into a Postgres handshake. Those need a protocol-aware local proxy, which is a
second product shape.

Anything not in the table can still be reached in one of three ways: a git
forge or a public endpoint [declared in your own configuration](#a-git-forge-defined-in-configuration),
or a [fronted MCP server](/use/from-an-agent/#fronting-an-mcp-server-you-did-not-write).

## A git forge, defined in configuration

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

Then `stk connect forge-main` (the token on stdin) and `stk verify forge-main`,
which makes one read call as that credential and prints the login it acts as,
or the reason it failed. `api_prefix:` sets the path the API is served under
when it is not the provider's default.

**Presets are enforced.** The broker decides every request to a forge before it
fetches the credential: a request no rule allows gets a `403` that names the
rule, and nothing is sent to the provider. The preset's rules come first, then
your own `rules:`; a matching `deny` always wins, and anything not allowed is
denied.

| `preset:` | allows (cumulative) |
|---|---|
| `read` | GET on `/user` and the configured repositories |
| `issues` | read, plus creating and editing issues, comments and issue labels |
| `pull-requests` | issues, plus opening and editing pull requests, reviews and review requests |
| `maintain` | pull-requests, plus merging pull requests, releases and repository labels |
| `none` | nothing; write every rule yourself |

No preset allows `DELETE`, so a `DELETE` needs an explicit `allow` of your own.
Bitbucket has no presets yet: use `preset: none`.

```yaml
    preset: read
    rules:
      - allow: "PATCH /repos/{owner}/{repo}/issues/*"
        when: {state: absent}      # a JSON body must not set `state`
      - deny: "POST /repos/{owner}/{repo}/issues/*/lock"
```

A rule is exactly one of `allow:` or `deny:`, with an optional `when:` on the
JSON body; any other key fails the load, because a dropped misspelling would
turn a conditional allow into an unconditional one. Paths are written relative
to `api_prefix`. `{owner}` and `{repo}` must be used together and match the
configured repositories. Paths containing `..`, `//` or an encoded slash are
refused.

GraphQL is denied by default (rule `builtin:graphql`), because one endpoint
carries every operation. `allow_graphql: true` on the service stops that
built-in deny; the endpoint is then still subject to the path rules, but the
operation inside the body is not inspected, so no rule can restrict which
queries or mutations run. `stk audit` shows the rule that denied a request.

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
(`scheme: token` is refused with it). The installation token is requested
restricted to the configured repositories, which must all belong to one owner.
For any host other than `api.github.com` the API is served under `/api/v3`,
which is the default `api_prefix`. Connect it with `app_id`, `installation_id`
and `private_key` as `field=value` lines on stdin to `stk connect acme-app`.

### Audit labels

`labels:` on a `kind: forge` service copies up to three short values — `station`, `principal`
and `grant` — onto every audit row for it, so a ledger shared by several callers
says whose request each was. Any other key, a value over 128 bytes or a control
character fails the load.

## A public endpoint, for policy and audit only

`auth: none` declares a forge service that holds no credential. The broker never
reads the store for it and injects nothing; its rules still decide every request
and `stk audit` still records it. Anonymous git over HTTPS is the case it is
for:

```yaml
services:
  git-public:
    kind: forge
    provider: github
    host: github.com
    auth: none
    api_prefix: /
    preset: none
    repositories: [acme/widgets]
    rules:
      - allow: "GET /{owner}/{repo}/info/refs"
      - allow: "POST /{owner}/{repo}/git-upload-pack"
      - deny: "POST /*/*/git-receive-pack"
```

A push opens with `GET …/info/refs?service=git-receive-pack`; the broker decides
that request as the push it begins, so a denied push is refused at its first
request. `scheme` and `env_var` cannot be set with `auth: none`, and
`stk connect` and `stk verify` refuse it. Point git at the broker with
`http.proxy` and `http.sslCAInfo` (from [`stk env`](/run/serve/#the-fixed-proxy-and-stk-env)),
and turn off `ssh://`, `git://` and `ext::`, which would go around it.
