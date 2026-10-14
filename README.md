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

## Install

Not yet released. Build from source:

```
go build -o stk ./cmd/stk
```

## Licence

Apache-2.0.
