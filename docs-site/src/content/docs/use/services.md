---
title: Services
description: The eleven services in the catalogue, and what the broker does for each.
---

The catalogue is deliberately short. Breadth is not the product: there are
hundreds of MCP servers already, and an entry here is only needed where the
broker fronts a service directly.

The eleven are chosen so that every auth scheme and every credential placement
has a **live connector** behind it rather than only a constant.

| Service | Host | Operation |
|---|---|---|
| `github` | api.github.com | substitute a token |
| `github-app` | api.github.com | mint a JWT → installation token |
| `aws-sts` | sts.amazonaws.com | sign with SigV4 |
| `x` | api.x.com | acquire via OAuth 2.0 refresh |
| `google` | sheets · drive · oauth2 | acquire via OAuth 2.0 refresh |
| `slack` | slack.com | substitute a token |
| `notion` | api.notion.com | substitute a token |
| `stripe` | api.stripe.com | substitute inside a Basic header |
| `openai` | api.openai.com | substitute a token |
| `cloudflare` | api.cloudflare.com | substitute a token |
| `resend` | api.resend.com | substitute a token |

```sh
stk add github slack x
```

Adding a service prints how its capabilities are classified — how many are
agent-callable reads and how many need approval.

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

Anything not in the table can still be reached as a
[fronted MCP server](/use/from-an-agent/#fronting-an-mcp-server-you-did-not-write).
