---
title: What supertoolkit is
description: A credential broker for agents, and the single invariant it is built around.
---

A toolkit for agents with credential and auth management built in. An agent asks
for an effect by name and never holds the secret that causes it.

## The one invariant

> **The agent never holds, reads, or receives a credential.**

Not configurable, no override. There is no endpoint that returns one — not for
an agent, not for the CLI, not for the web interface. Which effects an agent may
*trigger* is policy you set. That line is the product; everything else is detail.

## How it works

A broker runs as its own OS user on a Unix socket. Clients — CLIs, MCP servers,
anything that speaks HTTP — are started with `HTTPS_PROXY` pointing at it and a
**placeholder** where their token would be:

```sh
GH_TOKEN=stk:ref:github:v1
```

The broker recognises that placeholder on the wire and does whatever the service
needs. Clients need no modification, because they are configured exactly as they
would be without a broker — they simply hold a value that is worth nothing.

## The six credential operations

What a service needs decides what the broker does. The catalogue declares it, so
adding a scheme is an entry rather than a branch in the request path.

| Operation | What happens | On the wire | `stk connect` and `stk ui` call it |
|---|---|---|---|
| **substitute** | A stored token replaces the placeholder. | the long-lived token | substitute (token) |
| **substitute, scheme-aware** | The Basic header is decoded, the value replaced, and re-encoded. A plain string swap matches nothing, because the credential is inside base64. | the long-lived token | substitute (token) |
| **sign** | The request is signed inside the broker. The credential is an HMAC over the method, path, headers and body — not a value anything can carry. | a signature | sign (AWS SigV4) |
| **mint** | A JWT is minted from a stored private key and exchanged for an installation token that expires in an hour. | a short-lived token | acquire (GitHub App installation token) |
| **refresh** | A stored OAuth 2.0 refresh token is exchanged for a short-lived access token. The refresh token only ever reaches the provider's token endpoint. | a short-lived token | acquire (OAuth 2.0 refresh) |
| **exchange** | A stored service credential is exchanged at the Organization plane for a token that lasts minutes, naming the audience it is for. The stored credential only ever reaches the exchange endpoint. | a short-lived token | acquire (service token exchange) |

Four of the six operations never put a long-lived secret on the wire at all.
`stk doctor` tells you which case each connected service is in, derived from
what is actually stored rather than from what the catalogue expected.

A service declared with `auth: none` holds no credential at all, and is shown as
none (policy and audit only): the broker enforces its rules and records every
request, and injects nothing. See [Services](/use/services/#a-public-endpoint-for-policy-and-audit-only).

## What it is not

It is not a hosted service, and there is nothing to sign in to. It is not an
agent framework — it sits beside whatever you already run. It does not open
traffic for hosts you have not configured: everything else is tunnelled
unopened (and recorded), so the blast radius of interception is exactly your
service list — unless an [`egress:`](/use/mcp-serve/#egress-decided-by-address)
policy with `methods:` asks for those connections to be opened and checked.
