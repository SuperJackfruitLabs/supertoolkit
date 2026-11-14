---
title: What SuperToolkit is
description: A credential broker for agents, and the single invariant it is built around.
---

SuperToolkit gives agents credential and auth management without giving them
credentials. Your agent asks for an effect by name; we keep the secret that
causes it on the other side of the broker.

## The one invariant

> **The agent never holds, reads, or receives a credential.**

It is not configurable, and there is no override. No endpoint returns a
credential — not to an agent, the CLI, or the web interface. You set policy for
the effects an agent may *trigger*. That line is the product; everything else
exists to hold it.

## How it works

For one child, `stk run` starts an in-process broker and a loopback proxy. For
long-running agents, run `stk serve` as its own OS user; clients reach its Unix
control socket and loopback proxy. In either mode, you start HTTP clients with
`HTTPS_PROXY` pointing at the broker and a **placeholder** where their token
would be:

```sh
GH_TOKEN=stk:ref:github:v1
```

The broker recognises that placeholder on the wire and does whatever the service
needs. You do not modify the client: configure it exactly as you would without a
broker, except the value it holds is worth nothing. The request still works; the
credential never becomes client state.

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

You are not signing in to a hosted service, and we are not asking you to adopt
an agent framework. SuperToolkit sits beside whatever you already run. It does
not open traffic for hosts you have not configured: everything else is tunnelled
unopened (and recorded), so the blast radius of interception is exactly your
service list — unless an [`egress:`](/use/mcp-serve/#egress-decided-by-address)
policy with `methods:` asks for those connections to be opened and checked.
