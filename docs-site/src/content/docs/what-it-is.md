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

## The five credential operations

What a service needs decides what the broker does. The catalogue declares it, so
adding a scheme is an entry rather than a branch in the request path.

| Operation | What happens | On the wire |
|---|---|---|
| **substitute** | A stored token replaces the placeholder. | the long-lived token |
| **substitute, scheme-aware** | The Basic header is decoded, the value replaced, and re-encoded. A plain string swap matches nothing, because the credential is inside base64. | the long-lived token |
| **sign** | The request is signed inside the broker. The credential is an HMAC over the method, path, headers and body — not a value anything can carry. | a signature |
| **mint** | A JWT is minted from a stored private key and exchanged for an installation token that expires in an hour. | a short-lived token |
| **acquire** | A stored refresh token is exchanged for a short-lived access token. | a short-lived token |

Three of the five never put a long-lived secret on the wire at all. `stk doctor`
tells you which case each connected service is in, derived from what is actually
stored rather than from what the catalogue expected.

## What it is not

It is not a hosted service, and there is nothing to sign in to. It is not an
agent framework — it sits beside whatever you already run. It does not proxy
traffic for hosts you have not configured: everything else is tunnelled
unopened, so the blast radius of interception is exactly your service list.
