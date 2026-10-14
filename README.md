# supertoolkit

A toolkit for agents with credential and auth management built in. An agent asks
for an effect by name and never holds the secret that causes it.

**Status: Phase 0, in development.** Nothing here is released. The core mechanism
is validated — see [docs/design.md](docs/design.md) for what is decided and
[the sketchbook idea](https://forge.superjackfruit.com/SuperJackfruitLabs/sketchbook/src/branch/main/ideas/2026-10-14-supertoolkit)
for why.

## The one invariant

> The agent never holds, reads, or receives a credential.

Not configurable, no override. Which effects an agent may *trigger* is policy the
operator sets. This line is the product.

## The problem it solves

The standard way to give an agent a tool today is to put an API key in an MCP
config file. That file is plaintext, any process can read it, and the agent reads
it to start the server — so the credential ends up in the agent's own context,
and from there in the transcript and wherever transcripts are kept.

supertoolkit holds the credential in a process the agent cannot read, and injects
it on the way out.

## How it works, in one paragraph

A long-lived broker runs as its own OS user, listening on a Unix socket. Clients —
CLIs, MCP servers, anything that speaks HTTP — are started with `HTTPS_PROXY`
pointing at the broker and a **placeholder** where their token would be. The
broker recognises the placeholder on the wire and substitutes the real
credential, signs the request, mints a JWT, or exchanges one for a short-lived
token, depending on what the service needs. Clients need no modification. If an
agent reads the placeholder it has read nothing useful.

## Status of the mechanism

Validated on macOS, a Linux VPS and a microVM: a client sending only a
placeholder reached GitHub as the right account, never holding the credential.
HTTP/1.1, HTTP/2 and streaming all carry. A dead broker fails safe rather than
silently going direct.

Known gaps are recorded in [docs/design.md](docs/design.md) rather than implied
to be solved.

## Licence

Apache-2.0.
