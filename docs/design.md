# Design

The reasoning, the landscape review and the three spike rounds live in
[the sketchbook idea](https://forge.superjackfruit.com/SuperJackfruitLabs/sketchbook/src/branch/main/ideas/2026-10-14-supertoolkit).
This file records only what is **decided and binding** for the code here.

## The invariant

The agent never holds, reads, or receives a credential. No override, no
privileged caller, no debug flag. Everything else on this page is policy.

## Two axes

**Where a credential enters a request** — three injection points:

| Point | Covers |
|---|---|
| Egress proxy + placeholder | MCP servers, HTTP and GraphQL APIs, most CLIs. The client is unmodified |
| Credential helper | `git`, AWS `credential_process`, Docker. Their own supported hooks |
| Native call | Our own connectors and every approval-gated effect |

**What the broker does to produce one** — five operations:

| Operation | Broker holds | Covers |
|---|---|---|
| substitute | a token | OAuth2, Bearer, API key in header or query |
| scheme-aware substitute | a token | Basic, where the credential is inside base64 |
| sign | a secret key | AWS SigV4, OAuth 1.0a, NetSuite TBA, generic Signature |
| mint | a private key | JWT auth, Apple App Store, service accounts |
| acquire | a private key or client secret | GitHub App, OAuth2 client-credentials, Two Step, session schemes |

The last three never put a long-lived secret on the wire: a signature, a
nine-minute JWT, or a short-lived exchanged token. Anything that leaks downstream
expires on its own.

## Decided

- **Go**, single binary `stk`. Connectors ship pinned by version and checksum.
- **Long-lived daemon on a Unix socket**, own OS user, mode `0600`, callers
  identified by kernel peer credentials. Not in-process in a host, not a process
  per call.
- **Only the refresh token is persisted**, with a key derived by HKDF or Argon2id.
  Access tokens live in memory. Explicitly not the pad-or-truncate-to-32-bytes
  approach seen elsewhere in this estate.
- **Policy is per capability**: `agent`, `approval`, or `deny`. Defaults are safe
  — reads `agent`, writes `approval`. Policy governs who may *trigger* an effect,
  never who holds the credential.
- **Profiles narrow, never widen.** The service policy is the ceiling; a profile
  selects a subset. A profile referencing a denied capability gets nothing.
- **Profile identity is a socket path, not a token.** A token in a harness config
  would violate this product's own thesis. Tokens are the fallback for transports
  where a path cannot travel.
- **Four meta-tools, not N schemas.** `discover_server_categories`,
  `get_category_actions`, `get_action_details`, `execute_action`, answered from
  the caller's profile. One `execute_action` means one place to enforce policy.
- **Standalone first.** Nothing here imports agentpod, superpipeline, or the
  organization plane. Approval, identity, install and storage are adapters with
  working local defaults. The acceptance test is a bare laptop.
- **Interception is selective.** Only hosts named in policy are terminated.
  Everything else is tunnelled unopened.

## Validated by spiking

On macOS, a Linux VPS and a microVM: a client sending only a placeholder reached
the provider as the right account, never holding the credential. HTTP/1.1,
HTTP/2 and streaming carry. SigV4 signing reproduces AWS's published test vector.
JWT minting verifies. Acquisition is single-flight: twenty concurrent callers,
one exchange.

A broker outage fails closed — measured, not assumed.

## Known gaps, recorded rather than implied solved

- **WebSocket breaks** under the obvious implementation, because forwarding via a
  round-trip into a response writer has no hijack path. Needs explicit upgrade
  handling.
- **`NO_PROXY` is a bypass.** Anything that can set an environment variable can
  opt out. `stk doctor` must check it. A sandbox with no route neutralises it.
- **Clients that ignore proxy configuration cannot be stopped by configuration** —
  Go's zero-value `Transport`, Node's default `fetch`. They fail *silently*, which
  is why `doctor` exists. Clients that reject the CA fail loudly, which is safe.
- **HTTP/3 is out of reach** of a CONNECT proxy. Deny UDP/443 so clients fall
  back; a sandbox already does.
- **Non-HTTP protocols are not covered.** Postgres, MySQL, Redis, Kafka, SMTP,
  IMAP need a protocol-aware local proxy, not this one.
- **Inbound webhooks are not designed.** Receiving and verifying provider events
  is a separate surface.
- Untested: brokered mTLS, certificate pinning, bodies above 64 KB, vsock as the
  transport, and OAuth 1.0a's HMAC-SHA1 specifically.

## Not in scope

Breadth. There are 300+ Apache-2.0 MCP servers already, and Pipedream has 3,000
APIs; integration count is the commoditised axis. supertoolkit fronts servers it
did not write. A connector is authored only where none exists or where a service
needs the approval path.

A multi-tenant hosted service holding other people's credentials is also out of
scope. Remote access to the operator's own broker is a deployment question:
loopback on a laptop, the private network on a VPS, authenticated TLS only if
neither is possible.
