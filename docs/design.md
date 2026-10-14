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

## Connecting a service where there is no browser

A deployed agent is the normal case, not the exception, and every path above
assumes someone can open a browser on the machine where the broker runs. Three
paths close that gap, in order of preference.

**The device authorization grant** (RFC 8628), `stk connect <service> --device`.
The broker asks the provider for a short code, reaches the operator through the
notification adapter, and polls. The token comes back from the provider **to the
broker directly** — not through a hub, not through a laptop, not through us.
This is the only one of the three where the credential exists in exactly two
places, which is why it is first.

Three details of the spec decide whether it works in practice, and all three
fail quietly when got wrong: `authorization_pending` is the normal case rather
than an error; `slow_down` means widen the interval by five seconds, and a
client that ignores it gets rate-limited at the exact moment a person is trying
to help it; `expired_token` is something an operator can act on, while a network
fault is not.

The grant identifies an OAuth app, and supertoolkit ships no client id — a
shared one would make every installation look like the same app. The operator
registers their own and names it in the committed policy file, where a client id
is safe because it names an app and authorises nothing:

```yaml
services:
  github:
    device:
      client_id: <your app's client id>
      # a self-hosted instance speaks the same protocol at other addresses;
      # both endpoints move together or neither does
      authorization_url: https://github.example.com/login/device/code
      token_url: https://github.example.com/login/oauth/access_token
notify:
  webhook: https://ntfy.sh/your-topic
  file: /var/log/stk-notify.log
```

**The broker's own web UI** over a private network, where the provider's
redirect can reach it. This is Phase 4's work, used from a different machine.

**Encrypted hand-over**, `stk handover`. The broker publishes a public key that
can only seal; the machine that does have a browser seals the credential to it
with an anonymous NaCl box; only that broker's private key opens it. A tampered
envelope fails rather than yielding partial material.

This path costs something the other two do not, and the commands say so rather
than hiding it: the credential exists on the sealing machine for as long as it
takes to seal, and it still exists there afterwards. A fallback that conceals
what it gives up is worse than one that admits it.

### What is a secret here and what is not

A **user code** may be printed, read aloud, written to a log and sent through a
webhook: it is useless without the person who approves it. A **device code** may
not, because it is the value a poll redeems — it never reaches the notification
adapter and never appears in an error message. The tests assert both directions,
in the unit tests and again through the shipped binary.
