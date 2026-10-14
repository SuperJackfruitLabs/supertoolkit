# Roadmap

What is done, what is next, and what is deliberately unscheduled. Phases ship in
order; the open items below them are decisions rather than work queues.

## Done

**Phase 0 — the broker and the proof.** Egress proxy with selective
interception, h2 and http/1.1, streaming, trailers. Scheme-aware injection.
Argon2id credential store. `stk init/add/connect/run/doctor`. A child holding
only a placeholder reached live GitHub as the right account.

**Phase 1 — the daemon, profiles and four meta-tools.** Unix socket with
kernel peer credentials. Profiles that narrow and never widen, enforced at
discovery as well as execution. MCP over stdio with exactly four tools. The
approval queue, failing closed three ways. OS keychain for the store key.

## Phase 2 — sign, mint, acquire *(current)*

The three operations where **the broker never puts a long-lived secret on the
wire at all**: it emits a signature, a nine-minute JWT, or a short-lived token
it exchanged for. Anything that leaks downstream expires by itself.

Covers AWS SigV4, OAuth 1.0a, NetSuite TBA and generic Signature; JWT auth and
Apple App Store; GitHub App, OAuth2 client-credentials and Two Step logins.
All three were proven feasible by spiking — SigV4 against AWS's own published
vector, JWT minting verified, and acquisition single-flight under twenty
concurrent callers.

## Phase 3 — front third-party MCP servers

The point at which breadth stops being our problem. There are 300+ Apache-2.0
MCP servers already; we start one as a child with **no credential in its
environment**, give it a placeholder, and inject on egress. The proxy for this
shipped in Phase 0, so this is process supervision and configuration rather
than protocol work.

## Phase 4 — the web interface

Five screens: status, services, policy, approvals, audit. Policy is a grid and
belongs in one; approvals have no home without one. Loopback on a laptop, the
private network on a VPS, and never the credential plane's listener. Mockups
before implementation, per house practice.

## Phase 5 — headless connect

`stk connect` where there is no browser. Device authorization grant is the clean
path: the broker gets a code, the operator approves in their own browser, and
the token returns from the provider straight to the broker. Fallbacks are the
broker's own web UI over a private network, or an encrypted hand-over from a
machine that does have a browser.

## Phase 6 — release

Apache-2.0 public, GitHub mirror, `install.sh` with `SHA256SUMS`, brew. The
acceptance test is a bare laptop with no SJL infrastructure present.

## Unscheduled, and each needs a decision rather than a sprint

| Item | Why it is not a phase |
|---|---|
| **WebSocket upgrade handling** | Breaks under the obvious implementation: forwarding through a round-trip into a response writer has no hijack path. Needed the moment a brokered service uses WebSockets, and not before |
| **Non-HTTP protocols** | Postgres, MySQL, Redis, Kafka, SMTP, IMAP. A CONNECT proxy cannot inject into a Postgres handshake; these need a protocol-aware local proxy, which is a second product shape |
| **Inbound webhooks** | Receiving and verifying provider events is half of what an integration platform does, and all of it is a new surface with a different security posture |
| **Connectors as pinned binaries** | `connector-protocol/v1` is already specified. It earns its place when a service needs code we have to ship, which no service does yet |
| **Identity chaining** | ID-JAG and RFC 8693 against whichever issuer a deployment has. This is the step that makes it a product rather than a utility — and the drafts are still moving, so it should follow the RFC rather than predict it |
| **vsock transport** | For microsandboxes, where the sandbox has no filesystem shared with the host. Needs a guest-side shim, since curl cannot speak AF_VSOCK |
| **Brokered mTLS, certificate pinning** | Untested. A tunnelled host keeps its own mTLS intact, so this only matters for a service we intercept that also demands a client certificate |
| **Bodies above 64 KB** | Unproven rather than broken: the proxy was transparent at every size tested, but no endpoint accepted a large upload. X media upload is multipart, so this matters when a publishing connector lands |
| **Measured latency** | The broker's overhead is below network noise and has never been isolated. It needs a local upstream to measure, and nothing yet depends on the number |
