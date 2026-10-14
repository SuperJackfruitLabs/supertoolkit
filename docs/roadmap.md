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

## Phase 5 — headless connect — **shipped**

`stk connect --device` runs the device authorization grant: the broker gets a
code, the operator approves it in their own browser wherever they are, and the
token returns from the provider straight to the broker. `stk handover
key|seal|open` is the fallback from a machine that does have a browser, sealed
so only the target broker can open it — and it states, rather than hides, that
the credential briefly exists on the sealing machine. The notification adapter
(terminal, webhook, file) is shared with approvals, since a device code and an
approval are the same shape. See [design.md](design.md#connecting-a-service-where-there-is-no-browser)
and [plan-phase-5.md](plan-phase-5.md).

## Phase 6 — release readiness — **gaps closed, awaiting the human test**

See [plan-phase-6.md](plan-phase-6.md). What landed:

- **A durable effects ledger.** The audit screen had returned an empty list
  since Phase 4, because the broker recorded in memory and `stk ui` is another
  process. `stk audit` and the UI now read the same append-only file.
- **OAuth 2.0 authorization code + PKCE, with refresh rotation.** Replaced the
  planned OAuth 1.0a after checking X's live docs: media upload is OAuth 2.0
  only, so 1.0a could not post an image.
- **Eleven connectors**, one per auth scheme and placement.
- **`stk doctor --probe`** — proof that each client here goes through the
  broker, using a `.invalid` host so a DNS failure proves a bypass.
- **Three measurements**, in [measurements.md](measurements.md).
- **README, [limitations.md](limitations.md), [acceptance.md](acceptance.md)**,
  Apache-2.0, NOTICE, a verifying `install.sh`, and reproducible builds.

Two bugs the new tests found, both silent: `Entry.Request()` sent no body, so
`create_issue` dropped its required title; and `-ldflags -X main.version` was
ignored against a `const`, so every release binary would have reported
`0.0.1-dev`.

**Remaining:** the human half of [acceptance.md](acceptance.md), then the
GitHub mirror and the public switch — the operator's call, not a task.
Homebrew after the first tag exists.

## Unscheduled, and each needs a decision rather than a sprint

| Item | Why it is not a phase |
|---|---|
| **WebSocket upgrade handling** | **Now refused loudly** with a 501 and an explanation, instead of appearing to succeed and hanging. Full support still needs a hijack path; tunnelling the host works today and loses injection |
| **Non-HTTP protocols** | Postgres, MySQL, Redis, Kafka, SMTP, IMAP. A CONNECT proxy cannot inject into a Postgres handshake; these need a protocol-aware local proxy, which is a second product shape |
| **Inbound webhooks** | Receiving and verifying provider events is half of what an integration platform does, and all of it is a new surface with a different security posture |
| **Connectors as pinned binaries** | `connector-protocol/v1` is already specified. It earns its place when a service needs code we have to ship, which no service does yet |
| **Identity chaining** | ID-JAG and RFC 8693 against whichever issuer a deployment has. This is the step that makes it a product rather than a utility — and the drafts are still moving, so it should follow the RFC rather than predict it |
| **vsock transport** | For microsandboxes, where the sandbox has no filesystem shared with the host. Needs a guest-side shim, since curl cannot speak AF_VSOCK |
| **Brokered mTLS, certificate pinning** | **Measured: does not work.** 502, loud, nothing sent — the broker holds no client certificate. Tunnel that host. Changing it means a client certificate per service in the store |
| **Bodies above 64 KB** | **Measured: transparent to 8 MB**, hashes matching end to end, credential still substituted. Nothing buffers a whole body, so the next limit is the provider's |
| **Measured latency** | **Measured: ~79 µs median, 459 µs p99**, against 56 µs direct on loopback. A cross-region round trip is 250–1,900 times that |
| **GraphQL APIs** | New entry. Every call is `POST /graphql` with the operation in the body, so policy cannot name what it allows and the ledger cannot say what happened. Linear was dropped from the launch catalogue for this; a test now fails any entry with that shape |
