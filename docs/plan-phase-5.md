# Phase 5 implementation plan

**Goal:** connect a service on a machine with no browser — a VPS, a container, a
sandbox — without the credential ever transiting anything but the provider and
the broker.

**Why it is a phase rather than a flag.** Every path so far assumes someone can
open a browser where the broker runs. A deployed agent is the normal case, and
until this exists, `stk connect` on a server means pasting a token in by hand,
which is the habit this product exists to replace.

**Spec:** [design.md](design.md). **Roadmap:** [roadmap.md](roadmap.md).

## Global constraints

The sixteen already in force, plus two:

- **The credential travels provider → broker, and nowhere else.** Not through a
  hub, not through a laptop, not through us. Where a fallback cannot manage that,
  it says so rather than pretending.
- **A code is not a credential, and is treated as neither secret nor harmless.**
  A user code may be read aloud; it is useless without the person approving it.
  A device code may not, because it is the thing the poll redeems.

## The three paths, in order of preference

1. **Device authorization grant** (RFC 8628). The broker asks the provider, gets
   a short user code and a URL, reaches the operator through the notification
   adapter, and polls. The token comes back to the broker directly.
2. **The broker's own web UI**, over a private network, where the provider's
   redirect can reach it.
3. **Encrypted hand-over** from a machine that does have a browser. The broker
   publishes a public key; the operator's machine seals the credential to it;
   only the broker can open it. The credential exists briefly on the operator's
   own machine, which is stated rather than hidden.

---

### Task 1: the device flow

**Files:** create `internal/deviceflow/flow.go`, `flow_test.go`

**Produces:** `Start(ctx, cfg) (*Authorization, error)`, `Poll(ctx, cfg, auth) (Token, error)`.

- [ ] Write the failing test against a fake provider: start returns the user
      code, verification URI and interval; polling returns the token once the
      provider says it was approved.
- [ ] **`authorization_pending` is not an error** — the spec's normal case. The
      poll keeps going.
- [ ] **`slow_down` increases the interval by five seconds** and keeps polling,
      per RFC 8628 §3.5. Getting this wrong is how a client gets rate-limited at
      the moment a person is trying to help it.
- [ ] `access_denied` and `expired_token` stop, and are reported as what they
      are rather than as a network failure.
- [ ] The poll honours the context, so ctrl-C does not leave a goroutine.
- [ ] Assert no error message contains the device code, which is the value a
      poll redeems.
- [ ] Run, implement, run, commit.

### Task 2: providers that support it

**Files:** modify `internal/catalog/catalog.go`, `catalog_test.go`

- [ ] `Entry` gains a `Device` block: the authorization and token endpoints, the
      client id, and the scopes to request.
- [ ] GitHub is configured, because it genuinely supports the flow.
- [ ] A service with no device support reports that plainly, so `stk connect
      --device` says "this provider does not offer it, here is what to do
      instead" rather than failing obscurely.
- [ ] Run, implement, run, commit.

### Task 3: reaching the human

**Files:** create `internal/notify/notify.go`, `notify_test.go`

**Produces:** `Notify(ctx, Message) error`, with terminal, webhook and file sinks.

- [ ] Write the failing test: a message reaches every configured sink; a sink
      that fails does not stop the others, because the code reaching the person
      by any route is what matters.
- [ ] Assert the message carries the user code and the URL and **never** the
      device code or a credential.
- [ ] This is the same adapter an approval will use — a device code and an
      approval are both "something remote needs a specific person and will
      wait" — so the interface is written once here.
- [ ] Run, implement, run, commit.

### Task 4: `stk connect --device`

**Files:** modify `cmd/stk/setup.go`, create `cmd/stk/connect_device_test.go`

- [ ] `stk connect <service> --device` runs the flow, prints the code and URL,
      notifies through the adapter, polls, and stores the result.
- [ ] It prints what will happen before it happens, and how long the code lasts.
- [ ] Ctrl-C cancels cleanly without leaving the service half-connected.
- [ ] Commit.

### Task 5: encrypted hand-over

**Files:** create `internal/handover/handover.go`, `handover_test.go`

**Produces:** `PublicKey()`, `Seal(pub, Material)`, `Open(sealed)`.

- [ ] Write the failing test: material sealed to the broker's public key opens
      only with its private key; a tampered envelope fails rather than returning
      partial material.
- [ ] `stk handover key` prints the public key; `stk handover open` reads a
      sealed envelope on stdin and stores it.
- [ ] The command says plainly that the credential exists briefly on the machine
      doing the sealing, because a fallback that hides its cost is worse than
      one that states it.
- [ ] Commit.

### Task 6: end to end

**Files:** create `e2e/device_test.go`

- [ ] A fake provider that behaves like a real one: pending for a few polls,
      then a `slow_down`, then approval.
- [ ] Assert the token reaches the store, that the flow took at least as long as
      the increased interval demanded, and that nothing logged the device code.
- [ ] Commit.

## Out of scope for Phase 5

Refreshing a device-granted token, which is the acquire path Phase 2 already
has. PKCE browser flows, which need a redirect the broker can receive — that is
path 2 and belongs with the web UI. Any provider-specific quirk beyond GitHub
until a second provider needs it.
