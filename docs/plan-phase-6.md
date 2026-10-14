# Phase 6 implementation plan — release readiness

**Goal:** close every gap that would embarrass a public Apache-2.0 repository,
measure the three things we have only assumed, and put the whole thing in front
of a human on a clean machine before the mirror exists.

**Why the gaps come before the mirror.** A public repository is a claim. Once
`install.sh` has a URL, "the audit screen is empty" and "latency was never
measured" stop being notes in a plan and become defects someone else finds. The
cheapest moment to close them is while nobody is looking.

**Spec:** [design.md](design.md). **Roadmap:** [roadmap.md](roadmap.md).

## Global constraints

The eighteen already in force, plus two for this phase:

- **A measurement replaces an assumption or it is not worth taking.** Three
  roadmap items say "untested" or "unproven". Each one closes with a number and
  a committed result, or stays open and says why — not with a shrug.
- **A limitation is documented where someone will hit it**, not only in a
  roadmap table. Five items are out of scope by choice; each gets a sentence in
  the README saying so, and the code says so too where it can.

---

### Task 1: the effects ledger

**Files:** create `internal/ledger/ledger.go`, `ledger_test.go`; modify
`internal/broker/proxy.go`, `cmd/stk/ui.go`, `cmd/stk/run.go`, `cmd/stk/audit.go`

The broker records effects in memory and loses them on exit, and `stk ui` is a
different process, so the audit screen has always returned an empty list. For a
credential broker this is the gap that matters most: *what did the agent do with
my credentials* is the question the product exists to answer.

- [ ] Append-only JSON lines at `<home>/audit.log`, mode 0600. One process
      writes while others read, so each line is written with a single `Write` on
      a file opened `O_APPEND` — the one case POSIX gives us atomicity for.
- [ ] A truncated final line (a crash mid-write) is skipped on read, not fatal.
      A ledger that refuses to open because of its last line is a ledger that
      loses everything before it.
- [ ] Bounded: rotate at 8 MB to `audit.log.1`, keeping one generation. An
      unbounded audit log on a small VPS is an outage.
- [ ] **A test that asserts no stored credential, in any field, ever appears in
      the file** — against every auth scheme, including the signed ones where
      what travels is a signature.
- [ ] `stk audit [--limit n] [--json]` reads it, newest first.
- [ ] The web UI's audit screen reads the same file, so the two cannot disagree.
- [ ] Run, implement, run, commit.

### Task 2: OAuth1 signing, and X

**Files:** modify `internal/credential/sign.go`, `sign_test.go`,
`internal/catalog/catalog.go`, `internal/broker/proxy.go`

OAuth1 is the fifth credential operation and nothing proves it with a real
provider. It is also what X requires for the write endpoints the marketing
work needs.

- [ ] `SignOAuth1` per RFC 5849: HMAC-SHA1 over the signature base string, with
      percent-encoding that is RFC 3986 and not `url.QueryEscape` — the
      difference is `+` for a space, and it is the single most common reason an
      OAuth1 implementation returns 401 against a correct secret.
- [ ] Reproduce **RFC 5849 §3.1's own published example** end to end. A
      hand-rolled HMAC that matches nothing external proves only that it is
      self-consistent.
- [ ] `AuthOAuth1` in the catalogue, with four fields: consumer key and secret,
      token and token secret.
- [ ] The broker dispatches on it, so a signed request works through the proxy
      exactly as SigV4 does.
- [ ] Run, implement, run, commit.

### Task 3: seven more connectors

**Files:** modify `internal/catalog/catalog.go`, `catalog_test.go`

X, Slack, Notion, Linear, Google, Stripe, OpenAI, Cloudflare — chosen so every
auth scheme and every placement has a live connector behind it rather than only
a constant.

- [ ] Stripe uses **basic auth**, which is the placement that silently did
      nothing until the catalogue review caught it. A real connector keeps that
      honest.
- [ ] Each capability's `Kind` is set deliberately: a `Destructive` that is
      wrong is a credential doing something unrecoverable on an agent's say-so.
- [ ] A table test asserting every entry is coherent: a host, a placement its
      auth scheme supports, no capability with an unvalidated path parameter.
- [ ] Run, implement, run, commit.

### Task 4: prove the path, do not prove the environment

**Files:** modify `cmd/stk/doctor.go`, create `cmd/stk/probe.go`, `probe_test.go`

`doctor`'s leak check proves no credential is reachable from a child's
environment. That is necessary and **not sufficient**: the spikes found clients
that ignore proxy environment variables entirely and fail *silently*, reaching
the provider with the placeholder and getting a plausible-looking 401. A broker
that cannot detect its own bypass is a broker you cannot trust.

- [ ] `stk doctor --probe` starts the broker, drives a request through it to a
      local stand-in, and asserts the swap counter moved. A green probe is proof
      the path works; a red one names the client.
- [ ] `stk run` checks the child's binary against the known-silent list and says
      so **before** running it, because after is too late to be useful.
- [ ] Run, implement, run, commit.

### Task 5: WebSocket fails loudly

**Files:** modify `internal/broker/proxy.go`, `proxy_test.go`

An `Upgrade: websocket` request through the round-trip path has no hijack, so
today it fails in a way that looks like the provider's fault.

- [ ] Detect the upgrade on an intercepted host and return `501` with a body
      that says what happened and what to do: tunnel the host instead of
      brokering it, which works and loses injection.
- [ ] A test asserting the status and that the message names the host.
- [ ] Run, implement, run, commit.

### Task 6: the three measurements

**Files:** create `docs/measurements.md`, `e2e/measure_test.go`

Each of these is a roadmap line reading "untested" or "unproven". A number
closes it; nothing else does.

- [ ] **Bodies above 64 KB.** Transparent at every size tested, but no endpoint
      ever accepted a large upload. Drive 1 B, 64 KB, 1 MB and 8 MB through a
      local upstream and compare SHA-256 end to end. X media upload is multipart,
      so this is load-bearing for the marketing work.
- [ ] **Brokered mTLS.** Unknown, not broken. A local upstream demanding a client
      certificate, intercepted. Record what actually happens, and if it cannot
      work, say which layer refuses.
- [ ] **Latency.** The repo is about to claim speed. Measure the broker's
      overhead against a local upstream, direct versus brokered, enough
      iterations for a median and a p99.
- [ ] Commit the numbers with the hardware they came from. A benchmark without
      its machine is a rumour.

### Task 7: the README and the limitations

**Files:** modify `README.md`, `docs/roadmap.md`; create `docs/limitations.md`

- [ ] The README earns the first thirty seconds: the thesis in two sentences,
      install, a quickstart that works, the security model, and the limitations
      **above** the feature list rather than below it.
- [ ] `docs/limitations.md` states the five out-of-scope items with the reason
      each is out of scope, and the one failure mode that cannot be fixed —
      clients that ignore proxy configuration — with the detection from Task 4.
- [ ] Commit.

### Task 8: the human acceptance test

**Files:** create `docs/acceptance.md`

The test is a person on a clean machine with a real credential, because every
automated test here shares our assumptions.

- [ ] A numbered journey from `install` to a brokered write, with the expected
      output beside each step, so a deviation is obvious rather than a judgement.
- [ ] It names what only a human can do — approving in a browser, holding a real
      token — and what the machine proves on its own.
- [ ] Every step states what would make it a **failure**, not only what success
      looks like. A script that only describes success passes on a broken build.
- [ ] Run it as far as a machine can, record the result, and hand over the rest.

### Task 9: release mechanics

**Files:** create `LICENSE`, `NOTICE`, `install.sh`, `.github/workflows/release.yml`,
`docs/plan-phase-6.md` updates

- [ ] Apache-2.0, with the NOTICE our dependencies' licences require.
- [ ] `install.sh` verifies `SHA256SUMS` before it moves a binary. An installer
      that pipes curl into sh without checking is the thing this product exists
      to argue against.
- [ ] Reproducible `-trimpath -ldflags "-s -w"` builds for darwin/linux on amd64
      and arm64.
- [ ] The GitHub mirror and the public switch happen **after** Task 8 comes back
      green, and are the operator's call, not mine.

## Out of scope, and documented as such

Non-HTTP protocols, inbound webhooks, connectors as pinned binaries, identity
chaining, and the vsock transport. Each is a product-shape decision rather than
a missing afternoon, and each gets its sentence in `docs/limitations.md`.
