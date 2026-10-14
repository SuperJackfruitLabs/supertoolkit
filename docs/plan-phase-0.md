# Phase 0 implementation plan

**Goal:** `stk run -- gh pr list` works against GitHub with no credential in the
environment, the config file, or the agent's reach — and `stk doctor` proves it.

**Architecture:** A broker daemon owns the credential and runs an egress proxy.
The CLI starts clients with `HTTPS_PROXY` and a placeholder. Phase 0 implements
the two substitute operations only; sign, mint and acquire are Phase 1.

**Spec:** [design.md](design.md)

## Global constraints

Every task inherits these. They come from the spikes and each has a test.

- The agent never holds, reads or receives a credential. No endpoint returns one.
- Injection is credential-scheme aware: Bearer by replace, Basic by decode →
  replace → re-encode.
- HTTP/2 trailers are propagated, with the announce list rebuilt from
  `resp.Trailer`.
- Hosts outside policy are tunnelled with CONNECT and never opened.
- The audit record carries fingerprints, never a secret.
- An unreachable broker makes the client fail. Never a fall back to direct.
- Assert against broker counters and the audit record, not client exit codes.

---

### Task 1: the policy file and the catalogue

**Files:** create `internal/policy/config.go`, `internal/policy/config_test.go`,
`internal/catalog/catalog.go`

**Produces:** `policy.Load(path) (*Config, error)` with
`Config.Service(name) (*Service, bool)`; `Service.Policy(capability) Action`
where `Action` is `ActionAgent | ActionApproval | ActionDeny`;
`catalog.Lookup(name) (*Entry, bool)` carrying host, auth shape and capabilities.

- [ ] Write the failing test: a config naming `github` with `scopes: [repo:read]`
      loads, `Policy("list_repos")` is `ActionAgent`, `Policy("delete_repo")` is
      `ActionDeny` when listed as such, and an unknown capability defaults to
      `ActionApproval` rather than `ActionAgent`.
- [ ] Run it; expect a compile failure.
- [ ] Implement the minimum to pass.
- [ ] Add the revert-proof test: an empty `capabilities` block must default
      **writes to approval**, so deleting the default makes a named test fail.
- [ ] Commit.

### Task 2: scheme-aware injection

**Files:** create `internal/credential/inject.go`, `internal/credential/inject_test.go`

**Consumes:** nothing. **Produces:** `credential.Inject(r *http.Request, secret string) (where string, ok bool)`

- [ ] Write the failing test with four cases: `Bearer stk:ref:…` is replaced;
      `Basic base64(user:stk:ref:…)` is decoded, replaced and re-encoded so the
      provider sees `user:<secret>`; `X-Api-Key` is replaced; `?api_key=` is
      replaced.
- [ ] Add the case that caught the real bug: a naive string replace over the
      Basic header must **not** be what the implementation does — assert the
      output decodes to `user:<secret>` rather than merely differing from input.
- [ ] Run; expect failure.
- [ ] Implement.
- [ ] Commit.

### Task 3: the egress proxy

**Files:** create `internal/broker/proxy.go`, `internal/broker/proxy_test.go`

**Consumes:** `credential.Inject`, `policy.Config`.
**Produces:** `broker.New(cfg) *Broker`, `Broker.Serve(net.Listener) error`,
and counters `Broker.Stats()` with intercept, tunnel, swap, h2 and h1.

- [ ] Write the failing test using a local TLS provider the test controls: a
      CONNECT to an in-policy host is intercepted, the placeholder is swapped,
      and the provider reflects the real secret.
- [ ] Add the tunnel test: an out-of-policy host increments `tunnel`, not
      `intercept`, and no TLS is terminated.
- [ ] Add the trailer test with a control: the provider emits `Grpc-Status`; the
      client must see it through the broker. Keep the direct-to-provider control
      in the test, because without it a missing trailer is ambiguous.
- [ ] Add the h2 and h1 cases, asserting `NegotiatedProtocol` for each.
- [ ] Implement, offering `h2` and `http/1.1` in ALPN.
- [ ] Commit.

### Task 4: credential storage

**Files:** create `internal/credential/store.go`, `internal/credential/store_test.go`

**Produces:** `credential.OpenStore(dir, passphrase) (*Store, error)`,
`Store.Put(service, token) error`, `Store.Get(service) (string, error)`,
`Store.Revoke(service) error`

- [ ] Write the failing test: a token survives a close and reopen; the on-disk
      file does **not** contain the plaintext token; a wrong passphrase fails
      rather than returning garbage.
- [ ] Add the KDF assertion: the derived key must come from HKDF or Argon2id, so
      a short passphrase does not become a short key. Test by asserting two
      different passphrases of the same length produce different ciphertext for
      the same plaintext, and that the stored file length does not reveal the
      token length.
- [ ] Run; expect failure. Implement. Commit.

### Task 5: the CLI

**Files:** create `cmd/stk/main.go`, `cmd/stk/run.go`, `cmd/stk/doctor.go`,
`cmd/stk/doctor_test.go`

**Consumes:** everything above.

- [ ] `stk init` — generate the CA, write `supertoolkit.yaml`, start the broker,
      print the CA trust instruction for this platform (keychain on macOS,
      `SSL_CERT_FILE` on Linux, which the spike showed differ).
- [ ] `stk add <service>` — from the catalogue, with safe default policy.
- [ ] `stk connect <service> --token-stdin` — read a token from stdin, never a
      flag, so it cannot land in shell history. Device grant is Phase 1.
- [ ] `stk run -- <cmd>` — set `HTTPS_PROXY`, the CA variable for the platform,
      and the placeholder in the service's expected position.
- [ ] `stk doctor` — write the failing test first. It must report: broker
      reachable; socket mode and owner; whether the CA is trusted by `curl`;
      **whether `NO_PROXY` is set, which is a confirmed bypass**; and a leak
      check asserting no credential is reachable from the environment the agent
      would see.
- [ ] Commit.

### Task 6: the end-to-end proof

**Files:** create `e2e/e2e_test.go`

- [ ] Write the test that is the point of Phase 0: start a broker, store a
      token, run a child process with only a placeholder in its environment, and
      assert the provider received the real credential **and** that the child's
      own environment never contained it.
- [ ] Add the fail-closed case: with the broker stopped, the child must fail
      rather than reach the provider directly.
- [ ] Commit.

## Out of scope for Phase 0

MCP server and the four meta-tools; the web UI; sign, mint and acquire; profiles
and multiple agents; the approval adapter; device grant; connectors as separate
binaries. Each is Phase 1 or later in [design.md](design.md).
