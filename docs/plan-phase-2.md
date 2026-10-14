# Phase 2 implementation plan

**Goal:** brokering works for services whose credential is not a token to be
copied — where it must be **signed with**, **minted from**, or **exchanged for**.

**Why it matters beyond coverage.** These three operations never put a long-lived
secret on the wire. A signer emits an HMAC; a minter emits a nine-minute JWT; an
acquirer emits a short-lived token it traded for. So the strongest auth schemes
are the ones where the broker gives away the least, and anything that does leak
downstream expires on its own.

**Spec:** [design.md](design.md). **Roadmap:** [roadmap.md](roadmap.md).

## Global constraints

Phase 0's six and Phase 1's three still hold. Two more:

- **A long-lived secret never leaves the broker.** Signing, minting and
  exchanging all happen inside it. The material for these operations has no
  read path at all, not even the one `Store.Get` provides for tokens.
- **Acquisition is single-flight.** Twenty concurrent callers cause one
  exchange. Proven in the spike; now it has to hold in the product.

## The shape change this phase forces

The store holds one string per service. Signing needs an access-key pair,
minting needs a private key, and GitHub App needs an app id, a private key and
an installation id. So credential material becomes **typed** before any of the
three operations can land, and that is Task 1.

---

### Task 1: typed credential material

**Files:** modify `internal/credential/store.go`, `store_test.go`; create `internal/credential/material.go`

**Produces:** `Material map[string]string` with `Material.Token() string`;
`Store.PutMaterial(service, Material) error`, `Store.Material(service) (Material, error)`.
`Put`/`Get` stay as the token shorthand.

- [ ] Write the failing test: a multi-field material round-trips; a store
      written by the old single-token path still reads as `{"token": ...}`, so
      an existing install does not break.
- [ ] Assert the file still contains no plaintext for *any* field, and still
      hides length.
- [ ] Assert `Material` for an absent service is an error, not an empty map —
      an empty map would read as "no credential needed".
- [ ] Run, implement, run, commit.

### Task 2: sign — AWS SigV4

**Files:** create `internal/credential/sign.go`, `sign_test.go`

**Produces:** `SignSigV4(req *http.Request, m Material, region, service string, now time.Time) error`

- [ ] Write the failing test against **AWS's own published vector**
      (`aws-sig-v4-test-suite`, `get-vanilla`): access key `AKIDEXAMPLE`, secret
      `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, region `us-east-1`, service
      `service`, `20150830T123600Z`, expecting signature
      `5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31`.
- [ ] Add the body test: a request with a body must sign the body's SHA-256, so
      changing one byte changes the signature. This is the property that makes
      substitution impossible and signing necessary.
- [ ] Add the refusal test: missing `access_key_id` or `secret_access_key` is an
      error rather than a signature over nothing.
- [ ] Add the no-leak test: the `Authorization` header contains the access key
      id, which is public, and **never** the secret access key.
- [ ] Run, implement, run, commit.

### Task 3: mint — JWT

**Files:** create `internal/credential/mint.go`, `mint_test.go`

**Produces:** `MintJWT(m Material, claims map[string]any, ttl time.Duration) (string, error)`

- [ ] Write the failing test: an RS256 JWT verifies against the public key
      derived from the stored private key.
- [ ] Assert the lifetime: `exp` is within the requested ttl and `iat` is
      slightly in the past, because GitHub rejects a JWT whose `iat` is ahead of
      its clock.
- [ ] Assert a malformed or missing private key is an error.
- [ ] Assert the minted token is not the private key, and that nothing in it
      decodes to the key material.
- [ ] Run, implement, run, commit.

### Task 4: acquire — exchange, with single-flight

**Files:** create `internal/credential/acquire.go`, `acquire_test.go`

**Produces:** `Acquirer` with `Token(ctx, service) (string, error)`, caching
until shortly before expiry.

- [ ] Write the failing test: twenty concurrent callers against a provider that
      sleeps produce **exactly one** exchange, and all twenty get the token.
- [ ] Add the expiry test: after the cached token expires, the next call
      exchanges again — once.
- [ ] Add the failure test: an exchange that fails is not cached, so the next
      call retries rather than returning a stale or empty token.
- [ ] Add the no-leak test: the error from a failed exchange does not contain
      the private key or client secret.
- [ ] Run, implement, run, commit.

### Task 5: wiring, and two real services

**Files:** modify `internal/catalog/catalog.go`, `cmd/stk/serve.go`, `cmd/stk/setup.go`

- [ ] `catalog.Entry` gains `Auth` describing which operation a service needs:
      token, SigV4, JWT, GitHub App, or client credentials.
- [ ] Add `aws` (SigV4, one read capability) and `github-app` (acquire via
      installation token) to the catalogue.
- [ ] `stk connect <service>` reads the fields that service needs rather than a
      single token — still from stdin, never a flag.
- [ ] The executor dispatches on `Auth`, so `execute_action` and the proxy share
      one decision.
- [ ] `stk doctor` reports each service's operation, so an operator can see
      which credentials are long-lived and which are derived.
- [ ] Commit.

### Task 6: end to end

**Files:** create `e2e/operations_test.go`

- [ ] A SigV4 service: the provider verifies the signature it received against
      the expected one and the request is accepted.
- [ ] A GitHub-App-shaped service: the broker mints a JWT, exchanges it for an
      installation token, and the provider sees the installation token — never
      the private key.
- [ ] Assert across all three operations that no response to the agent contains
      any stored material.
- [ ] Commit.

## Out of scope for Phase 2

OAuth 1.0a specifically, though it is the same signer class — it earns its place
with a service that needs it. Two Step and Bill session schemes. Fronting
third-party MCP servers, which is Phase 3.
