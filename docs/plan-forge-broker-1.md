# Forge broker, slice 1: configured forge service, verify, atomic replace, sealing — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** stk can hold a Forgejo API token for a host named in configuration, verify it against the provider, replace it atomically, and receive it as a sealed envelope produced anywhere.

**Architecture:** A `kind: forge` entry in the policy file becomes a per-instance copy of a `catalog.Entry` (host, scheme and repositories come from config, not the compiled-in map). The CLI resolves service names through the loaded config before the catalogue. `verify` is a new package that makes one read call to the provider's identity endpoint. Request rules, the fixed listener and OS-user install are later slices.

**Tech Stack:** Go (module `github.com/SuperJackfruitLabs/supertoolkit`), `gopkg.in/yaml`, `net/http/httptest`, stdlib only for new code.

**Spec:** `docs/forge-broker-design.md` (decisions 1, 5, 6, 7), companion agentpod `docs/superpowers/specs/2026-10-17-forge-api-access-design.md`.

## Global Constraints

- The agent never holds, reads or receives a credential. No command prints, logs or returns one; `verify` output contains a login and a reason, never a token.
- Never log a secret; the audit record carries fingerprints (existing test `TestAuditNeverContainsTheSecret` must stay green).
- Fail closed, never direct.
- Pull requests are opened on forge (`origin`); do not use `gh`.
- Version tags continue from `0.0.1`.
- Built-in services behave exactly as before.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Tests are stdlib `testing`; run `go test ./...` before every commit.

## Review Focus

1. A `host` containing a scheme, path, port or whitespace (`https://forge.example/`) is rejected at load, not silently mismatched at the proxy.
2. Two forge entries on the same host would collide in the proxy's host map, so the second is rejected with a clear error for now (the placeholder names the service, so a later slice can lift this).
3. `repositories` entries without exactly one `/`, or empty, are rejected.
4. `verify` must not follow redirects (an `Authorization` header sent to a redirect target is a leak), must treat 401, 403, 5xx, a non-JSON body and a dial failure each as a distinct `reason`, and must not echo a provider error body that could contain the header.
5. A crash or concurrent read during credential replace must see the old or the new value, never a torn file; the temp file is `0600` and removed on failure.

---

### Task 1: Forge entries from configuration

**Files:**
- Create: `internal/catalog/forge.go`, `internal/catalog/forge_test.go`
- Modify: `internal/policy/config.go` (the `file` struct near line 188 and `Load` near line 256), `internal/policy/config_test.go`

**Interfaces:**
- Produces:
  - `catalog.ForgeSpec{Name, Provider, Host, APIPrefix, Auth, Scheme, EnvVar string; Repositories []string; Preset string}`
  - `catalog.NewForgeEntry(spec ForgeSpec) (*Entry, error)`
  - `Entry.Forge *ForgeInfo`, with `ForgeInfo{Provider, APIPrefix, Preset string; Repositories []string; IdentityPath string}` (nil for built-ins).
  - `catalog.Providers() []string` returns `forgejo, gitea, github, bitbucket`.
- Consumes: existing `Entry`, `Placement`, `AuthToken`.

- [ ] **Step 1: Write failing tests** in `forge_test.go`: `TestNewForgeEntryForgejo` (spec `{Name:"forge-main", Provider:"forgejo", Host:"forge.superjackfruit.com", Auth:"token", Scheme:"bearer", EnvVar:"FORGEJO_TOKEN", Repositories:["SuperJackfruitLabs/supertoolkit"], Preset:"issues"}` yields `Entry.Host`, `EnvVar`, `Auth == AuthToken`, `Placement == BearerHeader`, `Forge.APIPrefix == "/api/v1"`, `Forge.IdentityPath == "/user"`); `TestNewForgeEntryRejects` as a table: host with scheme, host with path, host with port-less whitespace, empty host, unknown provider, unknown scheme, `auth: app` (not in this slice: error says "app auth arrives with the GitHub adapter"), empty repositories, repository `"nobody"`, unknown preset (allowed: `read issues pull-requests maintain none`).
- [ ] **Step 2:** `go test ./internal/catalog -run Forge` — expect FAIL (undefined).
- [ ] **Step 3: Implement `NewForgeEntry` and `Providers`** in `forge.go`. Provider defaults: forgejo/gitea `APIPrefix "/api/v1"`, github `""` with identity `/user`, bitbucket `"/2.0"` with identity `/user`. `scheme: token` maps to the new `Placement` added in Task 3, so for now accept only `bearer` and return a clear error for `token` that Task 3 removes.
- [ ] **Step 4:** run the catalog tests — expect PASS.
- [ ] **Step 5: Write failing tests** in `config_test.go`: `TestLoadForgeService` (yaml with `services.forge-main: {kind: forge, provider: forgejo, host: …, auth: token, scheme: bearer, env_var: FORGEJO_TOKEN, repositories: […], preset: issues}` loads; `Config.Service("forge-main").Entry().Forge.Repositories` matches; `InterceptHosts()` contains the host); `TestLoadForgeRejectsSecondEntryOnSameHost`; `TestLoadStillRejectsUnknownBuiltin` (a service with no `kind` and an unknown name still fails with today's message); `TestForgeEntriesAreCopies` (two loads of different hosts do not share an `*Entry`).
- [ ] **Step 6:** `go test ./internal/policy` — expect FAIL.
- [ ] **Step 7: Extend `file.Services` with `kind, provider, host, api_prefix, auth, scheme, env_var, repositories, preset` and make `Load` call `catalog.NewForgeEntry` when `kind == "forge"`**, otherwise `catalog.Lookup` as today. Enforce the same-host rule in `Load`.
- [ ] **Step 8:** `go test ./...` — expect PASS.
- [ ] **Step 9: Commit** `feat(policy): forge services defined in configuration`.

### Task 2: The CLI resolves configured services

**Files:**
- Create: `cmd/stk/resolve.go`, `cmd/stk/resolve_test.go`
- Modify: `cmd/stk/setup.go` (lines 84, 144, 160), `cmd/stk/headless.go` (232, 284), `cmd/stk/revoke.go` (46)

**Interfaces:**
- Produces: `resolveEntry(name string) (*catalog.Entry, error)` — loads the policy file at `configPath()` if it exists, returns its entry for `name`, else `catalog.Lookup`, else an error that names both the known built-ins and, when the config is missing or lacks the name, says "forge services are defined in the policy file with `kind: forge`".
- Consumes: `policy.Load`, `configPath()`.

- [ ] **Step 1: Write failing tests**: `TestResolveEntryPrefersConfig` (a temp `STK_CONFIG` with a forge entry resolves; a built-in name still resolves with no config file); `TestResolveEntryUnknownMentionsForgeKind`; `TestConnectForgeServiceFromStdin` (pipe a token to `cmdConnect("forge-main")` with a temp `STK_HOME` and `STK_PASSPHRASE`; `store.Has("forge-main")` is true and stdout contains no token); `TestRevokeForgeServiceLocal`.
- [ ] **Step 2:** `go test ./cmd/stk -run 'Resolve|ConnectForge|RevokeForge'` — expect FAIL.
- [ ] **Step 3: Implement `resolveEntry`** and replace the five `catalog.Lookup` call sites. `stk add` keeps built-ins only but its error now mentions `kind: forge`.
- [ ] **Step 4:** `go test ./...` — expect PASS.
- [ ] **Step 5: Commit** `feat(cli): connect, revoke and handover resolve forge services`.

### Task 3: `Authorization: token` scheme

**Files:**
- Modify: `internal/catalog/catalog.go` (the `Placement` enum near line 33), `internal/credential/inject.go`, `internal/catalog/forge.go`
- Test: `internal/credential/inject_test.go`

**Interfaces:**
- Produces: `catalog.SchemeHeader` placement; `Inject(r, placeholder, secret, catalog.SchemeHeader, "token")` sets `Authorization: token <secret>` when the header contains the placeholder (the `field` argument carries the scheme word). `NewForgeEntry` maps `scheme: token` to it.

- [ ] **Step 1: Write failing tests**: `TestInjectSchemeHeader` (header `Authorization: token stk:ref:forge-main:v1` becomes `Authorization: token SECRET`; a request without the placeholder is untouched and returns false; scheme word with different case in the incoming header still matches); `TestNewForgeEntryTokenScheme`.
- [ ] **Step 2:** run both packages — expect FAIL.
- [ ] **Step 3: Add the placement and its `Inject` case**, and drop the Task 1 "token scheme not yet" error.
- [ ] **Step 4:** `go test ./...` — expect PASS.
- [ ] **Step 5: Commit** `feat(credential): Authorization: token scheme for forges`.

### Task 4: Atomic credential replace

**Files:**
- Modify: `internal/credential/store.go` (`putSealed`, line 104)
- Test: `internal/credential/store_test.go`

**Interfaces:**
- Produces: `putSealed` writes to a `0600` temp file in the store directory, `fsync`s, then renames over the target; the temp file is removed on any failure.

- [ ] **Step 1: Write failing tests**: `TestPutIsAtomicUnderConcurrentReads` (one goroutine loops `Put` alternating two distinct values, eight goroutines loop `Get`; every `Get` returns one of the two values or the not-yet-stored error, never a decrypt failure; run with `-race`); `TestPutLeavesNoTempFilesOnFailure` (make the target directory read-only after open, `Put` errors, directory listing contains no `*.tmp`); `TestPutKeepsMode0600`.
- [ ] **Step 2:** `go test -race ./internal/credential -run 'Atomic|NoTemp|Mode'` — expect FAIL on the concurrency test.
- [ ] **Step 3: Implement** with `os.CreateTemp(dir, ".<service>.*.tmp")`, `Chmod(0o600)`, write, `Sync`, `Rename`.
- [ ] **Step 4:** `go test -race ./...` — expect PASS.
- [ ] **Step 5: Commit** `fix(credential): replace a stored credential atomically`.

### Task 5: `stk verify`

**Files:**
- Create: `internal/verify/verify.go`, `internal/verify/verify_test.go`, `cmd/stk/verify.go`, `cmd/stk/verify_test.go`
- Modify: `cmd/stk/main.go` (dispatch and usage text)

**Interfaces:**
- Produces:
  - `verify.Result{OK bool; Login string; Reason string}` with JSON tags `ok, login, reason`.
  - `verify.Run(ctx context.Context, in verify.Input) verify.Result`, with `verify.Input{Entry *catalog.Entry; Secret string; ExpectLogin string; HTTP *http.Client; BaseURL string}` — `BaseURL` overrides `https://<Host>` for tests only.
  - Reasons (constants): `unauthorized`, `forbidden`, `unreachable`, `unexpected-response`, `wrong-identity`, `unsupported`.
  - CLI: `stk verify <service> [--expect-login L] [--json]`; exit 0 only when `OK`.
- Consumes: Task 1's `Entry.Forge`, Task 3's placement for header construction, `credential.Store.Get`.

- [ ] **Step 1: Write failing tests** against an `httptest.NewTLSServer` fake Forgejo: `TestVerifyOK` (`GET /api/v1/user` with `Authorization: Bearer S` returns `{"login":"chotu"}` → `{OK:true, Login:"chotu"}`); `TestVerifyTokenScheme`; `TestVerifyReasons` table (401→unauthorized, 403→forbidden, 500→unexpected-response, 200 with HTML→unexpected-response, closed server→unreachable); `TestVerifyWrongIdentity` (`ExpectLogin:"other"`); `TestVerifyDoesNotFollowRedirects` (302 to a second server that records any request; the second server sees none and the result is unexpected-response); `TestVerifyResultNeverContainsSecret` (provider echoes the Authorization header in its error body; marshalled `Result` does not contain the secret); `TestVerifyUnsupportedForBuiltin` (Entry with `Forge == nil`).
- [ ] **Step 2:** `go test ./internal/verify` — expect FAIL.
- [ ] **Step 3: Implement `verify.Run`** with a client that has `CheckRedirect` returning `http.ErrUseLastResponse` and a 15 s timeout; parse only `login` (and `username` fallback for providers that use it) from the JSON body; never copy body text into `Reason`.
- [ ] **Step 4:** `go test ./internal/verify` — expect PASS.
- [ ] **Step 5: Write failing CLI tests**: `TestVerifyCommandJSON` (stdout is valid JSON of `Result`, exit code 0 on ok, non-zero on each failure), `TestVerifyCommandNeverPrintsToken`.
- [ ] **Step 6: Implement `cmdVerify`** reading the secret via the store and calling `verify.Run`; wire into `main.go`.
- [ ] **Step 7:** `go test ./...` — expect PASS.
- [ ] **Step 8: Commit** `feat(verify): stk verify checks a stored credential against the provider`.

### Task 6: Sealing without a local store, and a frozen envelope

**Files:**
- Modify: `cmd/stk/headless.go` (`handoverSeal`, near line 232)
- Create: `testdata/handover-v1.json`, `docs/handover-v1.md`
- Test: `internal/handover/handover_test.go`, `cmd/stk/headless_test.go`

**Interfaces:**
- Produces: `stk handover seal --to <key> --stdin [--json]` reads `field=value` lines (or one bare value for a one-field service, with `--service <name>` naming the field set) from stdin and prints the `stk-handover-v1:` envelope; `stk handover open <service> --json` prints `{"service":"…","stored":true}`; `stk handover key --json` prints `{"public_key":"…"}`.
- Consumes: `handover.Seal`, `Keypair.Open`, Task 2's `resolveEntry`.

- [ ] **Step 1: Write failing tests**: `TestHandoverV1Vector` (loads `testdata/handover-v1.json` containing a private key, the plaintext `Material`, and a recorded envelope; `Keypair.Open` returns that material — this is the conformance vector agentpod's TypeScript implementation must also pass); `TestSealFromStdinRoundTrip` (seal to a test keypair with `--stdin`, then `open` stores it, `store.Material` equals the input); `TestSealOutputContainsNoPlaintext`; `TestHandoverOpenJSON`; `TestHandoverKeyJSON`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement the `--stdin`, `--service` and `--json` options**, generate the vector once with a fixed test keypair and commit it, and write `docs/handover-v1.md` specifying the envelope layout (prefix, NaCl anonymous box, JSON `Material` plaintext, field names) precisely enough for an independent implementation. State that v1 is frozen.
- [ ] **Step 4:** `go test ./...` — expect PASS.
- [ ] **Step 5: Commit** `feat(handover): seal from stdin, JSON output, frozen v1 vector`.

### Task 7: End-to-end through the proxy, and docs

**Files:**
- Create: `e2e/forge_test.go`
- Modify: `README.md` (services section), `docs/forge-broker-design.md` (status line)

- [ ] **Step 1: Write failing e2e test** `TestForgeServiceInjectsThroughProxy`: policy file with a forge entry pointing at a fake provider over TLS (follow `e2e/` helpers), `connect` a token, run a client through `stk run` with `FORGEJO_TOKEN` placeholder, assert the fake provider saw `Authorization: Bearer <token>` and the audit log contains the service name and no token.
- [ ] **Step 2:** `go test ./e2e -run Forge` — expect FAIL or pass depending on earlier tasks; fix any gap it finds in `internal/broker` host mapping.
- [ ] **Step 3:** Update README and set the spec status to "slice 1 implemented".
- [ ] **Step 4:** `go test ./...` and `go vet ./...` — expect PASS.
- [ ] **Step 5: Commit** `test(e2e): a forge service injects through the proxy`.

---

**Not in this slice:** request rules and presets enforcement, the fixed authenticated listener and `stk env`, `stk install` and isolation reporting, `auth: app` verify, reload and audit labels, harness probes, CA name constraints. Each is its own plan, in the order the design lists.

**Manual follow-up (needs a real token, so an operator step):** confirm Forgejo 16.0.5 accepts `Authorization: Bearer` for an API token; if not, set `scheme: token` for Forgejo services.
