# Forge broker, slice 3: reachable, isolated, GitHub-capable, reloadable — Implementation Plan

> **For agentpod workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A station can run stk as its own OS user, a separately started harness can reach its proxy with a credential, GitHub App grants work and verify, and policy changes apply without a restart.

**Architecture:** The broker gains an optional proxy credential and `Reload`. `stk serve` can publish the proxy on a fixed loopback address; `stk env` prints what a client needs. `stk install` provisions the service user and unit (Linux, behind an injectable runner so tests never touch the host). `doctor` reports an isolation level it actually checked. GitHub-provider forge entries may use `auth: app`, reusing the existing JWT-and-exchange operation with repository-restricted installation tokens.

**Tech Stack:** Go stdlib, existing `internal/*` packages, `golang.org/x/crypto`.

**Spec:** `docs/forge-broker-design.md` decisions 3, 4, 6, 7, 9 (probe exit codes only). Slices 1–2: `docs/plan-forge-broker-1.md`, `docs/plan-forge-broker-2.md` (merged). Agentpod's consuming interface table is in the same design under "Interface agentpod depends on"; this plan makes every row real.

## Global Constraints

- The agent never holds, reads or receives a credential. The proxy credential gates *use of the broker* only; it is not a service credential and must never unlock a secret.
- Never log a secret, a proxy credential, a private key or a JWT. The audit record carries fingerprints.
- Fail closed, never direct. A broker that cannot authenticate a client refuses before opening any tunnel.
- Built-in services and `stk run` behave exactly as before unless a task says otherwise.
- Tags continue from `0.0.1`. Pull requests are opened on forge (`origin`); do not use `gh`.
- Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- `go vet ./... && go test ./...` before every commit. `TestRefresh*` in `internal/credential` is a known flake.
- Tests that would modify the host (users, `/etc`, systemd) use a temp root and a fake runner. Nothing in the suite may need root; root-only checks `t.Skip` when not root.

## Review Focus

1. A CONNECT without `Proxy-Authorization`, with a wrong key, with a different scheme, with a malformed header, or with the key in the URL/query gets 407 before the connection is hijacked and before any tunnel or interception; comparison is constant-time.
2. The proxy key file is `0600`, created atomically, never printed except by `stk env` to the operator's terminal/stdout, and never written to the audit log or any log line.
3. `stk install` is idempotent (a second run changes nothing), refuses to run as non-root, never overwrites an existing store, never puts the passphrase in an environment file, and the unit denies the agent's user read access to the store, key and approvals by file mode.
4. `doctor`'s isolation verdict is `separate-user` only when every file on the path (store dir, `*.cred`, `salt`, key, `handover.key`, socket dir, approvals) is unreadable by every configured agent uid, including via group, ACL-free mode bits, and a symlinked or world-writable parent directory; any doubt reports `same-user` with the reason.
5. Reload is atomic for in-flight requests (a request sees the old or the new rules, never a mix), a bad file keeps the old policy and reports why, and a reload that removes a service stops brokering its host immediately.
6. A GitHub App installation token is requested with only the configured repositories, and `verify` for an app grant fails if any configured repository is missing from the installation.

---

### Task 1: Proxy credential in the broker

**Files:**
- Modify: `internal/broker/proxy.go` (`Options`, `Broker`, `handle`), `internal/broker/proxy_test.go`

**Interfaces:**
- Produces: `broker.Options.ProxyKey string` (empty = no authentication, today's behaviour). When set, `handle` requires `Proxy-Authorization: Basic base64("stk:" + key)` (scheme case-insensitive, username `stk`, key compared with `subtle.ConstantTimeCompare`); otherwise it answers `407` with `Proxy-Authenticate: Basic realm="stk"` and body `proxy authentication required`, increments `Stats.Refused`, and never hijacks or tunnels. `broker.ProxyURL(addr, key string) string` returns `http://stk:<key>@<addr>` with the key URL-escaped.
- Consumes: slice 2 `Stats.Refused`.

- [ ] **Step 1: Write failing tests**: `TestProxyKeyRequiredWhenSet` (no header, wrong key, Bearer scheme, malformed base64, wrong username → 407, `Refused` incremented, nothing dialled: assert the injected `Dial` was never called), `TestProxyKeyAccepted` (a real CONNECT with the right header reaches an intercepted fake provider and the credential is substituted), `TestNoProxyKeyKeepsOldBehaviour`, `TestProxyKeyNeverInRecords` (the key does not appear in any `Record`), `TestProxyURLEscapesKey`.
- [ ] **Step 2:** `go test ./internal/broker -run ProxyKey` — expect FAIL.
- [ ] **Step 3: Implement** the check at the top of `handle`, before the CONNECT-method check's hijack.
- [ ] **Step 4:** `go test -race ./internal/broker` — expect PASS.
- [ ] **Step 5: Commit** `feat(broker): optional proxy credential, 407 before any tunnel`.

### Task 2: Fixed listener, `stk serve --proxy-listen`, `stk env`

**Files:**
- Create: `cmd/stk/env.go`, `cmd/stk/env_test.go`, `cmd/stk/proxykey.go`, `cmd/stk/proxykey_test.go`
- Modify: `cmd/stk/serve.go` (`cmdServe` takes args), `cmd/stk/run.go` (`startBroker` gains a listen address and key), `cmd/stk/main.go`

**Interfaces:**
- Produces:
  - `loadOrCreateProxyKey(dir string) (string, error)` — `<dir>/proxy.key`, 32 random bytes base64url, written atomically at `0600`, reused if present, error if present with a mode wider than `0600`.
  - `stk serve --proxy-listen <host:port>` (loopback addresses only; anything else is an error naming why). Default (flag absent) is today's random loopback port with no key. With the flag the broker is started with `ProxyKey`.
  - `stk env [--json]` prints, for a running or configured station, the proxy URL with userinfo, the CA path, the placeholder variables for every configured service, and `NODE_USE_ENV_PROXY=1`/`STK_BROKERED=1`, built with the shared `broker.ChildEnv`. `--json` emits `{"proxy_url","ca_path","env":{...}}`. It reads the key from `proxy.key`; it never prints a service credential.
- Consumes: Task 1 `ProxyKey`, `ProxyURL`; `broker.ChildEnv`.

- [ ] **Step 1: Write failing tests**: `TestProxyKeyFileIsCreated0600AndReused`, `TestProxyKeyRefusesWideMode`, `TestServeProxyListenRejectsNonLoopback`, `TestEnvJSONHasProxyURLWithUserinfoAndNoServiceSecret` (store a service secret; assert it appears nowhere in the output), `TestEnvPlaceholdersMatchConfig`, `TestCurlThroughFixedListenerWithKey` (e2e: start `serve`-equivalent broker on a fixed port with a key; curl with the `env` output reaches the fake provider with the real credential; curl without the key gets 407 and the provider is not hit).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement.** Keep `stk run` and the default `serve` unchanged.
- [ ] **Step 4:** `go test ./cmd/stk ./e2e` — expect PASS.
- [ ] **Step 5: Commit** `feat(serve): fixed authenticated proxy listener and stk env`.

### Task 3: Control-socket caller allowlist

**Files:**
- Modify: `internal/daemon/daemon.go`, `cmd/stk/serve.go` (`handle`, `cmdServe` flag `--allow-uid`), tests

**Interfaces:**
- Produces: `daemon.Options{AllowUIDs []int; PeerUID func(net.Conn) (int, error)}` (second field for tests; default reads kernel peer credentials as today). A connection from a uid not in `AllowUIDs` (when the list is non-empty) is closed before any request is read. The accepted uid is passed to `handle` and recorded in the audit entry's `Caller` as `uid:<n>`.
- Consumes: existing `daemon.Listen`.

- [ ] **Step 1: Write failing tests**: `TestDaemonRefusesAnUnlistedUID` (injected `PeerUID` returns 4242; handler never called), `TestDaemonAcceptsAListedUID`, `TestEmptyAllowListKeepsOldBehaviour`, `TestHandleReceivesTheUID`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** and thread the uid into the audit `Caller`.
- [ ] **Step 4:** `go test -race ./internal/daemon ./cmd/stk` — expect PASS.
- [ ] **Step 5: Commit** `feat(daemon): allowlist callers by uid and record who called`.

### Task 4: `stk install` — own OS user and service unit

**Files:**
- Create: `cmd/stk/install.go`, `cmd/stk/install_test.go`, `internal/install/install.go`, `internal/install/unit.go`, `internal/install/install_test.go`

**Interfaces:**
- Produces:
  - `install.Plan{User, Group string; StateDir, RuntimeDir, ConfigPath string; AgentUIDs []int; Binary string}` and `install.Run(ctx, p Plan, root string, r Runner) (Report, error)`; `Runner` is `interface{ Run(name string, args ...string) error }` (production: `exec`; tests: a recorder). `root` prefixes every path (production `/`).
  - `install.Unit(p Plan) string` renders the systemd unit: `User=<User>`, `NoNewPrivileges=yes`, `LoadCredential=stk-passphrase:<StateDir>/passphrase.cred`, `ExecStart=<Binary> serve --proxy-listen 127.0.0.1:<port> --allow-uid …`, `ProtectSystem=strict`, `ReadWritePaths=<StateDir> <RuntimeDir>`, `UMask=0077`. No `Environment=STK_PASSPHRASE`.
  - `stk install --user stk [--state-dir /var/lib/stk] [--runtime-dir /run/stk] [--config /etc/stk/supertoolkit.yaml] [--agent-uid N]… [--dry-run]`. Non-root without `--dry-run` is an error. `--dry-run` prints the plan and the unit and changes nothing.
  - `Report` lists what was created/changed/left alone, never a secret.
- Consumes: nothing else; the passphrase file is generated here (32 random bytes, `0400`, owned by the service user) only if absent.

- [ ] **Step 1: Write failing tests** with a temp root and recorder: `TestInstallCreatesUserDirsAndUnit` (recorder saw `useradd` once; dirs `0700` owned by the user via recorded `chown`; unit text has the required lines and no `STK_PASSPHRASE`), `TestInstallIsIdempotent` (second run: no `useradd`, files byte-identical, Report says unchanged), `TestInstallNeverOverwritesAnExistingStore` (a pre-existing `salt` and `*.cred` untouched), `TestInstallRefusesNonRoot`, `TestDryRunChangesNothing`, `TestUnitDoesNotGrantAgentUIDsAccess` (state dir mode `0700`, socket dir group-less), `TestPassphraseFile0400`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement.** Linux only; on other platforms return `install is Linux/systemd only`.
- [ ] **Step 4:** `go test ./internal/install ./cmd/stk` — expect PASS.
- [ ] **Step 5: Commit** `feat(install): run stk as its own OS user under systemd`.

### Task 5: `doctor` isolation verdict and `--json`

**Files:**
- Create: `internal/isolation/isolation.go`, `internal/isolation/isolation_test.go`
- Modify: `cmd/stk/doctor.go`, `cmd/stk/doctor_test.go`

**Interfaces:**
- Produces:
  - `isolation.Check(paths []string, agentUIDs []int, inspect func(path string) (fs.FileInfo, error)) Report` where `Report{Level string; Method string; Reasons []string}`, `Level` is `separate-user` or `same-user`, `Method` is `mode-bits` (or `mode-bits+access` when run as root and the access attempt ran). The inspector is injectable for tests; production wraps `os.Lstat`.
  - Rules: the verdict is `separate-user` only if for every path (and every parent up to `/`) the owner is not an agent uid, no group/other bit grants read or write on files and directories holding secrets, no parent directory is writable by an agent uid or world, and no component is a symlink whose target is outside the checked tree. Anything unreadable by the checker is a reason and yields `same-user`.
  - `stk doctor --json` → `{"checks":[…],"isolation":{…}}`; `agent_uids:` is read from the policy file (new top-level key, ints) and `--agent-uid` repeats it.
  - When run as root with agent uids configured, a child process re-executed with `SysProcAttr.Credential` for each uid attempts `open` on each path; success is a reason and forces `same-user`. Skipped (test `t.Skip`) when not root.
- Consumes: Task 4's directory layout.

- [ ] **Step 1: Write failing tests** (fake inspector tables): `TestSeparateUserWhenOwnedByServiceAndMode0700`, `TestGroupReadableIsSameUser`, `TestOtherReadableIsSameUser`, `TestOwnedByAgentUIDIsSameUser`, `TestWorldWritableParentIsSameUser`, `TestSymlinkOutOfTreeIsSameUser`, `TestUnknownPathReportsReasonNotSeparate`, `TestDoctorJSONShape`, `TestRootAccessAttemptForcesSameUser` (skipped unless root).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** `Check`, the policy key, and the JSON output.
- [ ] **Step 4:** `go test ./internal/isolation ./cmd/stk` — expect PASS.
- [ ] **Step 5: Commit** `feat(doctor): report an isolation level that was actually checked; --json`.

### Task 6: GitHub App forge entries

**Files:**
- Modify: `internal/catalog/forge.go`, `internal/catalog/forge_test.go`, `internal/credential/acquire.go` (`ExchangeGitHubApp` request body), `cmd/stk/secrets.go` (`newAcquirers`, `secretSource`), tests

**Interfaces:**
- Produces:
  - `NewForgeEntry` accepts `Auth: "app"` only for `provider: github`; it sets `Entry.Auth = AuthGitHubApp`, `Forge.APIBase` (`https://api.github.com` for host `api.github.com`; `https://<host>/api/v3` for any other host), and `Forge.RepositoryNames` (the `name` half of each `owner/name`). Any other provider with `auth: app` is an error naming the provider.
  - `credential.ExchangeGitHubApp(apiBase string, client *http.Client, repositories func(service string) []string)`: when the function returns a non-empty list the installation-token request body is `{"repositories":["name",…]}`; empty keeps today's body (built-in `github-app` unchanged).
  - `newAcquirers` builds a per-service `Acquirer` for app forge entries (cache and single-flight per service) using that entry's `APIBase`.
- Consumes: slice 1 `NewForgeEntry`, `credential.Material` fields `app_id`, `installation_id`, `private_key`.

- [ ] **Step 1: Write failing tests**: `TestNewForgeEntryAppOnlyForGitHub`, `TestAppEntryAPIBaseForEnterprise`, `TestExchangeRequestsOnlyConfiguredRepositories` (httptest GitHub: capture the body of `POST /app/installations/{id}/access_tokens`), `TestBuiltinGitHubAppBodyUnchanged`, `TestAppForgeInjectsInstallationTokenThroughProxy` (e2e style: fake GitHub token endpoint + fake API; the API sees `Bearer <installation token>`; the private key and JWT appear in no log/record), `TestAppEntryRequiresAppFields` (connect with a missing field is refused by `Require`).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement.** The JWT and private key stay inside `credential`; nothing new logs them.
- [ ] **Step 4:** `go test ./internal/catalog ./internal/credential ./cmd/stk ./e2e` — expect PASS.
- [ ] **Step 5: Commit** `feat(forge): GitHub App grants with repository-restricted installation tokens`.

### Task 7: `verify` for app grants

**Files:**
- Modify: `internal/verify/verify.go`, `internal/verify/verify_test.go`, `cmd/stk/verify.go`, `cmd/stk/verify_test.go`

**Interfaces:**
- Produces: `verify.Input` gains `App *AppInput` with `AppInput{JWT func() (string, error); InstallationToken func() (string, error)}`; `verify.Run` for `Auth == AuthGitHubApp` calls `GET {APIBase}/app` with the JWT (login `<slug>[bot]`), then `GET {APIBase}/installation/repositories` with the installation token, and fails with new reason `repository-missing` if any configured repository (case-insensitive `owner/name`) is absent from the installation, `wrong-identity` if `ExpectLogin` differs from `<slug>[bot]`. Results never contain either token. `cmdVerify` builds `AppInput` from the store and the service's acquirer.
- Consumes: Task 6, slice 1 `verify.Result` and reasons.

- [ ] **Step 1: Write failing tests** against a fake GitHub: `TestVerifyAppOK`, `TestVerifyAppWrongSlug`, `TestVerifyAppRepositoryMissing`, `TestVerifyAppUnauthorized` (401 on `/app` → `unauthorized`), `TestVerifyAppResultNeverContainsTokens`, `TestVerifyAppPaginatesRepositories` (more than one page of installation repositories; a configured repo on page 2 is found), `TestVerifyAppDoesNotFollowRedirects`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** with the same no-redirect client as slice 1.
- [ ] **Step 4:** `go test ./internal/verify ./cmd/stk` — expect PASS.
- [ ] **Step 5: Commit** `feat(verify): verify GitHub App grants and their repositories`.

### Task 8: Reload and audit labels

**Files:**
- Modify: `internal/broker/proxy.go` (`Reload`), `internal/policy/config.go` (`labels:`), `internal/ledger/ledger.go` (`Entry.Labels`), `cmd/stk/audit.go`, `cmd/stk/serve.go` (SIGHUP, `reload` daemon method), `cmd/stk/main.go` (`stk reload`), tests

**Interfaces:**
- Produces:
  - `(*Broker).Reload(cfg *policy.Config) error` — swaps the config and host map under a lock held only for the swap; in-flight requests keep the config they started with; returns an error without changing anything if `cfg` is nil.
  - `labels: {station, principal, grant}` (string map, max 8 keys, values ≤ 128 chars, control characters rejected) on each `kind: forge` service; `Service.Labels() map[string]string`. `ledger.Entry.Labels map[string]string` (`labels,omitempty`); `Observe` copies the service's labels.
  - `stk reload` calls the daemon method `reload`, which re-reads the policy file, validates it fully, and only then calls `Reload`; output is `{"ok":true}` or `{"ok":false,"error":"…"}` with `--json`; SIGHUP does the same. A failed reload keeps the old policy.
  - A reload may not drop below the services that hold credentials without saying so: the result lists services removed.
- Consumes: slices 1–2, Task 2's `serve`.

- [ ] **Step 1: Write failing tests**: `TestReloadChangesRulesOnALiveBroker` (a request denied before reload is allowed after, and vice versa, same listener), `TestReloadIsAtomicForInFlightRequests` (`-race`; hammer requests while reloading between two rule sets and assert every response matches exactly one set), `TestReloadWithABadFileKeepsTheOldPolicy`, `TestReloadRemovingAServiceStopsBrokeringItsHost`, `TestLabelsCopiedToAuditRows`, `TestLabelsRejectControlCharsAndOversize`, `TestReloadCommandJSON`, `TestSIGHUPReloads`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** `Reload` with an `atomic.Pointer` to an immutable snapshot (config + host map) read once at the top of `handle`/`forward`.
- [ ] **Step 4:** `go test -race ./internal/broker ./internal/policy ./internal/ledger ./cmd/stk` — expect PASS.
- [ ] **Step 5: Commit** `feat(serve): reload policy without restart; audit labels`.

### Task 9: Probe exit status, JSON, and the docs

**Files:**
- Modify: `cmd/stk/probe.go`, `cmd/stk/probe_test.go`, `cmd/stk/main.go`, `README.md`, `docs/forge-broker-design.md`

**Interfaces:**
- Produces: `stk doctor --probe` exits non-zero when any client reports `bypassed`; `stk doctor --probe --json` emits `[{"client","outcome","detail"}]` with outcomes `honoured`, `bypassed`, `refused-ca`, `missing`, `failed`. When the broker under probe was started with a proxy key (Task 2 path), the probe sends it via the proxy URL userinfo and reports a client that drops userinfo as `failed` with detail `proxy credential not honoured`.
- Consumes: Tasks 1–2.

- [ ] **Step 1: Write failing tests**: `TestProbeExitsNonZeroOnBypass` (fake client list with one `bypassed`), `TestProbeJSONShape`, `TestProbeReportsClientDroppingProxyUserinfo`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement**; update README (a "Running as a station service" section: `stk install`, `stk env`, `stk reload`, `stk verify`, GitHub App example, isolation levels and what each claims) and set the design's Status line to what is implemented, leaving harness-specific probes, CA name constraints, Bitbucket presets and the MCP token-scheme guard as the remaining items.
- [ ] **Step 4:** `go vet ./... && go test ./...` — expect PASS.
- [ ] **Step 5: Commit** `feat(probe): exit non-zero on bypass, JSON output; docs for the station service`.

---

**Not in this slice:** per-harness bypass probes (needs the harness list and each harness's real client), CA name constraints, Bitbucket presets, the MCP/daemon `SchemeHeader` guard test, the slice 1–2 deferred minors. Authenticating `stk run`'s per-session loopback proxy is also deferred; it keeps today's behaviour (documented in `docs/limitations.md`).
