# Forge broker, slice 2: request rules in the proxy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `kind: forge` service refuses every request its rules do not allow, before any credential is fetched or anything is sent upstream, and the refusal is audited.

**Architecture:** A new dependency-free package `internal/rules` normalises a request path, matches it against allow/deny rules (deny wins, deny by default), binds `{owner}`/`{repo}` to the service's repositories, and evaluates simple JSON body conditions. Presets are rule lists per provider. `policy` builds a `*rules.Set` per forge service; `broker.forward` consults it first.

**Tech Stack:** Go stdlib, `gopkg.in/yaml`; no new dependencies.

**Spec:** `docs/forge-broker-design.md` decision 2 (and Presets). Slice 1 plan: `docs/plan-forge-broker-1.md`.

## Global Constraints

- The agent never holds, reads or receives a credential; a denied request never causes the secret to be fetched (`b.src` is not called).
- Deny by default for `kind: forge`. A `deny` match wins over an `allow`. Built-in services behave exactly as before (no rules, no enforcement).
- Rules are an extra filter: they never widen the token.
- Requests outside `api_prefix` on a forge host are denied. The query string is ignored for matching and forwarded unchanged.
- GraphQL (`/graphql`, any method) is denied unless the service sets `allow_graphql: true`.
- Body conditions read at most 64 KiB; a body that is not JSON, is over the limit, or has a non-JSON content type fails the condition (deny).
- Denial response: HTTP 403 whose body names the rule id and never a credential. Never log or return the secret.
- Fail closed: any error evaluating a rule is a deny.
- Pull requests are opened on forge (`origin`); do not use `gh`. Commit messages end with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.
- Run `go vet ./... && go test ./...` before every commit. `TestRefresh*` in `internal/credential` is a known flake unrelated to this slice.

## Review Focus

1. Path-normalisation bypasses are denied, each with a test: `/api/v1/repos/o/r/../../admin/users`, `%2e%2e`, `%2E%2E`, `%2f`, `%5c`, `//`, `;param` segments, a trailing `/.`, `\`, NUL and other control bytes.
2. A method-override header (`X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`) on a forge request is denied, because it would turn an allowed `POST` into a `DELETE`.
3. `{owner}`/`{repo}` binding is case-insensitive and exact: `Acme/Widgets` matches `acme/widgets` but not `acme/widgets-evil`, `acme/widgets/../x`, or a repository that is not in the grant.
4. A body condition cannot be dodged: duplicate JSON keys, nested keys, a body over 64 KiB, chunked bodies with no Content-Length, `Content-Type: text/plain` carrying JSON, and a body that is valid JSON but not an object.
5. A denied request is never forwarded and never calls the secret source (assert both), including over HTTP/2.

---

### Task 1: Path normalisation and patterns

**Files:**
- Create: `internal/rules/path.go`, `internal/rules/path_test.go`

**Interfaces:**
- Produces:
  - `rules.NormalizePath(escaped string) (string, error)` — takes `r.URL.EscapedPath()`, returns the cleaned decoded path or an error naming why it was refused (`dot-segment`, `encoded-separator`, `empty-segment`, `control-byte`, `backslash`, `path-parameter`).
  - `rules.MatchPath(pattern, path string, vars map[string]string) bool` — segment-wise: literal (case-sensitive), `*` one segment, `**` the remaining segments (last position only), `{name}` one segment captured into `vars`.
- Consumes: nothing.

- [ ] **Step 1: Write failing tests**: `TestNormalizePathRefuses` (table, one row per Review Focus 1 input, each expecting an error), `TestNormalizePathAccepts` (`/repos/o/r/issues`, `/repos/o/r/issues/7`, encoded space in a segment `%20` decodes to a space), `TestMatchPath` (table: literal, `*`, `**`, `{owner}` capture, `*` does not match two segments, `**` only in last position is a parse concern handled in Task 2, trailing slash does not match).
- [ ] **Step 2:** `go test ./internal/rules` — expect FAIL (undefined).
- [ ] **Step 3: Implement both functions.** `NormalizePath` splits the escaped path on `/` first, rejects any segment whose lowercase contains `%2f`, `%5c`, `%2e` as a whole segment, then decodes each segment once and rejects `.`/`..`, empty interior segments, `;`, `\` and bytes < 0x20 or 0x7f.
- [ ] **Step 4:** `go test ./internal/rules` — expect PASS.
- [ ] **Step 5: Commit** `feat(rules): path normalisation and matching`.

### Task 2: Rules, binding and body conditions

**Files:**
- Create: `internal/rules/rules.go`, `internal/rules/cond.go`, `internal/rules/rules_test.go`

**Interfaces:**
- Produces:
  - `rules.Rule{ID string; Allow bool; Method string; Pattern string; When []Cond}`.
  - `rules.Cond{Key string; Op string; Values []string}` with `Op` one of `absent`, `present`, `equals`, `oneof`; `Key` is a dotted JSON path (`state`, `labels.0` is not supported).
  - `rules.ParseRule(id, line string, when map[string]any, allow bool) (Rule, error)` — `line` is `"POST /repos/{owner}/{repo}/issues"`; rejects unknown methods, empty patterns, `**` not in last position, and `when` keys with unsupported value types.
  - `rules.Set` built by `rules.NewSet(repos []string, rs []Rule) (*Set, error)`.
  - `rules.Request{Method, EscapedPath string; Header http.Header; Body []byte; BodyTruncated bool; ContentType string}`.
  - `rules.Decision{Allowed bool; RuleID string; Reason string}`.
  - `(*Set).Evaluate(prefix string, r Request) Decision` — strips `prefix` (a path outside it is denied with reason `outside-api-prefix`), normalises, applies the method-override rule, evaluates deny-first then allow, denies by default with reason `no-rule`.
  - `rules.MaxBody = 64 << 10`.
- Consumes: Task 1.

- [ ] **Step 1: Write failing tests** (names are the cases): `TestDenyWinsOverAllow`, `TestDefaultDeny`, `TestOwnerRepoBindToGrantedRepositories` (Review Focus 3 inputs, including a repo not in the grant and case differences), `TestRulesWithoutRepoPlaceholderMatchLiterally` (`GET /user`), `TestOutsideAPIPrefixDenied`, `TestMethodOverrideHeaderDenied` (all three header names), `TestBodyConditionAbsent` (allow `PATCH …/issues/*` when `state` absent: `{"title":"x"}` allowed; `{"state":"closed"}` denied), `TestBodyConditionEqualsAndOneOf`, `TestBodyConditionFailsClosed` (not JSON, JSON array, truncated, content type `text/plain`, duplicate key `{"state":"open","state":"closed"}` treated as present), `TestParseRuleRejects` (bad method, `**` mid-pattern, empty pattern).
- [ ] **Step 2:** `go test ./internal/rules` — expect FAIL.
- [ ] **Step 3: Implement.** `{owner}`/`{repo}` are matched case-insensitively and must jointly equal one entry of the granted repositories; any other `{name}` capture is unrestricted. Duplicate-key detection uses `json.Decoder` token streaming at the top level. A `Cond` is evaluated only when the matched rule has `When`; a rule with `When` and a non-evaluable body is a non-match (so deny-by-default applies, and a `deny` rule with `When` that cannot be evaluated is treated as matched, to fail closed).
- [ ] **Step 4:** `go test -race ./internal/rules` — expect PASS.
- [ ] **Step 5: Commit** `feat(rules): evaluate allow/deny rules with repository binding and body conditions`.

### Task 3: Presets

**Files:**
- Create: `internal/rules/presets.go`, `internal/rules/presets_test.go`

**Interfaces:**
- Produces: `rules.Preset(provider, name string) ([]Rule, error)` for providers `forgejo`, `gitea`, `github` and names `read`, `issues`, `pull-requests`, `maintain`, `none` (`none` returns an empty list). Rule ids are `preset:<name>#<n>`. `bitbucket` returns an error `no presets for bitbucket yet; use preset: none and write rules`. Each preset includes the earlier ones; `GET /user` is in `read`; `DELETE` appears in no preset.
- Consumes: Task 2.

- [ ] **Step 1: Write failing tests**: `TestPresetsAreCumulative` (every rule of `read` is in `issues`, of `issues` in `pull-requests`, of that in `maintain`), `TestNoPresetAllowsDelete`, `TestPresetIssuesAllowsCreateAndComment` (evaluate against a `Set` built from `issues` for repo `o/r`: `POST /repos/o/r/issues` allowed, `POST /repos/o/r/issues/7/comments` allowed, `POST /repos/o/other/issues` denied, `POST /repos/o/r/pulls` denied), `TestPresetPullRequestsDoesNotMerge`, `TestPresetMaintainMergeMethodPerProvider` (Forgejo `POST …/pulls/*/merge`, GitHub `PUT …/pulls/*/merge`), `TestBitbucketHasNoPresets`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement the preset tables** from the design's Presets section (read: identity and `GET /repos/{owner}/{repo}/**`; issues: create, edit, comment, edit comment, label edits; pull-requests: create/edit pulls, reviews, requested reviewers; maintain: merge, releases, label create).
- [ ] **Step 4:** `go test ./internal/rules` — expect PASS.
- [ ] **Step 5: Commit** `feat(rules): presets for forgejo, gitea and github`.

### Task 4: Policy builds a rule set per forge service

**Files:**
- Modify: `internal/policy/config.go` (the `file.Services` struct and `Load`), `internal/policy/config_test.go`
- Create: `internal/policy/forge_rules_test.go`

**Interfaces:**
- Produces:
  - YAML on a `kind: forge` service: `rules:` — a list of `{allow: "<METHOD> <pattern>", when: {<key>: absent | present | <string> | [<strings>]}}` or `{deny: …}`; and `allow_graphql: bool`.
  - `(*Service).Rules() *rules.Set` (nil for built-ins), `(*Service).AllowGraphQL() bool`, `(*Service).APIPrefix() string`.
  - The set is the preset's rules followed by the operator's, so a `deny` can subtract and an `allow` can add. A `rules:` entry on a built-in service is an error.
- Consumes: Tasks 2–3, slice 1's `catalog.ForgeInfo`.

- [ ] **Step 1: Write failing tests**: `TestLoadForgeRulesExtendPreset`, `TestLoadForgeRuleDenySubtractsFromPreset`, `TestLoadRejectsRulesOnABuiltin`, `TestLoadRejectsABadRule` (names the service and the rule), `TestLoadRejectsBodyConditionOnGraphQLPath`, `TestLoadForgePresetNoneStartsEmpty`, `TestLoadForgeBitbucketPresetErrors`, `TestAllowGraphQLDefaultsFalse`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** the YAML fields, rule parsing with ids `user#<n>`, set construction in `Load`, and the three accessors.
- [ ] **Step 4:** `go test ./internal/policy` — expect PASS.
- [ ] **Step 5: Commit** `feat(policy): forge services carry a rule set`.

### Task 5: The broker enforces the rules

**Files:**
- Modify: `internal/broker/proxy.go` (`Stats`, `Record`, `forward`, counters), `internal/broker/proxy_test.go`

**Interfaces:**
- Produces: `Stats.Denied int64`; `Record.Rule string`; in `forward`, for a service whose `Rules()` is non-nil and before `b.src` is called: read the body (only when the request method can carry one and the rule set needs it, up to `rules.MaxBody`, restoring `r.Body` for forwarding), evaluate, and on deny respond `403` with `supertoolkit denied this request: rule <id> (<reason>). Nothing was sent.`, set `rec.Status = "403 denied: <id>"`, `rec.Rule = id`, increment `Denied`, and record. A `/graphql` path is denied with rule id `builtin:graphql` unless `AllowGraphQL()`.
- Consumes: Task 4 accessors, `rules.Request`.

- [ ] **Step 1: Write failing tests** (extend the existing proxy test rig): `TestDeniedRequestNeverReachesTheProvider` (provider handler counts hits; assert 0 and `Stats().Denied == 1`), `TestDeniedRequestNeverFetchesTheSecret` (secret source counts calls; assert 0), `TestAllowedRequestStillGetsTheCredential`, `TestBuiltinServiceIsUntouched` (no rules, request forwarded as before), `TestGraphQLDeniedByDefault`, `TestDeniedOverHTTP2` (client forced to h2), `TestBodyIsForwardedIntactAfterEvaluation` (provider receives the exact bytes), `TestOversizeBodyFailsClosedWhenARuleNeedsIt`.
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** the enforcement block at the top of `forward` after the upgrade check.
- [ ] **Step 4:** `go test -race ./internal/broker` — expect PASS.
- [ ] **Step 5: Commit** `feat(broker): enforce forge request rules before any credential is fetched`.

### Task 6: Audit records the rule

**Files:**
- Modify: `internal/ledger/ledger.go` (`Entry`), `cmd/stk/audit.go` (`observer.Observe` and the text view), and their tests

**Interfaces:**
- Produces: `ledger.Entry.Rule string` with JSON tag `rule,omitempty`; `Observe` copies `Record.Rule`; for a denied record `Capability` is `(denied)` and `Policy` is `deny`. `stk audit --json` includes `rule`. The text view shows the rule id for denied rows.
- Consumes: Task 5's `Record.Rule`.

- [ ] **Step 1: Write failing tests**: `TestObserveRecordsTheDenyingRule`, `TestAuditJSONIncludesRule`, `TestAuditNeverContainsTheSecretOnADeniedRequest` (a denied request carrying the placeholder; the ledger file does not contain the real secret, which was never fetched).
- [ ] **Step 2:** run — expect FAIL.
- [ ] **Step 3: Implement** the field and the mapping.
- [ ] **Step 4:** `go test ./...` — expect PASS.
- [ ] **Step 5: Commit** `feat(audit): record which rule denied a request`.

### Task 7: End to end through the real proxy, and docs

**Files:**
- Modify: `e2e/forge_test.go`, `README.md`, `docs/forge-broker-design.md`

- [ ] **Step 1: Write failing e2e tests** (reuse `forgeRig`, extended to take a rules block and to count provider hits): `TestForgeRulesAllowThenDeny` (preset `issues`: `POST /api/v1/repos/o/r/issues` reaches the provider with the substituted credential; `DELETE /api/v1/repos/o/r/issues/1` gets 403 and the provider hit count stays at 1), `TestForgeRulesRefuseTraversalThroughCurl` (`curl --path-as-is` with `..` and `%2e%2e` variants: 403, provider hits unchanged), `TestForgeBodyConditionThroughCurl` (rule forbids `state`: `{"title":"x"}` reaches the provider, `{"state":"closed"}` does not), `TestForgeGraphQLDeniedByDefault`.
- [ ] **Step 2:** `go test ./e2e -run ForgeRules` — expect FAIL until the rig takes rules.
- [ ] **Step 3: Extend the rig and make the tests pass.** Revert-proof: temporarily make `Evaluate` return allowed and confirm the deny tests fail, then restore.
- [ ] **Step 4:** Update the README forge section (presets are now enforced, with an example `rules:` block and the GraphQL note) and set the spec status line.
- [ ] **Step 5:** `go vet ./... && go test ./...` — expect PASS. **Commit** `test(e2e): forge rules deny before anything is sent`.

---

**Not in this slice:** the fixed authenticated listener and `stk env`, `stk install` and isolation reporting, `auth: app` verify, `stk reload` and audit labels, harness probes, CA name constraints, Bitbucket presets, the MCP/daemon `SchemeHeader` guard (add a test that fails if a capability is attached to a `SchemeHeader` entry), and the deferred minors from slice 1.
