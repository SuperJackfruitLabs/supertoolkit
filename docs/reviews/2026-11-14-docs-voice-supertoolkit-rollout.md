# Claims ledger — SuperToolkit docs voice rollout

Status: draft-stage evidence for the 17-page voice rollout.

## Immutable revisions and scope

- PR base: `28f816c62a0e328bc4718e7d0ebf000329916764` (includes the shared docs theme from SuperToolkit PR #50).
- Voice guide: `SuperJackfruitLabs/sketchbook@29690e4397467bcf92ea7ef7e88b4e89cffba88f`, `ideas/2026-11-14-docs-voice-guide-v1/README.md`.
- Reference rollout: `SuperJackfruitLabs/superdispatch`, merged PR #32. Its page-kind treatment and claims-ledger shape were used as the standard, not as a source of wording.
- Scope: all 17 published pages under `docs-site/src/content/docs/`, the generated source pages `docs/limitations.md` and `docs/measurements.md`, and this ledger.
- Product code, configuration, fixtures, deployment files, site setup, the Bento home layout, and the docs-theme integration are unchanged.
- Product evidence below is pinned to the PR base. Public release evidence is pinned to the v0.0.9 release URL. Private deployment state is not inferred from repository configuration.

## Page-by-page voice review

Every page passes narrator, exactness, vocabulary/privacy, originality, and claims. Step payoffs and running-gag rows are applied according to page kind.

| Page | Kind | Narrator and momentum | Step payoffs | Running gag | Exact and safety material |
| --- | --- | --- | --- | --- | --- |
| `index.mdx` | home/quick start | pass — the Bento flow and lower prose guide `you` from problem to boundary | pass — the quick-start note and broker flow name the observable policy, provider, and audit results | not applicable — the home uses one-off wit, not a tutorial gag | pass — command, placeholder, denial text, flow labels, version, and links remain literal |
| `what-it-is.md` | concept | pass — a shared narrator defines the invariant and follows one request | not applicable | not applicable | pass — invariant, operation table, placeholder, and policy boundary remain literal |
| `install.md` | task | pass — `we` install one binary and prove the path before trust | pass — installer, source build, init, probe, and revoke each end in a concrete result | not applicable | pass — commands, variables, output, platform warning, and recovery stay literal |
| `connect.md` | task | pass — the reader is carried through four credential paths in preference order | pass — add/connect, paste, browser, device, notifications, hand-over, verify, and revoke each state the resulting state or proof | not applicable | pass — commands, YAML, user/device-code warning, and revocation caveat remain literal |
| `use/from-an-agent.md` | task | pass — the narrator moves from the four-tool surface to a brokered child and fronted server | pass — install, run, probe, and server declaration each name the visible result | not applicable | pass — tool names, pending JSON, commands, and YAML are unchanged |
| `use/policy.md` | concept/task | pass — direct guidance frames the exact policy table | pass — profile and doctor actions end with the subset or report they produce | not applicable | pass — policy words, YAML, and fail-safe rules remain literal |
| `use/services.md` | reference/task | pass — warm prose explains why each exact row exists | pass — add, connect/verify, app connect, and `auth: none` declarations state the resulting boundary | not applicable | pass — 13-row catalogue, forge schema, presets, rules, limits, and examples stay literal |
| `use/audit.md` | reference/task | pass — the reader starts from the question the ledger answers | pass — audit commands end with the connection between effect, policy, and response | not applicable | pass — output, 8 MB rotation, tunnel distinctions, and exclusions stay literal |
| `use/approvals.md` | task/concept | pass — one promise carries the reader from pending effect to exact outcome | pass — local and hosted setup actions state where the request appears and who can decide | not applicable | pass — commands, JSON, expiry, digest checks, hosted sequence, warnings, and recovery remain literal |
| `use/publish.md` | task | pass — `we` follow exact bytes from submission through delivery or fence | pass — submit, perform, and recover each finish with a durable observable state | not applicable | pass — commands, exit codes, field table, URL, failure states, and retry fence remain literal |
| `use/mcp-serve.md` | task/reference | pass — a shared narrator keeps familiar tool names while narrowing network access | pass — serve, egress, hosts, network mode, and local-command setup each state the resulting boundary | not applicable | pass — YAML, commands, method names, address classes, modes, warnings, and rule ids stay literal |
| `run/serve.md` | task/reference | pass — the reader moves from one daemon to uid separation, install, env, and reload | pass — serve, install, env, and reload actions each close with an observable system state | not applicable | pass — flags, methods, modes, paths, commands, and variables remain literal |
| `security.md` | concept | pass — a direct narrator derives the model from the invariant and names its limits | not applicable | not applicable | pass — invariant, storage table, threats, failure rules, and disclosure route remain literal |
| `limitations.md` | concept/reference | pass — the opening brings the edges into daylight without softening them | pass — the probe action ends with a hard go/no-go result | not applicable | pass — generated-source notice, measurements, statuses, commands, warnings, deployment caveat, and network-mode limits stay literal |
| `measurements.md` | reference | pass — the reader is invited to reproduce rather than trust a rumour | pass — the reproduction command states the three measurements it reruns | not applicable | pass — machine, sizes, hashes, status, sample count, and latency table remain literal |
| `reference/cli.md` | reference | pass — short framing helps the reader choose the exact command group | not applicable | not applicable | pass — every command, flag, alias, exit behavior, and internal entry point stays literal |
| `reference/web-ui.md` | reference/task | pass — the reader starts from the inspection job and ends at the authority boundary | pass — `stk ui` closes with the cookie/redirect result | not applicable | pass — commands, bind address, cookie attributes, eight routes, bodies, and build command remain literal |

Candor passes across the set: proxy bypass, certificate refusal, uid separation, Linux store-key limits, local-proxy authentication, hosted-approval failure, outcome fencing, network-mode limits, GraphQL and non-HTTP exclusions, mTLS failure, audit rotation, and staging evidence limits remain explicit. No private host, person, agent, team, credential, customer, or private-message name was added. Public product names, loopback and documentation addresses, synthetic ids, generic OS identities, and placeholder values are the only examples.

## Claims checked at the PR base

Each row covers every material command, flag, route, setting, default, field, enum, status, limit, version, and behavioral claim on that page. The repository's docs-claims suite performs the exhaustive surface comparisons described below; this table records the implementation and test evidence used for the page-level behavioral review.

| Page | Material checked | Base evidence |
| --- | --- | --- |
| `index.mdx` | placeholder flow; proxy/CA and cleared `NO_PROXY`; forge deny precedence and 403; six operations; read/write defaults; audit fingerprint; no telemetry/update path; bypass probe; Go requirement; three-test quick start; current release | `internal/broker/childenv.go:20-67`; `internal/broker/proxy.go:1-12,194-255,579-673`; `internal/catalog/catalog.go:20-143`; `internal/policy/config.go:22-59,158-175`; `internal/audit/audit.go:22-100,203-212`; `internal/doctor/probe.go:1-467`; `e2e/e2e_test.go:139-199`; `e2e/forge_test.go:212-357`; `go.mod:1-5`; public release `https://github.com/SuperJackfruitLabs/supertoolkit/releases/tag/v0.0.9` (published 2026-11-09) |
| `what-it-is.md` | invariant; Unix/proxy/placeholder flow; six operations and wire material; doctor derivation; `auth: none`; configured-host interception and egress exception | `AGENTS.md:5-13`; `internal/session/run.go:37-195`; `internal/broker/childenv.go:20-84`; `internal/catalog/catalog.go:51-143`; `internal/credential/inject.go:1-99`; `internal/doctor/doctor.go:1-251`; `internal/policy/config.go:238-257`; `internal/broker/proxy.go:194-255` |
| `install.md` | platforms/architectures; installer variables, checksum refusal, destinations, and version output; Go requirement; source build; init artifacts/key source/CA behavior; doctor probe statuses; revoke behavior | `install.sh:11-108`; `go.mod:1-5`; `internal/setup/setup.go:17-63`; `internal/credential/key.go:1-117`; `internal/doctor/doctor.go:98-123`; `internal/doctor/probe.go:1-467`; `internal/credcmd/revoke.go:1-153` |
| `connect.md` | stdin-only connect; browser PKCE, loopback and paired endpoint rules; device grant, output and notification; refresh-token persistence; hand-over sealing; verify fields/exit; local/provider revoke distinction | `internal/setup/setup.go:104-227`; `internal/setup/headless.go:1-615`; `internal/oauth2flow/flow.go`; `internal/deviceflow/flow.go:1-226`; `internal/notify/notify.go`; `internal/credential/acquire.go:1-346`; `internal/handover/handover.go:1-138`; `internal/credcmd/verify.go:1-141`; `internal/credcmd/revoke.go:1-153` |
| `use/from-an-agent.md` | install targets; exactly four MCP tools; pending response behavior; child proxy/CA/placeholders and cleared `NO_PROXY`; probe; fronted-server keys and policy | `internal/mcpcmd/mcpcmd.go`; `internal/mcp/server.go:30-38,218-267,340-519`; `internal/broker/childenv.go:20-84`; `internal/doctor/probe.go:1-467`; `internal/policy/servers.go:1-177`; `internal/mcp/fronted.go:1-174` |
| `use/policy.md` | file shape; three action values and zero-value approval; catalogue defaults; unknown-effect behavior; profile narrowing and unknown-profile error; doctor profile report | `internal/policy/config.go:22-59,158-175,260-340`; `internal/catalog/catalog.go:20-31`; `internal/policy/profile.go:1-129`; `internal/doctor/doctor.go:1-251` |
| `use/services.md` | 13 built-ins, host/operation/env placement; two native-only services and scopes; provider-specific behavior; GraphQL/non-HTTP boundary; forge fields/providers/presets/rules/deny order/path validation/app auth; three labels/128-byte limit; `auth: none` | `internal/catalog/catalog.go:246-943`; `internal/catalog/forge.go:1-181`; `internal/policy/config.go:62-175,260-707`; `internal/rules/rules.go`; `internal/rules/path.go`; `internal/rules/presets.go`; `internal/credential/inject.go:1-99`; exact service count held by `internal/docsclaims/docs_test.go:229-305` |
| `use/audit.md` | command flags/default limit and fields; fingerprint/operation; shared ledger; 8 MB/one-generation rotation; malformed-line behavior; tunnel/egress recording boundary | `internal/audit/audit.go:22-212`; `internal/ledger/ledger.go:26-177`; `internal/broker/proxy.go:1-12`; `internal/broker/egress.go:1-229`; `internal/audit/audit_test.go` |
| `use/approvals.md` | command aliases; shared decide-once queue; operator-uid boundary; performed outcome; exact-request preview/digest; 30-minute expiry; hosted service requirements/fields/polling/decision checks/fail-closed behavior; same-user limit | `internal/approval/queue.go:1-250,327-681`; `internal/approval/digest.go:1-113`; `internal/approval/hosted.go:1-412`; `internal/controlplane/service.go`; `internal/daemon/daemon.go:35-83`; `internal/serve/serve.go:1-341`; `internal/approval/hosted_test.go`; `internal/controlplane/decide_test.go` |
| `use/publish.md` | three commands; exit 3; three services; exact submission fields and allowed method/URL; identifier/RFC3339/base64 checks; gate checks; read-back/card record; local-decision refusal; unknown-outcome fence and recovery states | `internal/publishcmd/command.go:23-195`; `internal/approval/publisher.go:1-993`; `internal/approval/queue.go:46-103`; `internal/catalog/catalog.go:297-380`; `internal/publishcmd/command_test.go`; `internal/approval/publisher_test.go` |
| `use/mcp-serve.md` | command flags/daemon requirement; MCP methods; visibility/decision/rule ids; approval refusal; child identity; five control methods; egress schema/classes/order/DNS/redirect/method/port behavior; host allowlist; three network modes; local-command socket isolation | `internal/mcpcmd/mcpserve.go:1-248`; `internal/mcpserve/serve.go:1-189`; `internal/daemon/daemon.go:35-83`; `internal/policy/config.go:177-217,292-377`; `internal/egress/egress.go:1-377`; `internal/broker/egress.go:1-229`; `internal/netjail/netjail_linux.go:1-140`; `internal/netjail/watch_linux.go:1-168`; `internal/broker/localcommands.go:10-71`; corresponding package tests |
| `run/serve.md` | serve flags/default socket; caller/operator authorization and methods; install requirements/defaults/modes/idempotence/unit; multiple-instance constraints; fixed proxy key/407 and env fields; reload/SIGHUP behavior; state variables and child scrubbing | `internal/serve/serve.go:1-341`; `internal/daemon/daemon.go:35-83`; `internal/install/install.go:1-390`; `internal/session/run.go:37-195`; `internal/proxyenv/env.go:1-159`; `internal/livepolicy/reload.go:1-257`; `internal/broker/proxy.go:194-255`; `internal/broker/childenv.go:20-84`; package tests |
| `security.md` | no credential-return surface; AES-256-GCM/Argon2id/padding/key sources; memory/wire/placeholder boundaries; sealed token cache and refresh ownership; stated threat/non-threat boundary; fail-closed defaults and disclosure route | `AGENTS.md:5-13`; `internal/credential/store.go:1-288`; `internal/credential/key.go:1-117`; `internal/credential/tokencache.go:13-167`; `internal/credential/acquire.go:1-346`; `internal/catalog/catalog.go:120-143`; `internal/policy/config.go:22-59,158-175`; `SECURITY.md:1-78` |
| `limitations.md` | bypass/probe and statuses; macOS Go trust; measured mTLS/body/latency results; upgrade refusal; non-HTTP/GraphQL boundaries; out-of-scope list; key-source warning; proxy/audit/OAuth/hand-over/refresh limits; refresh ownership; network modes/50 ms poll/Go loopback behavior; egress/tool-call limits; intended staging configuration | `internal/doctor/probe.go:1-467`; `internal/setup/setup.go:52-62`; `e2e/measure_test.go:7,141-301`; `internal/broker/proxy.go:1-813`; `internal/catalog/catalog_test.go`; `internal/credential/key.go:1-117`; `internal/ledger/ledger.go:26-177`; `internal/credential/acquire_test.go:226-306`; `internal/netjail/watch_linux.go:1-168`; `internal/broker/egress.go:1-229`; `deploy/staging/supertoolkit.yaml:1-71` |
| `measurements.md` | reproduction command, recorded machine/date, exact sizes/hashes/substitution, mTLS setup/502 behavior, sample/warm-up/percentiles and regression assertion | executable measurement definitions in `e2e/measure_test.go:1-329`; recorded results in `docs/measurements.md:1-96` at the base |
| `reference/cli.md` | every command, subcommand, flag, alias, exit behavior, doctor isolation enum, and three internal entry points | dispatch in `cmd/stk/main.go:1-161`; mechanically enumerated by `internal/docsclaims/surface_test.go:224-424`; exact docs comparison in `internal/docsclaims/docs_test.go:1-228`; command-package parsers and tests |
| `reference/web-ui.md` | command flags/default bind; five screens; separate listener; one-time token/cookie/redirect/401; credential exclusion; hosted-decision refusal; all eight routes and bodies; 200-record audit result; assetless fallback/build command | `internal/uicmd/ui.go:1-128`; `internal/webui/server.go:1-164`; `internal/webui/api.go`; route enumeration in `internal/docsclaims/surface_test.go:483-540`; web UI and hosted-decision tests |

## Corrections and evidence-bound changes

No behavioral fact, command, value, default, field, enum, limit, or deployment statement changed in this rollout. The source review found one repeated editorial defect: prose used the lowercase repository/binary spelling where the product name required official casing. Each affected public page was corrected explicitly rather than silently:

| Page | Old material | New material | Evidence |
| --- | --- | --- | --- |
| `index.mdx` | prose said “supertoolkit holds the credential” | prose says “SuperToolkit holds the credential” | Voice guide rule 8; product title in the same page and `AGENTS.md:1` |
| `what-it-is.md` | title said “What supertoolkit is” | title says “What SuperToolkit is” | Voice guide rule 8; `AGENTS.md:1` |
| `install.md` | description/opening said “Install supertoolkit” / “supertoolkit is” | description/opening use “SuperToolkit” | Voice guide rule 8; `AGENTS.md:1` |
| `connect.md` | prose said “supertoolkit ships no client id” | prose says “SuperToolkit ships no client id” | Voice guide rule 8; behavior remains backed by `internal/catalog/catalog.go:145-186` |
| `security.md` | description said “What supertoolkit protects against” | description uses “SuperToolkit” | Voice guide rule 8; `AGENTS.md:1` |
| `limitations.md` | generated body/source said “What supertoolkit does not do” and “supertoolkit ships none” | body/source use “SuperToolkit” | Voice guide rule 8; `AGENTS.md:1`; generated copy remains synchronized by `scripts/sync-docs.sh` |

Lowercase text remains only where it is exact material: the repository/path/domain name, `supertoolkit.yaml`, generated binary messages, and the documented denial string.

## Deployment claims that remain UNVERIFIED

- **UNVERIFIED:** `limitations.md` says the staging deployment currently runs the broker as user `stk` for a separate-uid Salaam agent, fronts `git-public`, uses `egress: public-only`, and runs `fetch` as `network: watched`. `deploy/staging/supertoolkit.yaml:1-71` and `deploy/staging/deploy.sh:1-233` prove the intended repository configuration, not the live private infrastructure. A request for pinned private-estate/provisioning evidence was posted on card `card_39154d0373974490` on 2026-11-14. The claim is not treated as false because the owning infrastructure is outside this repository.

## Mechanical claims ratchet

No new product fact was introduced by the voice edits, so no new one-off matcher was added. The existing code-derived ratchet already covers the mechanically checkable public surface in both directions:

- `internal/docsclaims/surface_test.go` parses every `stk` command and subcommand, flag, environment variable, `supertoolkit.yaml` key, web route, control-socket method, MCP tool, catalogue service, and credential-operation name from code/registries.
- `internal/docsclaims/docs_test.go` requires each surface item to appear in the published pages unless it is in the shrinking baseline; it also checks stated counts for operations, services, and MCP tools against the registries.
- `scripts/sync-docs.sh --check` requires the published limitations and measurements pages to match their repository sources exactly.

## Exact-material inventory

- `index.mdx`: frontmatter, Bento properties, quick-start command/note, agent prompt, flow labels/items, placeholder, denial text, card facts, version/date, links, and component boundaries.
- `what-it-is.md`: invariant, placeholder, six-operation table, `auth: none`, and egress link.
- `install.md`: commands, installer variables/defaults, Go/platform names, paths, probe output/statuses, and warnings.
- `connect.md`: commands, OAuth/device YAML, URLs, code output, notification YAML, hand-over commands, warnings, and flags.
- `use/`: all commands, tool/method/rule names, JSON, YAML, tables, ids, digests, statuses, exit values, routes, limits, modes, address ranges, warnings, and recovery sequences.
- `run/serve.md`: commands, flags, uid/mode/path/port defaults, control methods, systemd details, environment-variable table, warnings, and recovery behavior.
- `security.md`: invariant, credential-location table, failure rules, and disclosure links.
- `limitations.md` and `measurements.md`: generation notice, commands, outputs, statuses, machine/date, tables, measured values, limits, warnings, and deployment/network facts.
- `reference/`: every command, flag, alias, route, body, count, address, cookie attribute, and build command.

No humor was added to any exact region.

## Real checks

To be filled with the exact docs-only commands and outputs after the final content and ledger are committed.
