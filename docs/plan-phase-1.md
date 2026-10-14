# Phase 1 implementation plan

**Goal:** an agent — Claude Code, Cursor, anything that speaks MCP — can use
brokered tools through **four** meta-tools, with policy enforced in one place,
and still never holds a credential.

**Why this next.** Phase 0 serves CLIs through `stk run`. Agents reach tools over
MCP, so without this supertoolkit is a CLI wrapper rather than a toolkit for
agents. Everything else on the roadmap — more operations, more services — is
worth less until an agent can call anything at all.

**Spec:** [design.md](design.md). **Preceded by:** [plan-phase-0.md](plan-phase-0.md).

## Global constraints

Phase 0's six still hold. Three more:

- **Four meta-tools, never N.** Ten services at ten actions each would be a
  hundred schemas in every agent's context on every turn. `tools/list` returns
  four entries and nothing else, forever.
- **One enforcement point.** Policy is checked inside `execute_action` and
  nowhere else, so there is a single place to audit and no second path to forget.
- **A profile narrows and never widens.** Discovery answers from the caller's
  profile, so a capability the profile lacks is *absent* rather than refused —
  the agent is never told it exists.

## Decisions this phase makes

**`execute_action` uses the native path.** The broker makes the HTTP call itself,
from a request shape declared in the catalogue. Fronting third-party MCP servers
reuses the Phase 0 proxy instead and is Phase 2 — it needs no new protocol work,
only configuration, so it is not what this phase should spend itself on.

**Approval is queued, not prompted.** An MCP server's stdio is the protocol
channel, so it cannot ask a question there. A capability at `approval` returns
`pending` with an id; `stk approvals` lists and decides from another terminal.
Fail closed: with nothing to approve through, the effect does not happen.

---

### Task 1: request shapes in the catalogue

**Files:** modify `internal/catalog/catalog.go`, create `internal/catalog/catalog_test.go`

**Produces:** `Capability` gains `Method`, `Path`, `Summary` and `Params []Param`;
`Entry.Request(capability, args) (*http.Request, error)`.

- [ ] Write the failing test: `github`/`get_user` builds `GET https://api.github.com/user`;
      a path parameter is substituted; a missing required parameter is an error;
      an unknown capability is an error.
- [ ] Add the injection-safety case: a parameter containing `../` or a newline
      must be rejected rather than interpolated into the path.
- [ ] Run, implement, run, commit.

### Task 2: the daemon on a Unix socket

**Files:** create `internal/daemon/daemon.go`, `internal/daemon/daemon_test.go`

**Produces:** `daemon.Serve(sock string, h Handler) error`, `daemon.Dial(sock)`,
and `PeerUID(conn) (int, error)`.

- [ ] Write the failing test: the socket is created with mode `0600`; a request
      over it round-trips; `PeerUID` reports the connecting process's uid.
- [ ] Add the refusal test: the daemon exposes no method that returns a
      credential — asserted by enumerating its method table, so adding one
      later breaks the test.
- [ ] Add the stale-socket test: a leftover socket file from a dead process is
      replaced rather than causing a start failure.
- [ ] Run, implement, run, commit.

### Task 3: profiles

**Files:** create `internal/policy/profile.go`, `internal/policy/profile_test.go`

**Produces:** `Config.Profile(name) (*Profile, bool)`, `Profile.Visible(service, capability) bool`,
`Profile.Resolve(service, capability) Action`.

- [ ] Write the failing test: a profile listing `x: [read_timeline]` makes
      `post` invisible; a profile listing `post` gets it at the service's
      action — `approval` — and **cannot** promote it to `agent`; a profile
      naming a denied capability gets nothing.
- [ ] Add the default-profile test: with no profiles declared, every caller sees
      everything the service policy allows.
- [ ] Revert-proof: remove the ceiling and the promotion test must go red.
- [ ] Run, implement, run, commit.

### Task 4: the four meta-tools

**Files:** create `internal/mcp/server.go`, `internal/mcp/server_test.go`

**Produces:** a JSON-RPC 2.0 server over stdio with `initialize`, `tools/list`
and `tools/call`.

- [ ] Write the failing test: `tools/list` returns **exactly four** tools, by
      name. This is the test that stops the catalogue leaking into context.
- [ ] `discover_server_categories` lists only services visible to the profile.
- [ ] `get_category_actions` omits capabilities the profile cannot see, and
      `get_action_details` refuses one it cannot see rather than describing it.
- [ ] `execute_action` on an `agent` capability performs the call; on `approval`
      returns `pending` with an id and performs nothing; on `deny` refuses.
- [ ] Add the leak test: no response from any of the four may contain the
      credential, including error paths.
- [ ] Run, implement, run, commit.

### Task 5: the approval queue

**Files:** create `internal/approval/queue.go`, `internal/approval/queue_test.go`,
modify `cmd/stk`

**Produces:** `queue.Submit(req) (id string)`, `queue.List()`, `queue.Decide(id, allow bool, who string)`,
`queue.Await(ctx, id) (Decision, error)`; `stk approvals` and `stk approvals allow|refuse <id>`.

- [ ] Write the failing test: a submitted effect is pending; `Decide` resolves
      it once; a second `Decide` on the same id is an error rather than a second
      effect.
- [ ] Add the expiry test: an undecided effect expires and is reported as
      expired, never as approved.
- [ ] Add the fail-closed test: `Await` on an expired or refused id must not
      return an approval.
- [ ] Run, implement, run, commit.

### Task 6: wiring, and the keychain

**Files:** modify `cmd/stk/*`, create `internal/credential/keychain_darwin.go`
and `keychain_other.go`

- [ ] `stk serve` runs the daemon, the broker and the approval queue together.
- [ ] `stk mcp [--profile p]` speaks MCP on stdio and talks to the daemon.
- [ ] `stk mcp install <host>` prints or writes the client config, containing a
      socket path and **no secret**.
- [ ] Move the store key to the OS keychain where one exists, closing the
      warning `stk doctor` currently prints. Keep the file fallback, and keep
      doctor honest about which is in use.
- [ ] Extend `doctor`: daemon reachable, socket mode, profile count, and that
      `tools/list` really returns four.
- [ ] Commit.

### Task 7: end to end through MCP

**Files:** create `e2e/mcp_test.go`

- [ ] Drive the MCP server as an agent would: `initialize`, `tools/list`,
      `discover_server_categories`, `get_category_actions`, `execute_action`,
      and assert the provider received the real credential.
- [ ] Assert the `approval` path performs nothing until decided, and that the
      effect happens exactly once after approval.
- [ ] Assert a restricted profile cannot see, describe, or execute a capability
      outside it.
- [ ] Commit.

## Out of scope for Phase 1

Sign, mint and acquire — Phase 2, with the AWS and GitHub App shapes. Fronting
third-party MCP servers. The web interface. Device grant. Connectors as separate
binaries. Non-HTTP protocols. Inbound webhooks.
