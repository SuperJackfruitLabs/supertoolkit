# Phase 3 implementation plan

**Goal:** an MCP server **we did not write** runs as a child with no credential
in its environment, and an agent uses its tools through our four meta-tools.

**Why this is the phase that matters for breadth.** There are 300+ Apache-2.0 MCP
servers already. Writing our own for each service would rebuild the commoditised
half of the problem and leave the actual one — the credential in the config file —
unsolved. After this phase, adding a service is configuration.

**Spec:** [design.md](design.md). **Roadmap:** [roadmap.md](roadmap.md).

## Global constraints

The eleven already in force, plus two:

- **A fronted server never receives a credential.** It is started with a
  placeholder in the variable it expects and `HTTPS_PROXY` pointing at the
  broker. If the server is compromised, what it holds is worthless off this
  machine.
- **An unannotated third-party tool defaults to `approval`.** We did not write
  these tools and cannot know what they do. MCP's own `readOnlyHint` may promote
  one to `agent`; absence of a hint is not evidence of safety.

## The shape

A fronted server becomes a **category** whose actions are its tools, so the four
meta-tools cover native services and fronted servers identically — and the
child's fifty tools never reach the agent's context, because discovery is still
progressive.

```yaml
servers:
  slack:
    command: npx
    args: ["-y", "@modelcontextprotocol/server-slack"]
    host: slack.com                  # the broker intercepts this
    env_var: SLACK_BOT_TOKEN         # where the placeholder goes
    capabilities:
      slack_post_message: approval   # optional override
```

---

### Task 1: the server config section

**Files:** modify `internal/policy/config.go`; create `internal/policy/servers_test.go`

**Produces:** `Config.Servers() []string`, `Config.Server(name) (*Server, bool)`
with `Command`, `Args`, `Host`, `EnvVar`, and `Policy(tool, hint) Action`.

- [ ] Write the failing test: a server block parses; `Host` joins
      `InterceptHosts()` so the broker terminates it; a server with no
      `command` is refused at load.
- [ ] Assert a name collision between a `services` entry and a `servers` entry
      is refused, since both become categories and one would shadow the other.
- [ ] Assert `Policy` defaults to `approval` for an unannotated tool, honours an
      explicit override, and only promotes to `agent` on a read-only hint.
- [ ] Revert-proof the default: make unannotated tools `agent` and the test must
      go red.
- [ ] Run, implement, run, commit.

### Task 2: the child host

**Files:** create `internal/mcphost/host.go`, `host_test.go`

**Produces:** `Host.Start(ctx, spec) error`, `Host.ListTools(ctx) ([]Tool, error)`,
`Host.CallTool(ctx, name, args) (Result, error)`, `Host.Close() error`.

- [ ] Write the failing test against a **fixture MCP server** compiled from this
      repo's testdata, which stands in for a third-party one: `initialize` and
      `tools/list` round-trip, and `tools/call` returns the child's answer.
- [ ] Assert the child's environment contains the placeholder and **not** the
      credential — read from `/proc`-independent evidence by having the fixture
      report its own environment back.
- [ ] Assert a child that exits is reported as failed rather than hanging a
      caller, and that `Close` reaps it.
- [ ] Assert a child that writes garbage to stdout does not wedge the host.
- [ ] Run, implement, run, commit.

### Task 3: tool discovery and caching

**Files:** modify `internal/mcphost/host.go`; create `internal/mcphost/cache_test.go`

- [ ] Write the failing test: `tools/list` is called once across many
      discoveries, because a child's list does not change while it runs.
- [ ] Assert a tool's `readOnlyHint` becomes `agent` and everything else stays
      `approval`.
- [ ] Assert a child restarted after a crash re-lists rather than serving a
      stale list.
- [ ] Run, implement, run, commit.

### Task 4: fronted servers in the four meta-tools

**Files:** modify `internal/mcp/server.go`, `server_test.go`

- [ ] `discover_server_categories` lists native services and fronted servers
      together, marked so an agent knows which is which.
- [ ] `get_category_actions` on a fronted server lists its tools with their
      resolved policy; a profile still narrows.
- [ ] `execute_action` on a fronted server calls through to the child, enforcing
      policy at the same single point.
- [ ] Assert `tools/list` is **still exactly four** with servers configured —
      this is the test that stops fifty child tools reaching the context.
- [ ] Assert no child response can leak the credential, including on error.
- [ ] Run, implement, run, commit.

### Task 5: the credential-free environment

**Files:** modify `cmd/stk/run.go` (extract), create `internal/mcphost/env.go`

- [ ] Extract the environment construction `stk run` already uses so the child
      host and the CLI share one implementation: placeholder in, proxy set,
      `NODE_USE_ENV_PROXY` on, `NO_PROXY` cleared.
- [ ] Assert the built environment contains no credential and does contain the
      placeholder, for a fronted server.
- [ ] Commit.

### Task 6: end to end, through a server we did not write

**Files:** create `e2e/fronted_test.go`, `testdata/fakeserver/main.go`

- [ ] A fixture MCP server that makes an authenticated HTTP call to a provider
      and returns what the provider said. It reads its token from an
      environment variable, exactly as a real third-party server does, and is
      given only the placeholder.
- [ ] Drive it through the four meta-tools and assert the provider received the
      **real** credential while the child's environment held only the
      placeholder.
- [ ] Assert a write on a fronted server still queues for approval and performs
      nothing until decided.
- [ ] Commit.

## Out of scope for Phase 3

Pinning fronted servers by checksum — it matters when we distribute them, which
is Phase 6. Remote MCP servers over HTTP rather than stdio. Resources and
prompts: tools are what an agent calls. Hot-reloading a changed server config.
