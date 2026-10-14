# Phase 4 implementation plan

**Goal:** the five screens, served by the broker to its owner, built from vibekit
so supertoolkit looks like the rest of the suite in whichever vibe the person
chose.

**Mockups:** [vibekit#21](https://forge.superjackfruit.com/SuperJackfruitLabs/vibekit/pulls/21)
— twenty artboards, five screens in four vibes. Approved before this plan.

**Spec:** [design.md](design.md). **Roadmap:** [roadmap.md](roadmap.md).

## Why a UI at all

Four of the five screens are the wrong shape for a terminal. **Policy** is a grid,
and it is the screen where a mistake widens an agent's reach. **Approvals** have
no home at all without it: a terminal confirm only works if you are sitting at
the terminal, and a standalone user has no board gate and no push. **Audit**
needs filtering, not tailing. And **Connect** is already a browser flow, so the
OAuth callback may as well land somewhere useful.

## Global constraints

The thirteen already in force, plus three that make a UI safe to add to a
process that holds credentials:

- **Never the credential plane's listener.** The UI binds its own, and the
  socket the broker serves agents on gains no HTTP route.
- **The UI is just another caller.** It holds no privilege to read secrets,
  because no such privilege exists. It may show that a credential is present,
  its fields, scopes and age — never its value.
- **Bound to the narrowest interface its owner can reach**: loopback on a
  laptop, the private network on a VPS. Started on demand, so the default
  attack surface is unchanged.

---

### Task 1: the UI listener and its one-time token

**Files:** create `internal/webui/server.go`, `server_test.go`

**Produces:** `webui.Serve(ln net.Listener, opts Options) error`, `NewToken()`.

- [ ] Write the failing test: a request without the token is refused; a request
      with it is served; the token is accepted from a query parameter once and
      then from a cookie, as Jupyter does.
- [ ] Assert the token is compared in constant time, so a timing oracle cannot
      recover it.
- [ ] Assert the listener is separate: the credential-plane socket has no HTTP
      handler, and the UI's mux has no route that returns a credential — tested
      by enumerating routes, so adding one later breaks the test.
- [ ] Assert a bind to a non-loopback address is refused unless explicitly
      allowed, so a careless `stk ui` cannot publish itself.
- [ ] Run, implement, run, commit.

### Task 2: the read API

**Files:** create `internal/webui/api.go`, `api_test.go`

**Produces:** `GET /api/status`, `/api/services`, `/api/policy`, `/api/approvals`, `/api/audit`.

- [ ] Write the failing test: each endpoint answers with what its screen needs.
- [ ] **The leak test, across every endpoint and every error path**: no response
      may contain a stored credential. This is the same assertion the MCP layer
      carries, repeated here because this is a second surface.
- [ ] Assert `/api/services` reports the operation and whether a long-lived
      secret reaches the wire, which is the column the mockup exists for.
- [ ] Run, implement, run, commit.

### Task 3: the write API

**Files:** modify `internal/webui/api.go`, `api_test.go`

**Produces:** `POST /api/policy` (set one capability), `POST /api/approvals/{id}`
(allow or refuse), `POST /api/services/{name}/revoke`.

- [ ] Write the failing test: a policy change persists to the config file and
      takes effect; an approval decision resolves exactly once; a revoke removes
      the credential.
- [ ] Assert a write without the token is refused.
- [ ] Assert a policy change cannot promote a capability the catalogue marks
      destructive beyond `approval` — the UI is not a way around the ceiling.
- [ ] Run, implement, run, commit.

### Task 4: the web app

**Files:** create `web/` (SvelteKit, adapter-static), vendor vibekit as a packed
tarball the way superpipeline does.

- [ ] Five routes matching the mockups, built from vibekit components.
- [ ] The vibe and theme follow the person's choice, with Studio as the default
      and all four available — a vibe is the person's, not the product's.
- [ ] `pnpm build` produces static output; no server-side rendering, because the
      Go binary serves it.
- [ ] Commit.

### Task 5: embed and serve

**Files:** modify `internal/webui/server.go`, `cmd/stk/ui.go`

- [ ] `go:embed` the built assets, so the single binary keeps its promise.
- [ ] `stk ui` starts the listener, prints a URL carrying a one-time token, and
      opens it.
- [ ] A build without the web assets still compiles and says so, so `go build`
      works for someone who has not run pnpm.
- [ ] Commit.

### Task 6: end to end

**Files:** create `e2e/webui_test.go`

- [ ] Drive the API as the UI does: read status, change one policy, approve a
      pending effect, and confirm the effect then happened exactly once.
- [ ] Assert no credential appears anywhere in any response.
- [ ] Commit.

## Out of scope for Phase 4

A hosted, multi-tenant dashboard holding other people's credentials. Remote
access beyond binding to a private network. Live updates — the screens poll.
Editing profiles, which stays a file-level concern this phase.
