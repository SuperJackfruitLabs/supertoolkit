# Approvals hosted on SuperPipeline, operator-only local decisions

Charter decision `2026-11-08-waiting-cards-and-broker-approvals-reach-chat`, decisions 3, 5, 6
and 7 (SuperToolkit's half). The SuperPipeline side is its `POST/GET
/v1/boards/:boardId/approval-requests`.

## Who may decide

**All of this holds only in station mode**: agents run under their own uids and reach the broker
through the daemon socket (`stk install`). Standalone `stk mcp` runs as the agent's uid and owns the
state directory and store, so an agent can write a decision file, delete a `.hosted` marker or run
`stk ui` itself; `stk serve` with no `--allow-uid` makes its own uid an operator (and warns at
start), so an agent sharing that uid decides its own writes. Neither is a boundary.

**Locally, only an operator uid** (decision 6). The daemon socket refuses `approvals.decide` to
any uid that is not an operator, before any handler runs. Agent uids (`--allow-uid`, written by
`stk install --agent-uid`) keep every other method: discovery, `execute_action`, `approvals.list`,
`status`, `reload`.

| Method | Who |
|---|---|
| `approvals.decide` | operator uids only |
| `discover_server_categories`, `get_category_actions`, `get_action_details`, `execute_action`, `approvals.list`, `status` | agent and operator uids |
| `reload` | agent and operator uids: it applies the policy file the operator wrote and cannot change it, and AgentPod's node agent calls it as the agents' uid |
| `mcp.*` (the `stk mcp serve` gate) | agent and operator uids: they evaluate policy, they do not change it |

Operator uids are `stk serve --operator-uid N` (repeatable; `stk install --operator-uid N` writes
it into the unit). Without the flag they are **root and the uid the daemon runs as**, leaving out
either one if it is also an agent uid; on a station install that means `sudo stk approvals allow
<id>` or `sudo -u stk stk approvals allow <id>`. A uid named as both an agent and an operator is
refused at startup and by `stk install`. On a laptop with no `--allow-uid`, the daemon's owner is
the operator, as before: an agent running as that same user is the documented limit.

**The recorded decider is never the caller's claim.** The socket records the peer's
kernel-reported uid as `name (uid N)` and ignores any `who` in the params; `stk approvals` sends
none. `stk ui` records its own process identity (`name (uid N) via stk ui`): it had to open the
sealed store to run. A hosted approval records SuperPipeline's decider (`superpipeline: <label>
(<principalId>)`).

**On a host with an approvals board, nobody decides locally.** A hosted effect has a `.hosted`
marker beside it, written before the request record exists, and `DecideAndPerform` and `Decide`
both refuse it, for operators too. While the policy names a board, the socket and `stk ui` also
refuse every local decision on any effect, including one queued before the reload that added the
board (it has no marker): it waits and expires.

## The request digest

Every approval binds the exact request it would send, computed at submit and stored on the effect
as `request_digest`:

```
"sha256:" + hex(SHA-256(
  LP("schema", "stk-capability/v1")
  LP("service", service)      LP("capability", capability)   LP("profile", profile)
  LP("method", method)        LP("url", url)                 LP("body", body bytes)
  u64(number of arguments)
  LP("arg:" + name, value)    for each argument, in byte order of name
))
LP(label, value) = u64(len(label)) ‖ label ‖ u64(len(value)) ‖ value      (u64 big-endian)
```

`method`, `url` and `body` are the request the catalogue builds from the arguments. A fronted MCP
server's tool call has none: its method is `MCP` and its URL `mcp://<server>/<tool>`.

Before performing an approved effect, whoever performs it (a local operator's decision, the
hosted resolver, or an agent's waiting session performing an approval nobody else performed)
rebuilds the request from the stored effect and recomputes the digest. A
mismatch, or an effect with no digest (submitted by an older stk), is refused: nothing is sent and
the outcome is recorded as `refused` with both digests. A policy reload or catalogue change that
alters the target shows here, as does an edited queue record.

## Hosting

With `superpipeline.approvals_board` set (policy load refuses it unless both
`superpipeline-approvals-write` and `superpipeline-approvals-read` are declared), `execute_action`
at `approval`, on a catalogue capability or a fronted MCP server's tool:

1. Submits the effect with the `.hosted` marker (board id) written first.
2. Creates the approval request with the write credential (`approval-requests:write`), straight away, with a
   15-second budget:
   - `requestId` and `subject.id` = the effect id; `subject.digest` = the request digest;
     `subject.expires_at` = the effect's expiry (30 minutes, RFC 3339 UTC); `revision: 1`;
     `schema: stk-capability/v1`.
   - `question`: `Allow <requester> on <station> to <service>/<capability>: <summary>?`, cut to
     1000.
   - `preview`: Service, Capability, Target (method and URL, or `mcp://<server>/<tool>`), Station (host name), Requested by
     (the kernel-reported requester), Profile, Expires, Request digest, then each argument in full,
     one text block each. Blocks are cut to SuperPipeline's bounds (text 4000, field 200, 20
     blocks, counted in UTF-16 units as SuperPipeline counts them); anything cut, or arguments
     that do not fit, set `preview_complete: false`, so a client withholds approval until the
     person opens the full request.
   - The agent is answered `pending` with `decided_on: superpipeline` and the approval request id.
3. A watcher (in `stk serve`, and in `stk mcp` for its own session) reads each pending hosted
   effect back with the read credential (`approval-requests:read`) every 3 seconds; an effect whose create
   or read fails backs off, doubling to one minute.
4. On `approved`, stk checks again before acting (decision 5): the read-back is for the request it
   created, `option` is `allow_once`, `subject.id` is the effect id, `subject.digest` equals the
   stored digest, the effect is unexpired, and a decider is named. Any failure is recorded as
   refused (`supertoolkit: <reason>`) and nothing is sent. Otherwise it claims the decision (a file
   created with `O_EXCL`, so of several watchers exactly one performs), records SuperPipeline's
   decider, and performs; the perform step re-checks the digest against the rebuilt request. A
   fronted server's tool is run by the watching process on the server it fronts (started on first
   use), since no agent session waits on a hosted approval.
5. On `denied` the effect is refused with SuperPipeline's decider; on `expired` it is refused as
   expired undecided. A local expiry (the effect's own clock) stops the watcher reading it.

**Failure is closed.** If the create fails (SuperPipeline unreachable, credential missing or
refused), the effect stays pending and hosted. It is never decidable locally; the watcher retries
the create with the same `requestId`, which SuperPipeline answers with the same record, until the
effect expires. A read-back that fails is retried the same way. Changing `approvals_board` leaves
effects hosted on the old board waiting until they expire: stk never reads one board's answer for
another board's request.

## Upgrading

- An effect still pending from an stk without request digests has none, and is refused when it is
  approved: nothing is sent, and the agent asks again. Effects expire after 30 minutes, so this
  lasts no longer than that.
- `stk approvals` and `stk ui` no longer send or honour a decider name. On a station install, only
  root and the service user (or `--operator-uid`) can decide; run `sudo stk approvals allow <id>`.

## Enabling it on a host

Nothing changes on a host until its policy names a board. The operator:

1. Creates two Organization-plane services in Accounts for the board's workspace, one with scope
   `approval-requests:write` and one with `approval-requests:read` (write can also read back), and
   connects them: `stk connect superpipeline-approvals-write` and
   `stk connect superpipeline-approvals-read` (the credential on stdin). These are not the
   publisher's scopes: SuperPipeline refuses `approvals:read`/`approvals:write` on the
   approval-request routes. A host that also runs the automatic publisher connects credentials
   that carry both its `approvals:*` scope and the matching `approval-requests:*` scope.
2. Adds to the policy:

   ```yaml
   services:
     superpipeline-approvals-write: {}
     superpipeline-approvals-read: {}
   superpipeline:
     approvals_board: brd_…
   ```

3. Runs `stk reload` (or restarts `stk serve`).
4. Optionally reinstalls with `--operator-uid` to name the operator uids; by default they are root
   and the service user.

The credentials are native-only: no agent profile can name them, and their tokens are applied in
stk's transport and never returned.
