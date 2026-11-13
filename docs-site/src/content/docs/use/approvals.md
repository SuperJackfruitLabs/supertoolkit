---
title: Approvals
description: What happens when an agent proposes an effect you have to decide.
---

An effect at `approval` is submitted, returns `pending` with an id, and
**performs nothing** until somebody decides. With nothing to decide through, the
effect simply does not happen: the queue fails closed.

## Deciding

```sh
stk approvals                     # what is waiting on you
stk approvals allow <id>          # or: stk approvals approve <id>
stk approvals refuse <id>         # or: stk approvals deny <id>
```

`stk approval` is the same command. With a daemon running as its own user, only
an **operator uid** may decide: root and the daemon's user by default, or the
uids named with `--operator-uid`. See
[who may decide](/run/serve/#who-may-call-and-who-may-decide).

Or in the web interface, which shows the same queue:

```sh
stk ui
```

The queue is shared by every process on the machine, so an approval raised by an
agent through `stk mcp` can be decided from the CLI or the browser. Decide-once
is enforced by the filesystem: if two people answer at the same moment in two
windows, one wins and the other is told who got there first.

## Approving performs the effect

Whoever decides carries it out, and the record keeps what actually happened:

```json
{"state":"approved","decided_by":"web","performs":true}
{"outcome":"201 Created","error":""}
```

This matters more than it sounds. An approval that only records a decision —
with nothing anywhere performing it — puts a false statement in the audit trail:
somebody reading `approved` would reasonably believe the thing had happened.

Exactly one party performs an approved effect, and the record says which, so a
waiting agent reports the outcome rather than running it a second time.

"Approved, and it failed" is a true record and is kept as one. The outcome
carries the provider's status or the reason it did not work.

## What the screen shows

> Each shows the exact request that would be sent, not a summary. Approving a
> description is not approving the act.

The arguments are shown in full, because approving something you cannot inspect
is the thing this is meant to prevent. A request that cannot be built is refused
before anyone is asked, so a decision is never spent on something that could not
have taken effect.

## Expiry is never approval

An approval expires after thirty minutes by default. An expired effect cannot be
approved afterwards — somebody returning to a stale browser tab and clicking
allow must not cause the effect.

## Every approval binds the exact request

At submit, stk computes a digest over the exact request the effect would send —
service, capability, profile, method, URL, body and every argument — and stores
it on the effect. Whoever performs an approved effect rebuilds the request and
recomputes the digest first. A mismatch, from an edited queue record or a policy
or catalogue change that moved the target, is refused: nothing is sent, and the
outcome records both digests.

## Approvals hosted on SuperPipeline

By default an approval waits locally. Name a SuperPipeline board and every
approval is hosted there instead, for a workspace owner or admin to decide, on
the board or in chat:

```yaml
services:
  superpipeline-approvals-write: {}   # approval-requests:write: creates the request
  superpipeline-approvals-read: {}    # approval-requests:read: reads the decision back
superpipeline:
  approvals_board: brd_…
```

The policy does not load with `approvals_board` set unless both services are
declared. Connect each with an Organization-plane service credential that has
that one scope (`stk connect superpipeline-approvals-write`, then `-read`, the
credential on stdin), then `stk reload`.

With a board named, an effect at `approval`:

1. is submitted as hosted, and the agent is answered `pending` with
   `decided_on: superpipeline` and the approval request's id;
2. becomes an approval request on the board, with the request digest, the
   effect's 30-minute expiry, and a preview of the exact request (target,
   station, requester, profile and every argument). A preview that had to be
   cut is marked incomplete, so a client withholds approval until the person
   opens the full request;
3. is read back every few seconds by `stk serve` (and by `stk mcp` for its own
   session). On `approved`, stk checks again before acting: the answer is for
   the request it created, the option is allow-once, the subject and digest are
   the effect's, it has not expired, and a decider is named. Then exactly one
   watcher performs it and records SuperPipeline's decider. On `denied` it is
   refused; on `expired` it expires undecided.

**Nobody decides a hosted approval locally**, operators included: while the
policy names a board, `stk approvals` and `stk ui` refuse every local decision.
**Failure is closed**: if SuperPipeline cannot be reached, the effect waits,
is retried, and then expires. It never falls back to a local decision.

## The limit worth knowing

The gate protects against an agent confined to the tool surface it is given, and
against an agent with a shell **when the agent runs as its own uid** and the
broker as another: the daemon's socket refuses `approvals.decide` to agent uids
(see [Run as a service](/run/serve/)). It does **not** protect against an agent
that runs as the broker's own user, or as an operator uid: that agent could run
`stk approvals allow` itself, write a decision file, or run `stk ui`. A
standalone `stk mcp`, which runs as the agent's uid, is the same case. If that
matters, install the broker with `stk install` and do not give the agent a shell
as the broker's user.
