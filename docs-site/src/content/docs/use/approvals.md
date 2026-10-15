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
stk approvals allow <id>
stk approvals refuse <id>
```

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

## The limit worth knowing

The gate protects against an agent confined to the tool surface it is given. It
does **not** protect against an agent with arbitrary shell access on the same
machine, which could run `stk approvals allow` itself. If that matters, run the
broker as its own OS user and do not give the agent a shell there.
