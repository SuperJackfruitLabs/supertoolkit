---
title: Gated publishing
description: stk publish posts to X only after a SuperPipeline gate approved the exact bytes, and never posts twice.
---

`stk publish` is a durable command path for one effect that a person decides on
SuperPipeline and stk then carries out automatically: a post to X. The agent
proposes the exact bytes; a person approves those bytes on a SuperPipeline gate;
stk posts them, and only them, and records where they went.

```sh
stk publish submit < request.json   # store the exact request; prints its id and digest
stk publish perform <id>            # post it, if and only if the gate approved these bytes
stk publish recover                 # finish or fence anything a crash left half-done
```

**Exit status 3 means the gate is waiting for a person.** It is neither success
(0) nor failure (1): `perform` prints `{"id": …, "state": "awaiting_decision"}`
and nothing has been sent. Run it again later.

## What it needs

Three services connected on the broker: `x` (the account that posts), and the
two native-only SuperPipeline services, `superpipeline-approvals-read` (to read
the gate's decision) and `superpipeline-approvals-write` (to record the delivery
on the card). Each SuperPipeline credential is an Organization-plane service
credential with one scope. The agent holds none of them, and no profile can name
the SuperPipeline ones.

## Submit

`submit` reads one JSON request on stdin:

| Field | |
|---|---|
| `boardId`, `subjectId` | the SuperPipeline board and the frozen approval subject (`brd_…`, `aps_…`) |
| `expiresAt` | the subject's expiry, RFC 3339 |
| `method`, `url` | `POST` and `https://api.x.com/2/tweets`: the only request it accepts |
| `bodyBase64` | the exact request body |
| `mediaBase64` | each media object, in order |
| `summary` | what a person reading the record should see |

It stores those bytes and prints the effect's id, its request digest and its
state. The board and subject ids are lookup references, not authority: only
stk's own authenticated read-back of the gate can authorize the send.

## Perform

`perform` loads the stored bytes back from disk, then asks SuperPipeline
directly, with stk's own read credential, for the stored gate decision. It must
return the gate, the frozen subject's digest, an `automatic` delivery decision,
and that the decision is current. Immediately before sending, stk hashes the
actual method, URL, body and media and compares that with the digest the person
approved. A mismatch is refused and recorded with both digests. A rejection,
requested changes, a manual delivery choice, expiry, an unreachable
SuperPipeline or an unreadable answer all fail closed.

After X accepts the post, stk reads it back to find its live URL, and records
that URL on the SuperPipeline card with the write credential.

A SuperPipeline-gated effect cannot be decided locally: `stk approvals allow`
and `deny` both refuse it without changing its state.

## Never twice

A timeout or a dropped connection after the bytes may have reached X is not a
failure: stk records `outcome_unknown`, fences every retry, and reads X back to
see whether the exact approved post exists, without writing.

- **Found**: recorded as delivered, with its URL, which goes on the card.
- **Not found, or not indexed yet**: the fence stays. A search miss is
  inconclusive and never permits a retry.
- **Read-back failed**: still `outcome_unknown`, still fenced.

`stk publish recover` walks the queue and does this for every gated effect a
crash left sending, unknown, delivered-but-unrecorded or allowed to retry, and
refuses any that expired without a confirmed decision. A provider's 4xx or 5xx
is a confirmed answer, recorded as it is, and never treated as delivery.
