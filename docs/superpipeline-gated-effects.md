# SuperPipeline-gated effects and unknown-outcome read-back

Card: `card_691a65ff98944697`

## Decision

For a SuperPipeline-gated effect, stk asks SuperPipeline directly for the stored gate decision. The request uses an stk-owned, read-scoped service credential that is unavailable to the submitting agent, its shell, and `stk approvals allow`.

The confirmation must return all of the following from SuperPipeline's durable state:

- the gate identity;
- the frozen approval-subject digest;
- the delivery decision (`automatic` only);
- whether the decision is current rather than rejected, changes-requested, manual, or expired.

The frozen approval subject carries an `outboundRequest` descriptor: method, URL, base64 of the exact body bytes, and the ordered SHA-256 values of each media object. SuperPipeline independently computes and stores the complete-request digest inside the immutable subject; the human approves that subject digest and request digest together. Immediately before every provider side effect, stk deterministically hashes the actual method, URL, body bytes, and ordered media bytes and compares that request digest with the value returned by SuperPipeline. A mismatch is recorded as refused with both digests. The agent-supplied gate identity and expected digest are lookup references, not authority; only stk's own authenticated read-back can authorize the send. SuperPipeline rejection, request-changes, manual delivery, expiry, an unreachable confirmation service, or an unreadable response all fail closed.

The local approval record fields `_approval_authority`, `_approval_board`, and `_approval_subject` are lookup references only. `stk approvals allow` refuses them. The automatic publisher uses its own `approvals:read` token to verify the decision and a separate `approvals:write` token only after provider read-back has found the canonical live URL.

## Unknown outcome

A timeout or connection loss after request bytes may have reached X is not a normal failure. stk records `outcome_unknown`, fences every retry, and invokes deterministic provider read-back. For X, read-back checks whether the exact approved post exists without issuing a write:

- found: record `delivered` and the canonical live URL, then record that URL on the SuperPipeline card;
- not found: record the negative read-back and permit exactly one retry of the unchanged digest;
- inconclusive or failed read-back: remain `outcome_unknown` and keep retries fenced.

Provider 4xx/5xx responses are confirmed responses, not transport-unknown outcomes; they are recorded truthfully and never silently treated as delivery.

## Threat model

Protected against:

- an agent with shell access self-approving through `stk approvals allow`;
- forged agent input claiming a gate was approved;
- mutation of any request byte after approval;
- replay after rejection, manual choice, expiry, timeout, or a dropped response;
- duplicate posting after X accepted a request whose response was lost;
- credential disclosure to the agent or test process.

Trust boundaries and residual risks:

- stk trusts the authenticated SuperPipeline service response and its durable approval state;
- SuperPipeline trusts its approval subject canonicalization, signer, and gate storage;
- X read-back must identify the exact post strongly enough to avoid a false negative; an inconclusive match remains unknown rather than authorizing a retry;
- compromise of the stk daemon or its service credential is outside the agent-shell boundary and requires credential rotation plus audit review.

Tests use local callbacks and synthetic values only. They require no X credential, account, secret, or network call.
