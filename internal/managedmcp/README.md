# Managed broker invocation boundary

The versioned `stk managed-mcp-v1` command now uses this ledger with native
broker dispatch, private manifest admission and a local owner verifier. Legacy
`stk mcp` and its approval API remain separate. Salaam has not yet connected this
command to its parent controller or durable process recovery. No station
capability is enabled by these component proofs.

`Request` binds one invocation to an opaque execution-root fingerprint, reviewed
profile, exact service/action/arguments, broker approval requirement and bounded
expiry. The broker must construct it from its actual reviewed policy. Neither
request metadata, a fingerprint nor a decision grants execution authority.
`Execute` requires a fresh owner callback immediately before its durable dispatch
marker and executor. The callback must validate the actual principal/run lease
and consume the parent's exact operation grant. An answer to `Decide` performs
nothing; the supervised broker remains the only executor.

Records live in the private `managed-mcp-v1` directory. An older approval process
cannot consume them as legacy `.req` files. A stable filesystem lock serializes
independent writers; complete records and their containing directory are synced
before dispatch. Saved receipts precede fresh grants. Uncertain or active effects
fence other invocations under that root. No automatic replay or reconciliation
is provided. `FenceInterrupted` requires the supervisor to have observed its old
process stopped, and preserves uncertainty rather than asserting an effect failed.
The private `managed-control-v1` entry point now exposes exact inspect, fence,
cancel, root revoke and uncertainty acknowledgement through a separately scoped
owner check plus exclusive process ownership. An acknowledgement is an immutable
terminal non-success receipt; it never replays the old invocation or verifies the
effect. The actual parent must confirm the durable predecessor-stop evidence and
resolution decision. The control command does not open provider credentials and
can run after the old credential configuration/workspace is removed.

Cancellation is durable before the local context is aborted. A ledger receipt
does not confirm a process or external effect stopped. Supervision must account
for actual owned processes/resources; a received protocol result does not verify
the product effect. Executors must sanitize results before returning them to this
component; it holds no credential store and cannot redact unknown credentials.

The canonical producer corpus is `testdata/managed-mcp-v1.json`, mirrored in
Salaam's `test/fixtures/toolkit-managed-mcp-v1.json`. Both consumers check shape
and canonical hashes, including Unicode scalars and rejected byte bounds. Shape
conformance is separate from authority admission. The versioned command admits
private configuration and derives approval from its
actual native policy. The private owner protocol is implemented on the broker
side. Its Salaam consumer, actual authority/permission registry and durable
process supervision/recovery remain required before exposing this to a model
through Salaam.

The process proofs kill an actual child before send, after local HTTP acceptance
and after result storage. They prove no redispatch and retained uncertainty with
synthetic authority and effects; they do not exercise a deployed broker/provider.

The managed command is supervisor input, not a replacement for standalone MCP
configuration. See [the private owner protocol](../../docs/managed-mcp.md). Local
Unix/API fixtures exercise actual broker dispatch, credential acquisition,
redaction and cancellation with synthetic credentials. They are not a deployed
Accounts, station, Library or provider acceptance result.
