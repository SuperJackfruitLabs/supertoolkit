# Managed broker invocation boundary

This internal component is preparation for the managed MCP entry point. It is not
connected to `stk mcp`, the legacy approval API, or a model-facing executor yet.

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

Cancellation is durable before the local context is aborted. A ledger receipt
does not confirm a process or external effect stopped. Supervision must account
for actual owned processes/resources; a received protocol result does not verify
the product effect. Executors must sanitize results before returning them to this
component; it holds no credential store and cannot redact unknown credentials.

The canonical producer corpus is `testdata/managed-mcp-v1.json`, mirrored in
Salaam's `test/fixtures/toolkit-managed-mcp-v1.json`. Both consumers check shape
and canonical hashes, including Unicode scalars and rejected byte bounds. Shape
conformance is separate from authority admission. Managed stdio configuration,
broker policy admission, the private live owner verifier and the daemon/controller
integration remain required before this becomes an executable capability.

The process proofs kill an actual child before send, after local HTTP acceptance
and after result storage. They prove no redispatch and retained uncertainty with
synthetic authority and effects; they do not exercise a deployed broker/provider.
