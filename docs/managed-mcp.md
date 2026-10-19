# Private managed MCP owner protocol

`stk managed-mcp-v1 --manifest /absolute/private/manifest.json --sha256 <digest>`
is an internal supervisor entry point. Older binaries reject this command. Do
not append managed flags to `stk mcp`: its legacy parser ignores unknown flags.
The supervisor must pin the actual executable as well as the manifest bytes.
The command does not start the proxy, fronted executables, plugins or a legacy
approval executor. Public installation and standalone MCP behavior are unchanged.

Salaam's parent controller and persistent process registry are not connected yet.
Do not enable this command as a station/model capability until the parent proves
its live authority, operation, cancellation and recovery boundary.

## Admission

The closed JSON manifest contains `version: 1`, `root_digest`, `profile_digest`,
`workspace`, `policy_path`, `policy_sha256`, `profile`, `store_dir`,
`passphrase_file`, `state_dir`, `owner_socket` and `owner_key`. The key is a fresh
private 32-byte value encoded as 64 lowercase hex digits. It authenticates only
this local controller connection; it is not an Accounts token or a new issuer.

Paths must be canonical and absolute. Manifest, policy and passphrase are private
owner-only, single-link regular files; their parent directories are private.
Store/state directories and the Unix owner socket are private too. These paths
must be outside the declared workspace. The command reads the explicit passphrase
file and store, with no environment/keychain/default-directory fallback. Admission
retains manifest, policy and passphrase fingerprints and checks drift before
controller requests and dispatch. The policy parser uses the already hashed bytes.

`profile_digest` is SHA-256 over canonical JSON with sorted ASCII keys:

```json
{"kind":"stk-native-managed-v1","policy_sha256":"<policy SHA-256>","profile":"<selected profile or empty string>","protocol":"2025-06-18","version":1}
```

The executable pin binds the compiled catalogue. The profile selects/narrows the
actual policy. The initial managed mode rejects fronted servers, dynamic forge
policies and non-Bearer token substitution; those paths require their own native
admission and credential proofs. OAuth, application-token acquisition and SigV4
remain native broker operations. Unknown action parameters are refused, rather
than approved and silently omitted from the actual API request.

Private filesystem checks do not sandbox a same-user workspace command. A station
runner must independently protect these files, credentials and controller socket.
The state directory must remain stable across recovery of the same root. A second
state directory is not a way to escape saved/uncertain effects. The parent must
bind that path and each broker process to its durable root/worker registry.

## Controller verification

The broker sends a bounded POST over its configured Unix socket to
`/managed-toolkit/v1/verify`, with `Authorization: Bearer <owner_key>` and JSON:

```json
{"version":1,"phase":"dispatch","request":{"version":1,"root_digest":"...","invocation_id":"...","profile_digest":"...","service":"github","action":"get_user","args":{},"approval":false,"expires_at_ms":1}}
```

This is a shape illustration; real deadlines must be future milliseconds within
five minutes and real fingerprints are 64 lowercase hex digits. The canonical
`Request` and corpus are defined in `internal/managedmcp` and
`testdata/managed-mcp-v1.json`. The broker constructs root/profile/approval from
its admitted configuration and actual native policy, never a model boolean.

The closed reply contains `version`, `phase`, `request_digest`, `decision` and
phase-specific fields. A final `review` answer includes `decision_id`. An allowed
`admit` includes integer `authority_for_ms` (1–90,000) to bound credential
acquisition. An allowed `dispatch` includes integer `send_within_ms` (1–5,000)
and `authority_for_ms` (at least the send window, at most 90,000). Other replies
omit grant durations. Phase and request fingerprint must match exactly. The controller
must check actual current principal, station/run epoch, worker, attempt, call,
exact arguments/profile and live lease. Well-formed metadata is not authority.

| Phase | Required parent behavior |
| --- | --- |
| `review` | Return `pending`, or an exact human answer `allowed`/`denied` with its bounded decision ID. Answering performs no effect. |
| `admit` | Fresh non-consuming authority check before credential access/acquisition. Return `allowed` or `denied`. |
| `dispatch` | Fresh exact operation check and durable consumption of **one** effect grant, after credentials are prepared. Return `allowed` or `denied`. |

The parent computes grant durations from the actual remaining authority lease,
including its monotonic deadline. The broker anchors both durations to monotonic
time **before** its IPC request; network latency only shortens them. It refuses
stale replies, rechecks the send window immediately before API handoff, and
clamps credential acquisition and the actual API HTTP request to their respective
authority deadlines. The longer immutable
invocation/review deadline does not extend work authority. A dispatch reply must
not be cached/reissued as a reusable grant after its permission is consumed.

Do not also consume this effect permission at the MCP stdio handoff. The parent
may record invocation delivery there. The broker records its dispatch marker
after the final grant and sends the prepared native request once. Controller
failures, wrong bindings, redirects, oversized replies and drift deny dispatch.
The verifier never returns provider credentials to the parent or the model.

## MCP and outcomes

The closed protocol is MCP `2025-06-18` with the four progressive meta-tools.
`capabilities.experimental["salaam.dev/toolkit"]` advertises version, bounded
grants and native kinds. `lifecycleControl` remains false until the separately
authorized journal recovery interface exists. These compatibility flags grant no
authority. Native action discovery exposes `kind` (`read`, `write`, `destructive`
or `unknown`) separately from `policy` (`agent` or `approval` for visible actions).
An explicitly agent-callable write is still a write; the parent must never infer
read-only behavior from absence of human approval.
`execute_action` arguments are `{category, action, args}` with string-valued
argument properties. Private `params._meta["salaam.dev/toolkit"]` supplies
`{version:1, invocation_id, expires_at_ms}`. The parent must supply/bind this
metadata independently of model arguments. Missing metadata cannot execute.

Native HTTP uses one HTTP/1 connection per request, no environment proxy,
redirect, compression or replayable body, with a 30-second deadline. Replies are
bounded and sanitized before durable receipt storage and model output. Upstream
headers, trailers, status reasons and raw errors are not exposed. Redaction covers
actual injected values and common encodings; it does not defeat deliberately
arbitrary transformations by a malicious upstream.

`returned` means a complete protocol response, not verified product work. Its
native result carries `protocol_result`, `is_error`, HTTP `status` and safe `body`.
Non-2xx replies set MCP `isError`; denied, pending, interrupted or unknown receipts
also cannot look successful. Partial/oversized/lost replies remain unknown. Saved
receipts precede new grants; uncertain work fences other calls under that root.

Cancellation notifications durably cancel the invocation before aborting its
local context. EOF/termination cancels active work. An observed HTTP close does
not establish that a remote effect stopped. There is one active action, bounded
128 KiB JSONL input and at most 1,024 request IDs per broker process. The parent
must allow for bounded JSON escaping when pinning its output byte limit (up to
4 MiB). It must rotate/restart the owned process without losing the ledger.

`OwnProcess` excludes a second live broker using the same state directory. It
does not prove the previous owned process stopped or authorize
`FenceInterrupted`. The parent must persist and reconcile actual process identity,
stop old resources, then preserve interrupted records as unknown before any
replacement grant. An empty in-memory map is not a recovery receipt.
