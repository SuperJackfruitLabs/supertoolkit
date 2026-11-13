---
title: The audit ledger
description: What was done, under which policy, and what the provider said.
---

```sh
stk audit                 # the most recent effects
stk audit --limit 200
stk audit --json
```

```
  Oct 15 02:20:28  github     create_issue             approval 201 Created
                   POST /repos/you/your-repo/issues · credential: sha256:40a7a1d2319d
  Oct 15 02:20:15  github     get_user                 agent    200 OK
                   GET /user · credential: sha256:40a7a1d2319d
```

Each line records the service, the capability **by the name you set policy on**,
the policy that applied, and what the provider answered.

## No credential is ever recorded

What is kept about the credential is a fingerprint, or the name of the operation
that replaced it — never the value. A signed request carries no token at all, so
naming the operation is the honest answer there. There is a test for every
scheme.

## Where it lives

An append-only file in the state directory, owner-only. Every process writes the
same one — a broker, the daemon, an MCP server — so `stk audit` and the web
interface cannot disagree about what happened.

It rotates at 8 MB keeping one generation, because an unbounded audit log on a
small server is an outage. If you need more history, ship the file somewhere
before it rotates.

A line that cannot be parsed is skipped rather than fatal. A process killed
mid-write leaves one incomplete record, and a ledger that refuses to open
because of its last line has lost everything before it.

## Hosts outside policy

A connection to a host you have not configured is recorded too, but only as far
as the broker can see it:

- **With no `egress:`**, it is tunnelled unopened and recorded as
  `tunnelled, not decided`, with the host. The broker never sees inside it,
  which is what keeps interception's blast radius equal to your service list.
- **With an [`egress:`](/use/mcp-serve/#egress-decided-by-address) policy**, it
  is decided by address, and recorded allowed or refused with the rule that
  decided it and the address dialled.
- **With `methods:` in that egress**, the tunnel is opened with the broker's CA,
  so each request's method and path are checked and recorded as well.

## What is not recorded

The credential, ever. And, for a host outside policy whose egress has no
`methods:`, what went through the tunnel: its method, path and body are not
seen, only the host and the address.
