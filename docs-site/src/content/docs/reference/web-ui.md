---
title: The web interface
description: stk ui serves five screens on its own loopback listener behind a one-time link, and the eight API routes behind them.
---

```sh
stk ui                          # http://127.0.0.1:7420, opened in your browser
stk ui --no-open                # print the link only
stk ui --bind 10.0.0.5:7420     # an address on a private network, if you mean it
```

`stk ui` serves the status, services, policy, approvals and audit screens to the
person who runs it. Three rules hold it in place:

- **Its own listener.** The control socket agents reach gains no HTTP route,
  and the UI is started on demand, so a broker's attack surface is unchanged by
  the command existing.
- **Loopback unless you say otherwise.** It binds `127.0.0.1:7420` by default,
  and naming an address with `--bind` (`-b`) is what says you mean it.
- **A one-time link.** The URL carries a random token once; the browser keeps it
  as a cookie (`HttpOnly`, `SameSite=Strict`) and is redirected so the token
  leaves the address bar and the history. Without it every route answers `401`.

It is just another caller: it may show that a credential is present, its fields
and the operation that uses it, never its value. A decision made here performs
the effect in this process, and is recorded as `name (uid N) via stk ui`. While
the policy names a SuperPipeline approvals board, it refuses every local
decision, as `stk approvals` does.

## The API

The screens read the same JSON the browser fetches. Every route needs the
cookie; none returns a credential, and a test holds every route to that.

| Route | |
|---|---|
| `GET /api/status` | the workspace, how many services and fronted servers, the profiles, how many approvals are pending, and `stk doctor`'s checks |
| `GET /api/services` | each service and fronted server: host, operation, what goes on the wire, whether it is connected, and its field names |
| `GET /api/policy` | each capability's policy, summary and ceiling (`agent` for a read, `approval` otherwise) |
| `GET /api/approvals` | the approvals queue, each effect with its arguments, expiry, state and decider |
| `GET /api/audit` | the newest 200 records of the ledger |
| `POST /api/policy` | `{"category", "action", "policy"}`: set one capability's policy in `supertoolkit.yaml`. A write cannot be made agent-callable here: approval is its ceiling |
| `POST /api/approvals/decide` | `{"id", "allow"}`: decide an approval, and perform it if allowed |
| `POST /api/services/revoke` | `{"service"}`: remove the local copy of a credential. To withdraw it at the provider too, use `stk revoke` |

A binary built without the web assets serves the API alone and says so on
`/`; build the assets with `pnpm -C web build`.
