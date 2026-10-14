# supertoolkit

A credential broker for agents. One binary, `stk`. Go, because connectors ship as
checksum-pinned binaries and the release path for that already exists in Go
across this estate.

## The invariant, which no change may weaken

**The agent never holds, reads, or receives a credential.** There is no endpoint
that returns one — not for an agent, not for the CLI, not for our own web UI. A
change that adds one is wrong regardless of how convenient it is.

## Remotes

**Forge is primary.** `origin` is forge; the `github` remote exists for a future
public mirror and its push URL is deliberately `no-push--forge-is-primary`. Open
pull requests on forge. Note that `gh` bypasses the git push guard, so do not
reach for it here.

The Go module path is `github.com/SuperJackfruitLabs/supertoolkit` — the eventual
public path, chosen now so it does not change when the mirror appears.

## Versions

Tags start at `0.0.1`, per estate convention. Not `0.1.0`.

## Layout

- `cmd/stk` — the CLI and the daemon entry point
- `internal/broker` — the egress proxy: CONNECT, selective interception, h2 + h1
- `internal/credential` — the five operations: substitute, scheme-aware
  substitute, sign, mint, acquire
- `internal/policy` — config parsing, capability policy, profiles
- `internal/catalog` — service definitions (which host, which auth shape)

## Rules learned by spiking, which tests must hold

1. **Injection is credential-scheme aware.** A string replace works for Bearer
   and silently matches nothing for Basic, where the credential is inside base64.
   Test both.
2. **Propagate HTTP/2 trailers.** gRPC carries its status in a trailer, and the
   announce list must be rebuilt from `resp.Trailer` — Go's client does not leave
   it in `resp.Header`.
3. **Intercept selectively.** Hosts outside policy are tunnelled with CONNECT and
   never opened.
4. **Single-flight every acquisition.** Twenty concurrent callers must cause one
   token exchange.
5. **Never log a secret.** The audit record carries fingerprints. There is a test
   that asserts the real credential appears nowhere in it.
6. **Fail closed, never direct.** If the broker is unreachable the client must
   fail. A silent fall back to a direct connection is the worst outcome available.

## Measurement discipline

A client's exit code is not evidence: a bypass and a bad credential both look
like `401`. Assert against the broker's own counters and audit record. During the
spikes three results looked like findings and were faults in the instrument — add
a control before believing a surprising result.
