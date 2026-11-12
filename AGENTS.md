# supertoolkit

A credential broker for agents. One binary, `stk`. Go, because connectors ship as
checksum-pinned binaries and the release path for that already exists in Go
across this estate.

## The invariant, which no change may weaken

**The agent never holds, reads, or receives a credential.** There is no endpoint
that returns one — not for an agent, not for the CLI, not for our own web UI. A
change that adds one is wrong regardless of how convenient it is.

## Remotes

**Forge is primary.** `origin` is forge; open pull requests there, with `tea`. The `github`
remote is the public mirror, where the release, the sites and the staging deploy run: never push
to it, open pull requests on it, or reach for `gh` here.

The Go module path is `github.com/SuperJackfruitLabs/supertoolkit`, the mirror's path.

## Versions

Tags are `vX.Y.Z`, like every other suite repository, and the series starts at
`0.0.x` (not `0.1.0`). `0.0.1`–`0.0.3` were tagged without the `v` and stay; the
next release follows the latest `v` tag. `scripts/release.sh vX.Y.Z` stamps the binary `stk X.Y.Z`.

## Layout

`cmd/stk` is the entry point only: `main.go` dispatches each command to its package. The table in
[`docs/code-quality.md`](docs/code-quality.md) says what each package holds.

- `internal/broker`: the egress proxy (CONNECT, selective interception, h2 + h1)
- `internal/credential`: the five operations (substitute, scheme-aware substitute, sign, mint, acquire)
- `internal/policy`: config parsing, capability policy, profiles
- `internal/catalog`: service definitions (which host, which auth shape)
- Shared runtime: `localstate` (state dir, policy path, control socket, store), `secrets` (a
  stored credential becomes what goes on the wire), `livepolicy` (the policy in force and its
  reload), `audit` (the ledger observer, `stk audit`), `native` (one direct request outside the
  proxy), `session` (start a broker and a child's environment; `stk run`), `controlplane` (what
  the daemon serves)
- Commands: `serve`, `mcpcmd` (`stk mcp`, `stk approvals`), `publishcmd` (`stk publish`), `managedtoolkit` (the managed-* commands),
  `setup` (`stk init`, `add`, `connect`, `handover`), `credcmd` (`stk verify`, `revoke`), `doctor`,
  `proxyenv` (`stk env`), `uicmd` (`stk ui`)
- `internal/clitest`: fixtures the command packages' tests share; only tests import it

## Rules learned by spiking, which tests must hold

1. **Injection is credential-scheme aware.** A string replace works for Bearer
   and silently matches nothing for Basic, where the credential is inside base64.
   Test both.
2. **Propagate HTTP/2 trailers.** gRPC carries its status in a trailer, and the
   announce list must be rebuilt from `resp.Trailer` — Go's client does not leave
   it in `resp.Header`.
3. **Intercept selectively.** Hosts outside policy are tunnelled with CONNECT and
   never opened — unless an `egress:` with `methods:` asks for it. Either way they
   are recorded, and decided by address when an egress applies.
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

## Things agents get wrong

- **Run what CI runs before pushing.** Read `.forgejo/workflows/ci.yml` and [`docs/code-quality.md`](docs/code-quality.md): `gofmt -l cmd internal`, `go vet ./...`, `go test -race -p 1 ./...`, `go run ./scripts/lint-go` rather than guessing; the commands are there.
- **Snapshots and goldens pass in a bare environment and on Linux.** Run them under `env -i PATH="$PATH" HOME="$HOME" CI=true go test ./cmd/stk -run TestCLICharacterization`. Normalise platform strings (OS, arch) and `COLORTERM` in the test instead of recording your machine's.
- **Count lint baselines on a clean install** (`go run ./scripts/lint-go` with the pinned golangci-lint it requires), never on a tree with stray packages or a stale build.
- **No skipped tests.** Never `.skip`, `.only` or delete a red test to get green (the existing platform skips are the only ones); fix it, or say in the PR why it is red.
- **Characterization test first.** Before a refactor that touches behaviour, commit a test against the old code and prove it can fail (revert the code, watch it go red).
- **Check the PR is still open before pushing to its branch.** PRs are often merged within minutes, and a push to a merged branch strands the work.
- **Forge-primary.** Push and open PRs on the forge (`origin`, `tea`); the `github` remote is a public mirror: never push to it or open PRs there.
- **A tag only publishes binaries.** The mirror runs the suite's shared release workflow (`.github/workflows/release.yml` and `.github/release/`, synced byte-identical from the suite's release kit: change them there, never here; settings in `.github/release-config.json`). It needs the forge's `broker-conformance / broker (push)` status to have passed for the tag's commit (or runs `go test ./...` at the tag when it cannot read it), builds with `scripts/release.sh <tag>` and publishes the archives, `SHA256SUMS` and attestations. Nothing deploys from a tag. Write user-visible changes under `## Unreleased` in `CHANGELOG.md`.
- **Some tests need Linux or a short `TMPDIR`.** Network modes other than host (`network: confined`) are Linux-only and skip on a Mac, and Unix socket paths must fit in 104 bytes on macOS. A Mac pass does not prove those; CI does.
- **SuperToolkit brokers agent tools and MCP only, never AI providers.** A model's API key stays with the harness.
- **Broker and credential code is security-sensitive** (`internal/broker`, `credential`, `secrets`, `egress`, `netjail`). Hold the invariant above, and assert against the broker's own counters and audit record.
- **The Claude CI files are synced copies.** `.github/claude/claude-ci.mjs` and the `claude-review`/`claude-triage` workflows come from the suite's shared kit; change them there, not here. The advisory PR review follows [`REVIEW.md`](REVIEW.md).

