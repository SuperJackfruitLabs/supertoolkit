# Code structure and quality ratchets

How the code is laid out, and the checks that keep it that way. Every number
here is held by a script or a test that fails when it is wrong; this page
explains them, and the numbers themselves live in the files it cites.

Each ratchet records how the code looks and fails if it gets worse. Each one
also fails if it gets **better** without the record being lowered, so a stale
record cannot let the next regression through.

---

## Where the code lives

`cmd/stk` is the entry point and nothing else: `main.go` prints the usage and
dispatches each command to its package, and `install.go` parses the flags of
`stk install`. stk's version is a variable in `main.go` (the release build
stamps it with `-ldflags -X main.version=…`), and main passes it to the
packages that report it or send it as a User-Agent.

The commands and the broker runtime they share are in `internal/`, one package
per seam:

| Package | Holds |
|---|---|
| `localstate` | the state directory, the policy file's path, the control socket, the proxy key and address files, opening the store, resolving a service name, dialling the daemon |
| `secrets` | where a stored credential becomes what goes on the wire: the acquirers, the proxy's secret source, `Authorize` for a direct request |
| `livepolicy` | the policy in force in a running process, its reload, and `stk reload` |
| `audit` | the ledger observer, who each entry is attributed to, `stk audit`, the web UI's feed |
| `native` | one direct request with a credential attached, outside the proxy, and the managed Toolkit's owned client |
| `session` | starting a broker and the environment a child gets; `stk run` |
| `controlplane` | what the daemon serves: its methods, approving and performing an effect, fronted MCP servers, the daemon side of `stk mcp serve` |
| `serve` | `stk serve` |
| `mcpcmd` | `stk mcp`, `stk mcp install`, `stk mcp serve`, `stk approvals` |
| `publishcmd` | durable ingress, execution and recovery for `stk publish` |
| `managedtoolkit` | `managed-mcp-v1`, `managed-control-v1`, `managed-evidence-v1` |
| `setup` | `stk init`, `stk add`, `stk connect` (stdin, `--device`, `--browser`), `stk handover` |
| `credcmd` | `stk verify`, `stk revoke` |
| `doctor` | `stk doctor` and `stk doctor --probe` |
| `proxyenv` | `stk env` |
| `uicmd` | `stk ui` |
| `clitest` | fixtures the command packages' tests share; only tests import it |

The packages below them are unchanged: `broker` (the egress proxy),
`credential` (the five operations), `policy`, `catalog`, and the rest.

A new command goes in a package of its own, or in the one whose seam it
shares, and gets one line in `main.go`.

## Go lint: `go run ./scripts/lint-go`

[golangci-lint](https://golangci-lint.run) `v2.15.0`, pinned in
[`scripts/lint-go/main.go`](../scripts/lint-go/main.go) and in CI; the command
refuses any other version, because a newer linter finds more and the counts
would mean nothing. Configuration: [`.golangci.yml`](../.golangci.yml). Install
it once into the repository's ignored `.bin/`:

```bash
GOBIN="$PWD/.bin" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

- **Linters:** `errcheck`, `govet`, `staticcheck`, `ineffassign`, `unused`,
  `gosec`, `errorlint`, `bodyclose`, `nilerr`, `noctx`, `misspell`,
  `unconvert`, `copyloopvar`. `revive` and `gocritic` are off (mostly style).
  Of gosec's rules only G104 is off, because it counts every unchecked error a
  second time; every other rule stays on and its findings are held by the
  baseline, not switched off.
- **It analyses the linux/amd64 build**, so a Mac and CI count the same.
- **The ratchet.** Findings are counted per linter in
  [`scripts/lint-go/baseline.json`](../scripts/lint-go/baseline.json). A count
  may fall but never rise, and a linter missing from the baseline must be
  clean. After a cleanup, `go run ./scripts/lint-go --update` writes the lower
  counts (it refuses to raise one); lint fails until you do.
- **golangci-lint reports one finding per line.** When a fix removes one
  linter's finding from a line, another linter's finding on the same line can
  appear, and moving code between packages changes what gosec's taint rules
  can follow. When that raises a count, the commit that does it says so and
  sets the new count by hand.

In shipped code `errcheck` is at zero: an error the code means to drop is
dropped with `_ =` and a comment saying why. Most of what the baseline holds is
in tests.

## Architecture: `internal/archtest`

Run by `go test ./...` like any other package.

- **Size** ([`size_test.go`](../internal/archtest/size_test.go)): a shipped
  `.go` file may have at most 1,000 lines and a package (one directory) at most
  4,000. Files and packages over the limit are listed with their current size
  in `oversizeFiles` and `oversizePackages`, may only shrink, and must have
  their entry lowered when they do. Both lists are empty. Tests and testdata do
  not count.
- **Import direction** ([`imports_test.go`](../internal/archtest/imports_test.go)):
  nothing imports `cmd/`, and the internal packages sit in layers, lowest
  first, each importing only packages in a lower layer, so two packages in one
  layer are independent. A new package fails the test until it is given a
  layer. Back-edges allowed for now would be listed in `knownBackEdges`, which
  may only shrink and is empty. The layers are the order the code has: each
  package sits one layer above the highest package it imports.

When a lower package needs something from a higher one, do not add a
back-edge: move the pure helper down to the package that needs it, or pass the
dependency in as a parameter or a narrow interface where the pieces are put
together (`main.go`, or the command that builds the call), the way stk's
version is passed in rather than read from main.

## What stk prints: the CLI goldens

[`cmd/stk/cli_characterization_test.go`](../cmd/stk/cli_characterization_test.go)
runs the real `main()` in child processes, each with its own state directory,
policy file and `PATH`, and holds what they print and how they exit in
`cmd/stk/testdata/cli-*.golden.txt`: help and usage, every command's argument
and error text, exit codes, JSON output, a stdio MCP session, `stk doctor` and
its probe over fake clients, the device grant against a local stand-in
provider, `stk serve` with reload, SIGHUP, `stk env` and approvals against it,
`stk ui`, and `stk install` for Linux and for anything else. Nothing reaches
the network or a real store.

The goldens hold the Linux output, which CI runs. The few lines that differ by
platform on purpose (where a Go program finds its CA) are mapped to their Linux
form before the comparison, so the same files pass on a Mac. Random values (a
key, a port, a sealed envelope, a clock) print as names such as
`$PROXY_KEY`.

A change to what stk prints shows up as a golden diff, which is the point:
regenerate with

```bash
go test ./cmd/stk -run TestCLICharacterization -update-cli-golden
```

and read the diff before committing it.

## What CI runs

[`.forgejo/workflows/ci.yml`](../.forgejo/workflows/ci.yml), on every pull
request and on main:

```bash
gofmt -l cmd internal          # must print nothing
go vet ./...
go test -race -p 1 ./...
go run ./scripts/lint-go       # after installing the pinned golangci-lint
```

Run the same before pushing.

## Left as they are

Findings the lint cleanup did not touch, because changing them would change
behaviour or because the code is the broker's own:

- **`errorlint` in shipped code (11).** Ten are `fmt.Errorf` with `%v` around
  an error (in `egress`, `localstate`, `mcpcmd`, `mcphost`, `netjail`,
  `proxyenv` and `serve`). Turning `%v` into `%w` would make `errors.Is` and
  `errors.As` see through the wrapper, which can change what a caller matches.
  The eleventh is the `io.EOF` compare in `credential/refreshlock_unix.go`,
  left alone because it is in the credential package.
- **`noctx` in shipped code (2):** the TLS handshakes in `broker/egress.go`
  and `broker/proxy.go`.
- **gosec G112 on the broker's one-connection servers.** They have no
  `ReadHeaderTimeout`; adding one would change the proxy.
- **`nilerr` (3)** in `credential/store.go`, `install/install.go` and
  `mcpserve/decide.go`: each returns nil after an error on purpose, with a
  comment saying why (an untyped legacy credential, an absent unit file, a
  decision that could not be recorded becoming a denial).
- **Test seams that are package variables:** `oauthPort` in `setup`,
  `verifyHTTP` and `verifyBaseURL` in `credcmd`, and `doctorProbe`,
  `doctorCheckFn`, `doctorIsolation`, `probeClients` and `newRigFn` in
  `doctor`. They predate the split and moved with their code.
