---
title: Install
description: Install supertoolkit with the checksum-verifying installer or from source, and stand up a broker.
---

supertoolkit is a single Go binary, `stk`. It runs on your own machine, on Linux
or macOS, amd64 or arm64.

## The installer

```sh
curl -fsSL https://supertoolkit.dev/install.sh | sh
```

It downloads the release archive for this OS and architecture and the release's
`SHA256SUMS`, and **verifies the archive before moving anything into place**. A
missing checksum tool, a `SHA256SUMS` that does not mention the archive, or a
mismatch stops it: it refuses rather than warns. It then puts `stk` in
`/usr/local/bin` if that is writable, otherwise `~/.local/bin`, and prints
`stk version`.

| Variable | Default | |
|---|---|---|
| `STK_VERSION` | the latest release | a tag to install instead |
| `STK_BIN_DIR` | `/usr/local/bin` or `~/.local/bin` | where to put the binary |
| `STK_BASE_URL` | the GitHub release | a mirror or an air-gapped copy. `SHA256SUMS` is still fetched from it and still verified |

```sh
curl -fsSL https://supertoolkit.dev/install.sh | STK_VERSION=v0.0.9 STK_BIN_DIR="$HOME/bin" sh
```

## From source

```sh
git clone https://github.com/SuperJackfruitLabs/supertoolkit
cd supertoolkit
go build -o stk ./cmd/stk
mkdir -p "$HOME/.local/bin"
install -m 0755 stk "$HOME/.local/bin/stk"
export PATH="$HOME/.local/bin:$PATH"
```

Go 1.26.0 or newer is required by the module. The commands above install `stk`
under your account and add it to this shell's `PATH`. Add the same `export` line
to your shell startup file to use it in future terminals.

There is nothing else to install: the web interface is
embedded in the binary. `stk version` prints the version it was built as.

On a server where agents run as their own OS users, run the broker as another
one, under systemd: see [Run as a service](/run/serve/), and `stk install`.

## First run

```sh
stk init
```

This creates a local certificate authority, a sealed credential store, and a
starter `supertoolkit.yaml`. It prints where each lives and **where the store
key came from** — an OS keychain, or a file beside the ciphertext. That
difference matters and is reported rather than hidden; see
[Limitations](/limitations/#the-store-key-is-only-as-good-as-the-platform).

The CA is created once per install and persists. On macOS, Go programs ignore
`SSL_CERT_FILE` and read the system keychain, so tools written in Go — `gh`
among them — need the CA trusted there. `stk init` prints the exact command.

## Prove it works before trusting it

```sh
stk doctor          # the setup, and that no credential is reachable by a child
stk doctor --probe  # that your clients actually go through the broker
```

The probe is the important one. It drives a real request through a real broker
at a hostname in the `.invalid` TLD, which can never resolve — so a client that
fails DNS has **proved** it bypassed the proxy rather than merely looked like it
might:

```
✓ curl               honoured    the provider received the substituted credential
✓ python3 urllib     honoured    the provider received the substituted credential
✓ node fetch         honoured    the provider received the substituted credential
✗ go net/http        refused-ca  it would not trust the broker's certificate
```

A client reported as `bypassed` must not be brokered. A client that *refuses the
certificate* is the safe case: the request does not happen, rather than
happening unbrokered.

## Uninstall

Delete the binary and the state directory `stk init` named. To withdraw the
credentials first, and as far as possible at the providers too:

```sh
stk revoke <service>
```
