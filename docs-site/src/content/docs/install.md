---
title: Install
description: Build supertoolkit from source and stand up a broker.
---

supertoolkit is a single Go binary, `stk`. It runs on your own machine.

## From source

```sh
git clone https://github.com/SuperJackfruitLabs/supertoolkit
cd supertoolkit
go build -o stk ./cmd/stk
```

Go 1.21 or newer. There is nothing else to install: the web interface is
embedded in the binary.

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
