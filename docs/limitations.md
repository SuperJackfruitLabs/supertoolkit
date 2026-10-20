# Limitations

What supertoolkit does not do, and why. Each entry is a decision or a
measurement, not a shrug — and the ones that are decisions say what they would
cost to change.

Read this before trusting the broker with something that matters.

---

## The one failure mode that cannot be fixed

**A client that ignores proxy configuration entirely goes around the broker, and
fails silently.**

This is the only limitation on this page that is not recoverable by design. Such
a client sends the worthless placeholder to the provider, gets a plausible 401
back, and the error reads as a credential problem rather than a routing one. The
Phase 0 spikes found two: a Go program that builds its own `http.Transport`
without `ProxyFromEnvironment`, and Node's default `fetch` before
`NODE_USE_ENV_PROXY` existed.

Nothing in a proxy can detect a client that never speaks to it. What can be done
is detect it from outside, which is what `stk doctor --probe` is for:

```
$ stk doctor --probe
  ✓ curl               honoured    the provider received the substituted credential
  ✓ python3 urllib     honoured    the provider received the substituted credential
  ✓ node fetch         honoured    the provider received the substituted credential
  ✗ go net/http        refused-ca  it would not trust the broker's certificate
```

The probe drives a real request through a real broker at a hostname in the
`.invalid` TLD, which RFC 2606 guarantees will never resolve. A client that
honours the proxy resolves nothing — it asks the broker for the host by name. A
client that ignores the proxy must resolve it itself and cannot. A DNS failure
is therefore **proof** of a bypass, not a guess.

**Run the probe before trusting a new client.** A client it reports as
`bypassed` must not be brokered. The command exits non-zero on `bypassed` or
`failed`, and `--json` gives a machine-readable list.

### The safe class, by contrast

A client that *rejects the broker's certificate* fails **loudly**: the request
does not happen. That is the right failure. On macOS, Go programs ignore
`SSL_CERT_FILE` and use the system keychain, so `gh` and similar need the CA
trusted there — `stk init` prints the command. Everywhere else `stk run` sets the
trust store and it just works.

---

## Measured, and recorded as facts

Full numbers and the machine they came from: [measurements.md](measurements.md).

- **Brokered mTLS does not work.** An upstream requiring a client certificate
  gets a 502 — loud, immediate, nothing sent. The broker holds no client
  certificate. Tunnel that host instead of brokering it, where its own
  certificate stays intact. Changing this means a client certificate per service
  in the store, which is a feature.
- **Bodies are transparent to at least 8 MB**, hashes matching end to end, with
  the credential still substituted. Nothing buffers a whole body, so the next
  limit is the provider's.
- **Overhead is about 79 µs at the median**, 459 µs at p99, against 56 µs
  direct. A cross-region round trip is 250 to 1,900 times that.

---

## Protocol limits

### WebSocket and other upgrades: refused, not broken

A credential is substituted on an HTTP request, and an upgraded connection
carries no further HTTP requests to substitute into. The broker returns **501**
with an explanation rather than appearing to succeed and then hanging, which is
what it used to do and reads as the provider's fault.

Tunnel the host instead: remove it from `services` and its traffic passes
through unopened. The connection works and carries whatever credential the
client itself holds — the trade this product otherwise exists to avoid.

### Non-HTTP protocols are out of scope

Postgres, MySQL, Redis, Kafka, SMTP, IMAP. A CONNECT proxy cannot inject into a
Postgres handshake; these need a protocol-aware local proxy per protocol, which
is a second product shape rather than a missing afternoon. A tunnelled host
passes them through untouched today, unbrokered.

### GraphQL APIs do not fit the catalogue

Every call is `POST /graphql` and the operation lives in the body, so a method
and a path cannot tell one capability from another. Policy could not name what
it was allowing and the audit ledger could not say what happened — which is
worse than not supporting it. Linear was dropped from the launch catalogue for
exactly this, and a test
(`TestNoTwoCapabilitiesAreIndistinguishableOnTheWire`) now fails any entry with
that shape.

Supporting GraphQL means dispatching on the operation name inside the body,
which is a real design with real ambiguities (aliases, batched operations,
fragments). It is not hard; it is simply not done.

---

## Deliberately out of scope

Each of these is a product-shape decision. None is blocked; none is started.

| Not done | Why not |
|---|---|
| **Inbound webhooks** | Receiving and verifying provider events is half of what an integration platform does, and all of it is a new surface with a different security posture — a public listener instead of an outbound proxy |
| **Connectors as pinned binaries** | `connector-protocol/v1` is already specified. It earns its place when a service needs code we have to ship, which no service in the catalogue does |
| **Identity chaining** | ID-JAG and RFC 8693 against whichever issuer a deployment has. This is the step that makes it a platform rather than a utility, and the drafts are still moving — better to follow the RFC than predict it |
| **vsock transport** | For microsandboxes with no filesystem shared with the host. Needs a guest-side shim, because `curl` cannot speak AF_VSOCK. The net-rule path works today |
| **OAuth 1.0a** | Built for, then dropped. X is the only provider in the catalogue that offers it, recommends OAuth 2.0 instead, and does not support 1.0a for media upload at all — so it could not post an image. Nothing shipped needs it |

---

## The store key is only as good as the platform

**On Linux there is usually no OS keychain, so the key that encrypts your
credentials sits in a file beside the ciphertext.** Anything that can read one
can read the other, and the encryption then protects against a stolen disk
rather than against another process running as the same user.

`stk doctor` says so rather than hiding it:

```
! credential store key  file beside the ciphertext — anything that can read one
                        file can read the other; an OS keychain is not wired on
                        this platform
```

On macOS the key comes from the login keychain and this warning does not
appear. The difference matters most where it is least visible: a production
token on a server is less well protected than the same token on a laptop, which
is the opposite of what most people would assume.

What you can do today:

- `STK_PASSPHRASE` in the broker's environment takes precedence over the file,
  so a key held by your init system — systemd `LoadCredential`, a secrets
  manager, a prompt at start — never touches the disk.
- Run the broker as its own OS user with a `0700` home, which is the posture
  the design assumes anyway.
- Treat a VPS credential as narrower in scope than a laptop one: shorter-lived,
  fewer scopes, and revoked on suspicion rather than on proof.

What would close it properly is wiring a Linux keyring — libsecret or the
kernel keyring — which is a platform integration rather than a fix, and is not
done.

## Operational limits

- **`stk run`'s per-session loopback proxy is not authenticated.** Only the
  fixed proxy of `stk serve --proxy-listen` requires a proxy key. Any local
  process that finds a `stk run` session's port can use the routes that session
  allows, though it still receives no credential.

- **The audit ledger rotates at 8 MB, keeping one generation.** An unbounded
  audit log on a small VPS is an outage. If you need more history, ship
  `audit.log` somewhere before it rotates.
- **One client id per service, in the committed policy file.** supertoolkit
  ships none: a shared client id would make every installation look like the
  same app to the provider. You register your own.
- **The OAuth redirect must be a loopback URL.** The broker listens for the
  redirect itself, so a callback pointing anywhere else never reaches the
  machine — and one reachable from the network would let anybody on it deliver
  a code there. `127.0.0.1` and `localhost` both work, on any port and path.
  The default is `http://127.0.0.1:7837/callback`; an app that is already
  registered with a different loopback callback names it under
  `oauth2.redirect_uri` rather than being edited to suit us.
- **A credential's rotation is written back before the access token is
  returned.** If that write fails, the connect fails loudly — the alternative is
  a lockout hours later, nowhere near its cause.
- **`stk handover` briefly puts the credential on the sealing machine.** The
  commands say so. The device grant and the web UI do not have that property, so
  prefer them when either is possible.

## Shared refresh ownership

On supported macOS and Linux hosts, token acquisition uses a stable OS-owned file
lock. Process death releases it; elapsed time does not prove an owner died. Cache
invalidation preserves lock files. If ownership or cache persistence is unavailable,
acquisition fails explicitly instead of racing another refresh or returning an
unpersisted access token. No additional refresh retries are introduced.

Stop older broker processes before updating a store to this lock format. Known
live old-format owners are refused, but concurrent old and new broker binaries
sharing one store are not a supported migration. Do not remove a live cache lock
file to bypass a refusal. Managed profiles must pin their broker version and
account for old owned processes during upgrade and recovery.
