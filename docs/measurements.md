# Measurements

Three roadmap items read "untested" or "unproven". A measurement replaces an
assumption or it is not worth taking, so each one closes here with a number and
the machine it came from — a benchmark without its machine is a rumour.

Reproduce with `go test ./e2e/ -run Measure -v`.

**Machine:** darwin/arm64, 8 CPUs, go1.26.4. Taken 2026-10-15.
Every figure is against a **local** upstream on loopback, which is the point: it
isolates the broker's own cost from the network's.

---

## 1. Bodies above 64 KB — transparent

The roadmap called this "unproven rather than broken": the proxy was transparent
at every size tested, but no endpoint had ever accepted a large upload. X's
media `APPEND` is multipart with segments up to 5 MB, so this is load-bearing
for publishing work rather than theoretical.

A random body is sent through the broker and hashed at both ends.

| Size | Bytes received | SHA-256 matches | Credential |
|---|---|---|---|
| 1 B | 1 | yes | substituted |
| 64 KB | 65,536 | yes | substituted |
| 1 MB | 1,048,576 | yes | substituted |
| 8 MB | 8,388,608 | yes | substituted |

**Finding: transparent at every size, and the credential is still substituted.**
The substitution happens on headers, so the risk was a buffering bug reordering
it; the test asserts the upstream saw the real credential at 8 MB as well as at
1 byte. Nothing above 8 MB has been tried, and nothing in the implementation
buffers a whole body, so the next limit is the provider's.

One note for whoever reads the test: an earlier run reported the credential as
`"Bearer"` and looked like a real defect. That was `%s` in `fmt.Sscanf` stopping
at the space inside the header value — a measurement artifact, the fourth of its
kind in this project. The upstream now answers tab-separated.

## 2. Brokered mTLS — does not work, and says so

The roadmap said "untested", which is not the same as broken.

An upstream demanding `RequireAndVerifyClientCert` was placed behind the broker.

**Finding: the broker returns 502 and the client sees the failure.** The
upstream's log reads `tls: client didn't provide a certificate`; the client
receives `supertoolkit: upstream unreachable`. The broker holds no client
certificate, so it cannot complete the handshake on the operator's behalf.

This is the **safe** class of failure: loud, immediate, and nothing was sent. It
is not fixed by configuration. A host requiring mTLS should be **tunnelled**
rather than brokered — remove it from `services` and the broker passes its
traffic through unopened, with the client's own certificate intact. Brokering it
would need a client certificate per service in the store, which is a feature and
not a bug fix.

## 3. Latency — 79 µs median overhead

The repository is about to claim speed in public, and the broker's overhead had
never been isolated. 300 requests after a 10-request warm-up, so the CONNECT and
the TLS handshake are not counted as steady state — measuring those once as if
they were is how a proxy gets blamed for a handshake.

| Path | Median | p99 |
|---|---|---|
| Direct to upstream | 56 µs | 95 µs |
| Through the broker | 135 µs | 554 µs |
| **Overhead** | **79 µs** | **459 µs** |

**Finding: about 79 µs at the median, 459 µs at the 99th percentile.** For
scale, a single packet round-trip to a provider in another region is 20–150 ms —
between 250 and 1,900 times the median overhead. The broker's cost is below the
noise of any real network, which is what "fast" has to mean for a thing that
sits in front of an API call.

The p99 is six times the median, which is the cost of the broker being a second
Go runtime scheduling point rather than anything structural. It has not been
chased, because 459 µs is still a rounding error against a real request.

The test asserts only that the brokered median stays within an order of
magnitude of the direct one. A regression past that is a design change, not a
slow afternoon.
