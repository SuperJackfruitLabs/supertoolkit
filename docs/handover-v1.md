# Hand-over envelope, version 1

**Status: frozen.** A change to anything below is a new version (`stk-handover-v2:`),
and a broker keeps accepting v1 for as long as v1 envelopes exist in the wild.
agentpod's CLI and console implement this independently, so the format is
specified here, with a conformance vector, rather than left to the Go code.

## What it is for

Moving a credential to a broker that cannot fetch it itself, through anything
that must not be able to read it: a hub, a chat message, a paste buffer. Only the
broker's private key opens an envelope.

## The broker's public key

```
stk-handover-v1:<base64url-nopad of 32 bytes>
```

The 32 bytes are an X25519 public key. `stk handover key` prints it; the private
half never leaves the broker's state directory.

## The envelope

```
stk-handover-v1:<base64url-nopad of sealed-box bytes>
```

The bytes are a libsodium **`crypto_box_seal`** output for the broker's public
key:

- an ephemeral X25519 public key (32 bytes), then
- the XSalsa20-Poly1305 box of the plaintext, nonce
  `BLAKE2b-192(ephemeral_pk || recipient_pk)`.

Go's `golang.org/x/crypto/nacl/box.SealAnonymous` and libsodium's
`crypto_box_seal` produce and open the same bytes. In JavaScript use
`libsodium-wrappers` `crypto_box_seal` / `crypto_box_seal_open`.

## The plaintext

A JSON object whose keys are credential field names and whose values are strings:

```json
{"token": "…"}
```

A service names its fields (`token` for most; `app_id`, `installation_id` and
`private_key` for a GitHub App). An envelope with no fields, or with a missing
required field, is refused when opened.

## Rules for implementers

- Base64url **without padding**, both in the key and the envelope.
- Sealing is anonymous: the envelope names neither sender nor recipient.
- Seal with a fresh ephemeral key every time. Two seals of the same material
  must differ.
- Never log, store or display the plaintext, and never put it in a URL.
- Opening a tampered envelope fails; there is no partial result.

## Conformance vector

`testdata/handover-v1.json` holds a fixture keypair (it protects nothing), a
material, and an envelope sealed to it. An implementation conforms when it:

1. derives the recorded `public_key` from the recorded `private_key`,
2. opens the recorded `envelope` to the recorded `material`, and
3. produces envelopes that the Go code opens (`TestVectorKeyOpensAFreshSeal`).
