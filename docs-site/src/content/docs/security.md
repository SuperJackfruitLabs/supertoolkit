---
title: Security model
description: What supertoolkit protects against, what it does not, and where the credential actually is.
---

## The invariant

> The agent never holds, reads, or receives a credential.

There is no endpoint that returns one — not for an agent, not for the CLI, not
for the web interface. A change that adds one is wrong regardless of how
convenient it would be.

## Where a credential lives

| | |
|---|---|
| **At rest** | AES-256-GCM, in an owner-only file in an owner-only directory. The key is derived with Argon2id from a passphrase held in the OS keychain where one exists. Ciphertext is padded, so the file's size does not report the credential's length. |
| **In memory** | Only in the broker, only while a request is in flight or a short-lived token is cached. |
| **On the wire** | Whatever the scheme requires — and for three of the five operations, never the long-lived secret. |
| **In the agent** | A placeholder, which means nothing off the host. |

The short-lived access token is cached on disk too, sealed with the same key and
bound to its own purpose, so one cannot be substituted for the credential that
minted it. It is there so that concurrent processes do not each exchange a
refresh token — which, against a provider that rotates, they would lose.

## What it protects against

- A credential reaching an agent's context, a transcript, or a log.
- An agent causing an irreversible effect on its own say-so.
- Not knowing afterwards what was done.
- A plaintext key in an MCP configuration file that any process can read.

## What it does not protect against

- **A client that ignores proxy configuration.** It goes around the broker and
  fails silently. Detect it from outside with `stk doctor --probe`, and do not
  broker a client it reports as `bypassed`.
- **An agent with a shell on the same machine.** It could run
  `stk approvals allow` itself, or read the store if it runs as the same user.
  Run the broker as its own OS user, and do not give the agent a shell there.
- **A host you chose to intercept behaving badly.** Interception's blast radius
  is exactly your configured service list; everything else is tunnelled
  unopened.
- **Reading the CA private key.** Anyone who can is able to impersonate the
  hosts this broker intercepts, which is the same reach as reading the
  credential store. Both are owner-only in an owner-only directory.
- **A platform with no keychain.** On Linux the store key is usually a file
  beside the ciphertext, which `stk doctor` reports as a warning. See
  [Limitations](/limitations/#the-store-key-is-only-as-good-as-the-platform).

## Failing closed

If the broker is unreachable, a client fails. It does not fall back to a direct
connection — a silent fall back is the worst outcome available, because it looks
like success while the credential is a worthless placeholder.

- A capability nobody has classified is treated as a write.
- A missing or misspelled policy resolves to `approval`, not `agent`.
- An unknown profile is an error rather than the default set.
- Expiry is never approval.
- A request that cannot be built is refused before anyone is asked to approve it.

## Reporting something

Report a suspected vulnerability **privately**: open the repository's
**Security** tab and choose **Report a vulnerability**. That creates an advisory
only the maintainers can see. Please do not open a public issue for one.

[SECURITY.md](https://github.com/SuperJackfruitLabs/supertoolkit/blob/main/SECURITY.md)
sets out what is in scope, and which behaviours are already documented
limitations rather than flaws.

For anything that is not a vulnerability,
[issues](https://github.com/SuperJackfruitLabs/supertoolkit/issues) are the
right place.
