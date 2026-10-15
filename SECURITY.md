# Security

supertoolkit exists to hold credentials that an agent must not have. A flaw
here is a flaw in the one thing it promises, so reports are genuinely welcome.

## Reporting a vulnerability

Please report security issues **privately**, through GitHub:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.

That opens a private advisory only the maintainers can see. Please don't open a
public issue or pull request for a suspected vulnerability.

A useful report includes the version (`stk version`), the platform, what you
did, what happened, and what you expected. If you have a proof of concept,
include it in the advisory.

You'll get an acknowledgement within a few days. Fixes are released as a new
patch version with a published advisory, and you'll be credited unless you'd
rather not be.

## Supported versions

supertoolkit is pre-1.0. Security fixes go into the latest release only, so
please upgrade to it before reporting.

## Scope

The parts where a flaw would matter most:

- **Anything that lets an agent obtain a credential.** The invariant is that it
  never holds, reads or receives one. A path that returns a credential to a
  caller — through the MCP tools, the daemon socket, the web interface, or a
  child's environment — is the most serious report you can make.
- **Credential substitution reaching the wrong host.** Interception is meant to
  be limited to the hosts your policy names; everything else is tunnelled
  unopened. A credential arriving somewhere policy did not send it is in scope.
- **The approval gate.** An effect at `approval` happening without a decision,
  an expired approval taking effect, or one effect being performed twice.
- **The audit ledger recording a credential**, in any form, for any scheme.
- **The sealed store and the CA private key.** Key derivation, the AEAD and its
  additional data, and the file permissions on both.
- **The web interface's one-time token** and anything that lets a request
  without it reach the API.

## Already known, and not a vulnerability

These are documented in [docs/limitations.md](docs/limitations.md). A report
about one of them is useful only if it shows the behaviour is worse than
recorded:

- **A client that ignores proxy configuration** goes around the broker and fails
  silently. Nothing inside a proxy can detect a client that never speaks to it;
  `stk doctor --probe` detects it from outside.
- **An agent with a shell on the same machine** can run `stk approvals allow`
  itself, or read the store if it runs as the same user. The gate protects
  against an agent confined to the tool surface it was given.
- **On Linux the store key is a file beside the ciphertext**, because there is
  usually no OS keychain. `stk doctor` reports this.
- **Brokered mTLS does not work** — 502, nothing sent.
