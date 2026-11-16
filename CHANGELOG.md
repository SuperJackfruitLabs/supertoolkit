# Changelog

Changes people will notice, newest first. Add an entry under `## Unreleased` with each such
change; before a tag, a release-prep PR runs `sh .github/release/prep-release.sh vX.Y.Z`, which
stamps the section `## vX.Y.Z — YYYY-MM-DD`, and the release notes quote it. Releases up to
v0.0.9 predate this file: their notes are on the GitHub releases.

## Unreleased

- SuperToolkit is now MIT-licensed, like most of the suite. It was Apache-2.0. Third-party notices
  stay in `NOTICE`.

## v0.0.10 — 2026-11-16

- The broker no longer presents an expired certificate after running for a day. Each host's
  certificate lasted 24 hours but was reused for the life of the process, so HTTPS through the
  broker failed with "certificate has expired" until it was restarted. It is now replaced an
  hour before it expires.
- Releases are built by the suite's shared release workflow: the forge's CI must have passed for
  the tag's commit, every archive comes with `SHA256SUMS` and a build-provenance attestation
  (`gh attestation verify <file> -R SuperJackfruitLabs/supertoolkit`), and the notes carry a
  summary, this section and the grouped commits. Install with
  `curl -fsSL https://supertoolkit.dev/install.sh | sh`, which verifies `SHA256SUMS`; read
  `docs/limitations.md` before trusting the broker with anything that matters, and run
  `stk doctor --probe` on the machine you intend to use it on.
