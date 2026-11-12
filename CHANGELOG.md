# Changelog

Changes people will notice, newest first. Add an entry under `## Unreleased` with each such
change; before a tag, a release-prep PR runs `sh .github/release/prep-release.sh vX.Y.Z`, which
stamps the section `## vX.Y.Z — YYYY-MM-DD`, and the release notes quote it. Releases up to
v0.0.9 predate this file: their notes are on the GitHub releases.

## Unreleased

- Releases are built by the suite's shared release workflow: the forge's CI must have passed for
  the tag's commit, every archive comes with `SHA256SUMS` and a build-provenance attestation
  (`gh attestation verify <file> -R SuperJackfruitLabs/supertoolkit`), and the notes carry a
  summary, this section and the grouped commits.
