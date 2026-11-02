# Review instructions

Claude reads this file from the base branch when it reviews a pull request here. The review is
advisory: it never approves, blocks or requests changes. A person decides.

## How to review

Make three passes over the diff, and tag every finding with the pass that found it.

1. **Bugs.** Behaviour that is wrong: logic errors, broken edge cases, races, resource leaks,
   error paths that lose the error, a test that cannot fail.
2. **Security.** Secrets or personal data written to logs, files or responses; injection;
   missing authentication or authorisation; untrusted input reaching a shell, a query or a
   path; a weakened check.
3. **Compliance.** The rules in the files listed under "Rule files" below, and the pull
   request's own stated plan: does the diff do what its description says, and nothing it does
   not mention?

## Severity

- **important:** only for a finding that breaks behaviour, leaks data, or breaches a written
  policy. Say which.
- **moderate:** a real problem that does not reach that bar.
- **nit:** style, naming, wording. Report at most five; the rest are counted, not listed.

A finding names the file and line and says what to do. Prefer no finding to a weak one.

## Do not report

- Anything in the paths under "Generated paths", or in lockfiles.
- What CI already enforces: formatting, the lint ratchet, the architecture and file-size tests.
- Matters of taste the rule files do not settle.

## Rule files

- `AGENTS.md`
- `docs/code-quality.md`
- `SECURITY.md`

## Generated paths

- `internal/webui/build/**`
- `**/vendor/**`

## What matters most here

- The invariant: the agent never holds, reads or receives a credential. Any path that returns one is important.
- Never log a secret; the audit record carries fingerprints. Fail closed, never direct.
- Injection is credential-scheme aware, HTTP/2 trailers propagate, acquisitions are single-flight.
