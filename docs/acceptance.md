# Acceptance test

The test is a person on a machine with a real credential, because every
automated test in this repository shares our assumptions.

Two halves. The machine half is a script and proves the mechanism and the
refusals. The human half needs a real provider, a real browser and a real
decision, and it is the only thing that can prove the product works.

**Every step says what counts as a failure, not only what success looks like.**
A script that describes only success passes on a broken build.

---

## The machine half

```
./scripts/acceptance.sh
```

It runs in a scratch directory with its own `STK_HOME`, so it cannot touch a
real store or a real credential. It covers eight areas:

1. A clean install leaves a policy file with nothing secret in it
2. Services are added with defaults that fail safe
3. A credential goes in from stdin and never comes back out
4. The leak check proves a child cannot reach the credential
5. **The probe proves requests actually go through the broker**
6. The ledger reads as empty rather than erroring
7. The refusals are refusals, and each says what to do next
8. The hand-over key can only seal

**Last run:** 2026-10-15, darwin/arm64 — **21 passed, 0 failed.** The probe
reported `curl`, `python3` and `node` honoured, and `go net/http` as
`refused-ca`, which is the expected macOS result: Go ignores `SSL_CERT_FILE`
there and uses the system keychain. That is the loud, safe class.

**Failure:** any failed step. Do not continue to the human half — a mechanism
that cannot pass its own checks will waste a real credential.

---

## The human half

You need: a machine, a terminal, a browser, and one real credential you are
willing to use. Fifteen minutes.

Work in a scratch directory so nothing here touches your real setup:

```
mkdir ~/stk-acceptance && cd ~/stk-acceptance
export STK_HOME=$PWD/home
go build -o ./stk /path/to/supertoolkit/cmd/stk
```

### Step 9 — install, and read what it tells you

```
./stk init
```

**Expect:** a CA path, a store key source, and a `supertoolkit.yaml`. On macOS it
also prints the `security add-trusted-cert` command for Go clients.

**Failure:** it does not say where the store key came from. You cannot judge how
well a credential is protected without knowing whether the key is in the
keychain or in a file beside it.

### Step 10 — connect GitHub with a real token

Make a classic token with `repo` scope at
https://github.com/settings/tokens, then:

```
./stk add github
pbpaste | ./stk connect github        # or: cat | ./stk connect github
```

**Expect:** `github connected · substitute (token)`, the number of fields sealed,
and a line saying it is never in `supertoolkit.yaml`.

**Failure:** the token appearing anywhere in the output; or the command accepting
a token as an argument. It must read stdin only — a flag lands in shell history
and in the process table.

### Step 11 — the moment the product either works or does not

```
./stk run -- gh api user
```

(Or, if `gh` is not installed:
`./stk run -- curl -s https://api.github.com/user | head -5`)

**Expect:** your own GitHub account. The child process had
`GH_TOKEN=stk:ref:github:v1` and nothing else.

**Failure, and the one that matters most:** a 401. That means the placeholder
reached GitHub unsubstituted. Run `./stk doctor --probe` and read which client
is listed as `bypassed` or `refused-ca`. On macOS, `gh` is a Go program and will
need the CA in the keychain — the command `stk init` printed.

**Also a failure:** it works, but `echo $GH_TOKEN` in your own shell shows a real
token. The agent's environment must carry the placeholder.

### Step 12 — confirm the credential was never in reach

```
./stk doctor
```

**Expect:** `no credential reachable from a child's environment (N checked)`.

**Failure:** `a credential is present in <VAR>`. That is the invariant broken and
nothing else in this test matters until it is fixed.

### Step 13 — the audit answers the question

```
./stk audit
```

**Expect:** the request from step 11, with the capability named `get_user` — not
`GET /user` — the policy that applied, the status, and a **fingerprint** where
the credential would be.

**Failure:** an empty ledger after a successful request; the capability reading
`(not in the catalogue)`; or your token appearing in any form. Then:

```
grep -r "<the first 8 characters of your token>" $STK_HOME
```

**Failure:** any match outside the sealed `.cred` files.

### Step 14 — an approval stops something happening

```
./stk mcp install claude      # prints config; add it to your client
```

Then ask your agent to open an issue on a repository you own.

**Expect:** the agent reports `state: pending` and an id. **No issue exists
yet.** Check the repository.

```
./stk approvals
./stk approvals refuse <id>
```

**Expect:** the agent is told it was not approved and nothing was done. The
repository still has no issue.

**Failure, and the most serious one on this page:** the issue exists before you
approved it. A write that happens on an agent's say-so is the thing this product
exists to prevent.

Now repeat and `allow` it. **Expect:** the issue appears, with the title the
agent asked for. **Failure:** the issue appears with no title or an empty body —
that was a real bug in Phase 1 (a required parameter that the request model
dropped silently), and this step is how it would have been caught.

### Step 15 — connect X, which needs a browser

This is the step that proves the OAuth 2.0 path, and the one most likely to
surface a provider's own quirks.

1. Create an app at https://developer.x.com, with **OAuth 2.0** enabled
2. Set the redirect URI to exactly `http://127.0.0.1:7837/callback`
3. Request scopes `tweet.read tweet.write users.read media.write offline.access`
4. Put the client id in `supertoolkit.yaml`:

```yaml
services:
  x:
    oauth2:
      client_id: <your app's client id>
```

```
./stk add x
./stk connect x --browser        # paste the client secret, then ctrl-D
```

**Expect:** a browser opens to X; you approve; the terminal says `x connected`
and that the refresh token is stored while the access token is not.

**Failure:** `returned no refresh token` — your app did not grant
`offline.access`, and a connection that cannot refresh itself dies in two hours.
Fix the app rather than working around it.

**Failure:** a redirect mismatch. The URI must match character for character,
including the port.

### Step 16 — post something, with your approval

Ask your agent to post. **Expect:** `pending`, and nothing on your timeline.
Approve it. **Expect:** the post appears.

**Failure:** anything on your timeline before you approved.

### Step 17 — the headless path, on a machine with no browser

If you have a VPS, this is the step worth the most:

```
ssh your-vps
# install stk, then
stk add github && stk connect github --device
```

**Expect:** a short code and a URL, printed and sent to any webhook you
configured. You approve it on your phone. The token arrives **on the VPS**,
having never touched your laptop.

**Failure:** the device code appearing in the output. The user code may be shown
— it is useless without you — but the device code is what the poll redeems.

**Failure:** it polls at the same rate after the provider says `slow_down`. You
will see rate-limiting at the exact moment you are trying to help it.

### Step 18 — break it on purpose

```
# Point the proxy at nothing and confirm the client fails rather than going direct
HTTPS_PROXY=http://127.0.0.1:1 gh api user
```

**Expect:** a connection failure.

**Failure:** your GitHub account. A client that silently goes direct when the
broker is down is the worst outcome available, because it looks like success.

---

## Reporting

For each step: the number, pass or fail, and for a failure the exact output.
`./stk doctor --probe` output is worth attaching whatever happens — it is the
one thing that differs most between machines.
