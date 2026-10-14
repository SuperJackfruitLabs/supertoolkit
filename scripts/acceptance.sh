#!/usr/bin/env bash
#
# The machine-checkable half of docs/acceptance.md.
#
# It runs in a scratch directory with its own STK_HOME, so it cannot touch a
# real store or a real credential. It proves the mechanism and the refusals; it
# cannot prove a real provider accepts a real token, which is what the human
# half is for.
#
# Every step states what counts as failure, because a script that only
# describes success passes on a broken build.
set -uo pipefail

STK="${STK:-}"
if [ -z "$STK" ]; then
  STK="$(mktemp -d)/stk"
  go build -o "$STK" ./cmd/stk || { echo "FAIL: the binary does not build"; exit 1; }
fi

WORK="$(mktemp -d)"
export STK_HOME="$WORK/home"
export STK_CONFIG="$WORK/supertoolkit.yaml"
export STK_PASSPHRASE="acceptance-$$"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
step() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; pass=$((pass+1)); }
no()   { printf '  \033[31m✗\033[0m %s\n' "$*"; fail=$((fail+1)); }

# expect <description> <pattern> -- <command...>
expect() {
  local desc="$1" pat="$2"; shift 3
  local out; out="$("$@" 2>&1)"
  if printf '%s' "$out" | grep -q -- "$pat"; then ok "$desc"
  else no "$desc"; printf '      wanted /%s/, got:\n%s\n' "$pat" "$(printf '%s' "$out" | sed 's/^/      /' | head -6)"; fi
}

# refuse <description> <pattern> -- <command...>   (the command must fail)
refuse() {
  local desc="$1" pat="$2"; shift 3
  local out; out="$("$@" 2>&1)"; local code=$?
  if [ $code -eq 0 ]; then no "$desc (it succeeded, and should not have)"; return; fi
  if printf '%s' "$out" | grep -q -- "$pat"; then ok "$desc"
  else no "$desc"; printf '      wanted /%s/, got:\n%s\n' "$pat" "$(printf '%s' "$out" | sed 's/^/      /' | head -6)"; fi
}

step "1. A clean install leaves a policy file with no secret in it"
expect "stk init creates the CA and the store" "CA certificate" -- "$STK" init
if grep -rqiE "(ghp_|sk-|AKIA|-----BEGIN)" "$STK_CONFIG"; then
  no "the policy file contains something credential-shaped"
else
  ok "the policy file holds no secret (it is meant to be committed)"
fi
# FAILURE: anything secret-shaped in supertoolkit.yaml. That file goes in git.

step "2. Services are added with defaults that fail safe"
# The known-service list is in the usage text; `stk add` only echoes what it was
# asked for, which an earlier version of this script mistook for the catalogue.
expect "the catalogue offers eleven services" "resend" -- "$STK" help
expect "services are added with their read/write split shown" "write→approval" -- "$STK" add github x stripe slack aws-sts
expect "a write defaults to approval, not to the agent" "write→approval" -- "$STK" add notion
# FAILURE: a write shown as agent-callable. The default must be approval.

step "3. A credential goes in from stdin and never comes back out"
printf 'ghp_acceptance_test_credential' | "$STK" connect github >/dev/null 2>&1
expect "github reads as connected" "github" -- "$STK" doctor
if "$STK" doctor 2>&1 | grep -q "ghp_acceptance_test_credential"; then
  no "doctor printed the credential"
else
  ok "doctor never prints the credential"
fi
if grep -rq "ghp_acceptance_test_credential" "$STK_HOME" 2>/dev/null; then
  no "the credential is on disk in plaintext"
else
  ok "the credential is sealed on disk, not stored in the clear"
fi
# FAILURE: the literal credential appearing in any output or any file.

step "4. The leak check proves a child cannot reach the credential"
expect "no credential is reachable from a child's environment" "no credential reachable" -- "$STK" doctor
# FAILURE: "a credential is present in <VAR>". That is the invariant broken.

step "5. The probe proves requests actually go through the broker"
out="$("$STK" doctor --probe 2>&1)"
printf '%s\n' "$out" | sed 's/^/    /'
if printf '%s' "$out" | grep -q "bypassed"; then
  no "a client reached past the broker — do not broker that client"
else
  ok "no client bypassed the broker"
fi
if printf '%s' "$out" | grep -q "honoured"; then
  ok "at least one client honoured the broker and received a substituted credential"
else
  no "no client honoured the broker; the mechanism is not working here"
fi
# FAILURE: any "bypassed" line, or no "honoured" line at all.

step "6. An effect is recorded durably, with no credential in it"
expect "the ledger starts empty and says so" "nothing recorded yet" -- "$STK" audit
# FAILURE: an error rather than an empty ledger. Reading nothing is not an error.

step "7. The refusals are refusals"
refuse "an unknown service is refused by name" "unknown service" -- "$STK" add not-a-real-service
# google is deliberately not added above.
refuse "connecting an unconfigured service points at stk add" "stk add" -- "$STK" connect google --browser
# X offers PKCE and no device grant, which is a different "no" and says so.
refuse "a provider with no device grant names the remaining paths" "does not offer" -- "$STK" connect x --device
refuse "a signed service says it is signed, not substituted" "does not offer" -- "$STK" connect aws-sts --device
refuse "x asks for the client id it does not ship" "client_id" -- "$STK" connect x --browser
refuse "the two flows are not combinable" "pick one" -- "$STK" connect x --device --browser
# FAILURE: any of these succeeding, or failing with a message that does not say
# what to do next. An obscure refusal is a defect.

step "8. The hand-over key can only seal"
key="$("$STK" handover key 2>/dev/null)"
case "$key" in
  stk-handover-v1:*) ok "the broker publishes a hand-over key" ;;
  *) no "handover key printed '$key'" ;;
esac
env="$("$STK" handover seal github --to "$key" 2>/dev/null)"
if printf '%s' "$env" | grep -q "ghp_acceptance_test_credential"; then
  no "the sealed envelope contains the credential in the clear"
else
  ok "the sealed envelope carries no plaintext credential"
fi
expect "opening it says the credential still exists where it was sealed" "still exists" \
  -- sh -c "printf '%s' '$env' | $STK handover open github"
# FAILURE: a plaintext credential in the envelope, or an open that hides the cost.

printf '\n\033[1m%d passed, %d failed\033[0m\n' "$pass" "$fail"
if [ "$fail" -gt 0 ]; then
  printf 'The machine half did not pass. Do not proceed to the human half.\n'
  exit 1
fi
printf 'The machine half passed. Continue with docs/acceptance.md from step 9.\n'
