#!/usr/bin/env bash
# Deploy one commit of supertoolkit to the staging plane (workbench), as root.
#
# CI runs it on every push to main: `ssh root@workbench supertoolkit <sha>`, forced to estate's
# staging-deploy (provision/301), which runs this file *from that commit*. By hand:
#   ssh workbench 'staging-deploy-run() { SSH_ORIGINAL_COMMAND="supertoolkit <sha>" /usr/local/sbin/staging-deploy; }; staging-deploy-run'
#
# Host prerequisites are estate provision/305-stk-host.sh: the `stk` user and group, salaam in
# that group, /var/lib/stk, /etc/stk, the GitHub CLI and the checkout this reads.
#
# Steps: build in a container (nothing Go on the host) -> install the binary -> `stk install`
# (stk's own installer; idempotent) -> policy from this commit -> `stk init` once -> connect the
# GitHub token if the operator placed one -> restart the broker -> write Salaam's client settings
# and gh wrapper -> smoke.
#
# Nothing here prints a credential. The token file is fed to `stk connect` on stdin and deleted.
set -euo pipefail

sha="${1:?usage: deploy.sh <sha>}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "deploy.sh: want a 40-hex sha" >&2; exit 2; }
repo=/opt/suite-staging/supertoolkit
bin=/opt/suite-staging/supertoolkit-bin
token=/opt/suite-staging/env/stk/gh-token
agent=salaam
H=/home/$agent
GO_IMAGE=golang:1.26-bookworm

as_stk() {
  runuser -u stk -- env -i PATH=/usr/local/bin:/usr/bin:/bin STK_HOME=/var/lib/stk \
    STK_CONFIG=/etc/stk/supertoolkit.yaml STK_SOCKET=/run/stk/stk.sock \
    STK_PASSPHRASE_FILE=/var/lib/stk/stk-passphrase.key "$@"
}

echo "== build ${sha:0:12}"
version="0.0.4-dev+${sha:0:12}"
src=$(mktemp -d); trap 'rm -rf "$src"' EXIT
git -C "$repo" archive "$sha" | tar -x -C "$src"
docker run --rm -v "$src:/src" -v stk-gomod:/go/pkg/mod -v stk-gocache:/root/.cache/go-build \
  -w /src -e CGO_ENABLED=0 "$GO_IMAGE" \
  go build -trimpath -ldflags "-s -w -X main.version=$version" -o /src/stk ./cmd/stk
install -d -m 755 "$bin"
install -m 755 "$src/stk" "$bin/stk-${sha:0:12}"
ln -sfn "$bin/stk-${sha:0:12}" /usr/local/bin/stk.new && mv -T /usr/local/bin/stk.new /usr/local/bin/stk
ls -1t "$bin"/stk-* | tail -n +6 | xargs -r rm -f   # keep the last five builds
echo "   $(/usr/local/bin/stk version)"

echo "== install"
/usr/local/bin/stk install --user stk --group stk --agent-uid "$(id -u $agent)" | sed 's/^/   /'
install -m 640 -o root -g stk "$src/deploy/staging/supertoolkit.yaml" /etc/stk/supertoolkit.yaml
[ -f /var/lib/stk/ca.pem ] || as_stk /usr/local/bin/stk init | sed 's/^/   /'
# The CA certificate is public; the agent needs it to trust the broker. Its key stays in 0700.
install -m 644 -o root -g root /var/lib/stk/ca.pem /etc/stk/ca.pem

if [ -f "$token" ]; then
  echo "== connect github-public (from the operator's token file, on stdin)"
  as_stk /usr/local/bin/stk connect github-public < "$token" >/dev/null
  shred -u "$token" 2>/dev/null || rm -f "$token"
  echo "   connected; $token removed"
fi

echo "== broker"
systemctl daemon-reload
systemctl enable -q stk
systemctl restart stk
for _ in $(seq 20); do [ -S /run/stk/stk.sock ] && break; sleep 0.5; done
systemctl is-active --quiet stk
echo "   stk.service active, socket $(stat -c '%a %U:%G' /run/stk/stk.sock)"

echo "== client settings for $agent"
# `stk env` checks the proxy is live before printing its key. The key gates use of the broker
# and unlocks no secret; the service variables are placeholders.
envfile=$(mktemp)
for _ in $(seq 20); do as_stk /usr/local/bin/stk env > "$envfile" 2>/dev/null && break; sleep 0.5; done
[ -s "$envfile" ] || { echo "stk env produced nothing"; exit 1; }
sed -i 's#/var/lib/stk/ca.pem#/etc/stk/ca.pem#g' "$envfile"
if grep -qE 'github_pat_|ghp_|gho_|ghs_' "$envfile"; then echo "stk env printed a token"; exit 1; fi
install -d -o $agent -g $agent -m 700 "$H/.config/stk"
install -m 600 -o $agent -g $agent "$envfile" "$H/.config/stk/env"
rm -f "$envfile"
install -d -o $agent -g $agent -m 755 "$H/.local/bin"
cat > "$H/.local/bin/gh.new" <<'EOF'
#!/bin/sh
# Written by supertoolkit deploy/staging/deploy.sh. gh, through the stk broker: the proxy, its CA
# and a placeholder GH_TOKEN. The real token never reaches this process; the broker attaches it.
set -a
. /home/salaam/.config/stk/env
set +a
export GH_HOST=github.com GH_NO_UPDATE_NOTIFIER=1 GH_PROMPT_DISABLED=1
unset GITHUB_TOKEN GH_ENTERPRISE_TOKEN
exec /usr/local/lib/gh/bin/gh "$@"
EOF
chown $agent:$agent "$H/.local/bin/gh.new" && chmod 755 "$H/.local/bin/gh.new"
mv -T "$H/.local/bin/gh.new" "$H/.local/bin/gh"
echo "   $H/.config/stk/env (600), $H/.local/bin/gh -> stk"

# A systemd --user manager started before salaam joined the stk group does not have it.
uid=$(id -u $agent)
if ! grep -q "^Groups:.* $(getent group stk | cut -d: -f3)\b" /proc/"$(systemctl show -p MainPID --value user@$uid)"/status 2>/dev/null; then
  echo "   restarting user@$uid so salaam's session has the stk group"
  systemctl restart user@$uid
fi

echo "== smoke"
doc=$(as_stk /usr/local/bin/stk doctor --agent-uid "$uid" 2>&1 || true)
printf '%s\n' "$doc" | grep -E '✓|✗' | sed 's/^/   /'
printf '%s\n' "$doc" | grep -q 'isolation  separate-user' || { echo "isolation is not separate-user"; exit 1; }
# Two failures are expected here and are not faults: doctor wants the socket 0600, but
# `stk install --group` makes it 0660 on purpose (the uid allowlist is the authorisation), and
# the credential is missing until the operator places the token.
bad=$(printf '%s\n' "$doc" | grep '✗' | grep -v -e 'daemon socket .* mode 660' -e 'credential for github-public  missing' || true)
[ -z "$bad" ] || { echo "doctor failed:"; printf '%s\n' "$bad"; exit 1; }
# The agent can reach the socket, and cannot read the broker's state.
runuser -u $agent -- test -w /run/stk/stk.sock || { echo "$agent cannot reach the socket"; exit 1; }
if runuser -u $agent -- ls /var/lib/stk >/dev/null 2>&1; then echo "$agent can read /var/lib/stk"; exit 1; fi
# A request outside policy is refused by the broker, recorded, and nothing goes to GitHub.
code=$(runuser -u $agent -- "$H/.local/bin/gh" api -X POST repos/SuperJackfruitLabs/agentpod/issues \
  -f title=smoke 2>&1 | grep -oE 'HTTP [0-9]+' | head -1 || true)
echo "   gh write through the broker: ${code:-no status}"
[ "$code" = "HTTP 403" ] || { echo "expected the broker to refuse a write with 403"; exit 1; }
if as_stk /usr/local/bin/stk verify github-public >/dev/null 2>&1; then
  echo "   verify github-public: ok"
  runuser -u $agent -- "$H/.local/bin/gh" api repos/SuperJackfruitLabs/agentpod -q .full_name | sed 's/^/   gh read through the broker: /'
else
  echo "   github-public has no credential yet (operator places $token, then redeploy)"
fi
as_stk /usr/local/bin/stk audit --limit 3 | sed 's/^/   /'
echo "deployed supertoolkit ${sha:0:12}"
