#!/usr/bin/env bash
# Deploy one commit of supertoolkit to the staging plane (workbench), as root.
#
# CI runs it on every push to main: `ssh root@workbench supertoolkit <sha>`, forced to estate's
# staging-deploy (provision/301), which runs this file *from that commit*.
#
# Host prerequisites are estate provision/305-stk-host.sh: the `stk` user and group, salaam in
# that group, /var/lib/stk, /etc/stk and the checkout this reads.
#
# Steps: build in a container (nothing Go on the host) -> install the binary -> `stk install`
# (stk's own installer; idempotent) -> policy from this commit -> `stk init` once -> restart the
# broker -> write Salaam's client settings and its git wrapper -> smoke.
#
# Staging holds no credential at all: the one service, git-public, is `auth: none` (policy and
# audit only). Nothing here prints a secret; the proxy key goes only into Salaam's 0600 env file.
set -euo pipefail

sha="${1:?usage: deploy.sh <sha>}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "deploy.sh: want a 40-hex sha" >&2; exit 2; }
repo=/opt/suite-staging/supertoolkit
bin=/opt/suite-staging/supertoolkit-bin
agent=salaam
H=/home/$agent
GO_IMAGE=golang:1.26-bookworm
REPO_URL=https://github.com/SuperJackfruitLabs/agentpod.git

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

echo "== broker"
systemctl daemon-reload
systemctl enable -q stk
systemctl restart stk
for _ in $(seq 20); do [ -S /run/stk/stk.sock ] && break; sleep 0.5; done
systemctl is-active --quiet stk
echo "   stk.service active, socket $(stat -c '%a %U:%G' /run/stk/stk.sock)"

echo "== client settings for $agent"
# `stk env` checks the proxy is live before printing its key. The key gates use of the broker
# and unlocks no secret.
envfile=$(mktemp)
for _ in $(seq 20); do as_stk /usr/local/bin/stk env > "$envfile" 2>/dev/null && break; sleep 0.5; done
[ -s "$envfile" ] || { echo "stk env produced nothing"; exit 1; }
sed -i 's#/var/lib/stk/ca.pem#/etc/stk/ca.pem#g' "$envfile"
install -d -o $agent -g $agent -m 700 "$H/.config/stk"
install -m 600 -o $agent -g $agent "$envfile" "$H/.config/stk/env"
rm -f "$envfile"
install -d -o $agent -g $agent -m 755 "$H/.local/bin"
cat > "$H/.local/bin/git.new" <<'WRAPPER'
#!/bin/sh
# Written by supertoolkit deploy/staging/deploy.sh. git, through the stk broker: its proxy and CA.
# Only HTTPS goes through the proxy, so ssh://, git:// and ext:: (which would go around the
# broker and its policy) are refused here.
set -a
. /home/salaam/.config/stk/env
set +a
export GIT_SSL_CAINFO="$SSL_CERT_FILE" GIT_TERMINAL_PROMPT=0
export GIT_CONFIG_COUNT=3 \
  GIT_CONFIG_KEY_0=protocol.ssh.allow GIT_CONFIG_VALUE_0=never \
  GIT_CONFIG_KEY_1=protocol.git.allow GIT_CONFIG_VALUE_1=never \
  GIT_CONFIG_KEY_2=protocol.ext.allow GIT_CONFIG_VALUE_2=never
exec /usr/bin/git "$@"
WRAPPER
chown $agent:$agent "$H/.local/bin/git.new" && chmod 755 "$H/.local/bin/git.new"
mv -T "$H/.local/bin/git.new" "$H/.local/bin/git"
echo "   $H/.config/stk/env (600), $H/.local/bin/git -> stk"

# A systemd --user manager started before salaam joined the stk group does not have it.
uid=$(id -u $agent)
gid=$(getent group stk | cut -d: -f3)
mpid=$(systemctl show -p MainPID --value user@$uid)
if [ "$mpid" != 0 ] && ! grep -qE "^Groups:.*\b$gid\b" /proc/$mpid/status; then
  echo "   restarting user@$uid so salaam's session has the stk group"
  systemctl restart user@$uid
fi

echo "== smoke"
doc=$(as_stk /usr/local/bin/stk doctor --agent-uid "$uid" 2>&1 || true)
printf '%s\n' "$doc" | grep -E '✓|✗' | sed 's/^/   /'
printf '%s\n' "$doc" | grep -q 'isolation  separate-user' || { echo "isolation is not separate-user"; exit 1; }
# One failure is expected and is not a fault: doctor wants the socket 0600, but
# `stk install --group` makes it 0660 on purpose (the uid allowlist is the authorisation).
bad=$(printf '%s\n' "$doc" | grep '✗' | grep -v 'daemon socket .* mode 660' || true)
[ -z "$bad" ] || { echo "doctor failed:"; printf '%s\n' "$bad"; exit 1; }
# The agent can reach the socket and cannot read the broker's state.
runuser -u $agent -- sh -c "test -w /run/stk/stk.sock" || { echo "$agent cannot reach the socket"; exit 1; }
if runuser -u $agent -- ls /var/lib/stk >/dev/null 2>&1; then echo "$agent can read /var/lib/stk"; exit 1; fi
# A read through the broker works, a push is refused by name, and both are in the audit.
tmpd=$(runuser -u $agent -- mktemp -d)
head=$(runuser -u $agent -- env HOME="$tmpd" "$H/.local/bin/git" ls-remote "$REPO_URL" refs/heads/main | cut -c1-12)
[ -n "$head" ] || { echo "git ls-remote through the broker returned nothing"; exit 1; }
echo "   git ls-remote through the broker: agentpod main $head"
push=$(runuser -u $agent -- env HOME="$tmpd" sh -c "cd '$tmpd' && /usr/bin/git init -q r && cd r &&
  /usr/bin/git -c user.name=smoke -c user.email=smoke@invalid commit -q --allow-empty -m smoke &&
  '$H/.local/bin/git' push '$REPO_URL' HEAD:refs/heads/stk-smoke 2>&1" || true)
rm -rf "$tmpd"
printf '%s\n' "$push" | grep -q 'error: 403' ||
  { echo "expected the push to be refused with 403, got:"; printf '%s\n' "$push"; exit 1; }
# git does not show the broker's reason; the audit record is the evidence, not git's exit code.
as_stk /usr/local/bin/stk audit --json --limit 10 | grep -q 'git-receive-pack.*denied: user#5\|denied: user#5.*git-receive-pack' ||
  { echo "the audit does not show the push denied by rule user#5"; exit 1; }
echo "   git push through the broker: 403, audit shows it denied by rule user#5"
as_stk /usr/local/bin/stk audit --limit 4 | sed 's/^/   /'
echo "deployed supertoolkit ${sha:0:12}"
