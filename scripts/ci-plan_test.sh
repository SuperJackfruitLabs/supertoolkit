#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
planner="$repo_root/scripts/ci-plan.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

git -C "$fixture" init -q
git -C "$fixture" -c user.name=CI -c user.email=ci@example.invalid commit --allow-empty -qm base
base=$(git -C "$fixture" rev-parse HEAD)

plan() {
  (cd "$fixture" && "$planner" pull_request "$1")
}

case_number=0
check_case() {
  expected=$1
  description=$2
  shift 2
  case_number=$((case_number + 1))
  git -C "$fixture" reset --hard -q "$base"
  git -C "$fixture" clean -fdq
  for path in "$@"; do
    mkdir -p "$fixture/$(dirname "$path")"
    printf 'case %s\n' "$case_number" >"$fixture/$path"
  done
  git -C "$fixture" add -A
  git -C "$fixture" -c user.name=CI -c user.email=ci@example.invalid commit -qm "$description"
  actual=$(plan "$base")
  if [ "$actual" != "full=$expected" ]; then
    printf 'FAIL: %s: got %s, want full=%s\n' "$description" "$actual" "$expected" >&2
    exit 1
  fi
}

check_case false 'all accepted documentation roots' \
  README README.md README.markdown README.txt README.rst \
  docs/guide.md docs-site/src/content/docs/guide.md
check_case false 'docs subtree only' docs/reference/configuration.md
check_case false 'docs site subtree only' docs-site/package.json
check_case true 'nested README is application work' web/README.md
check_case true 'mixed docs and code is full CI' docs/guide.md internal/broker/proxy.go
check_case true 'workflow change is full CI' .forgejo/workflows/ci.yml
check_case true 'config package lock and generated changes are full CI' \
  .golangci.yml web/package.json web/pnpm-lock.yaml internal/generated/client.go

# Empty and unknowable comparisons fail closed to full CI.
git -C "$fixture" reset --hard -q "$base"
[ "$(plan "$base")" = 'full=true' ]
[ "$(plan '')" = 'full=true' ]
[ "$(plan deadbeef)" = 'full=true' ]
[ "$(cd "$fixture" && "$planner" push "$base")" = 'full=true' ]

# Keep the regression test attached to the path the live workflow executes.
workflow=$(<"$repo_root/.forgejo/workflows/ci.yml")
[[ "$workflow" == *'run: scripts/ci-plan_test.sh'* ]]
[[ "$workflow" == *'run: scripts/ci-plan.sh "$EVENT" "$BASE"'* ]]
[[ "$workflow" == *'if: needs.changes.outputs.full == '\''true'\'''* ]]
[[ "$workflow" == *'if: always()'* ]]
[[ "$workflow" == *$'  check:\n'* ]]

printf 'PASS: %s routing cases and live workflow wiring\n' "$case_number"
