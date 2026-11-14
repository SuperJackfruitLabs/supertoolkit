#!/usr/bin/env bash
set -euo pipefail

# Default closed: unknown triggers, missing bases, empty diffs, and diff failures
# run the full suite. A pull request is docs-only only when every changed path
# belongs to the deliberately small public-documentation allowlist.
full=true
event=${1:-}
base=${2:-}
files=$(mktemp)
trap 'rm -f "$files"' EXIT

if [ "$event" = pull_request ] \
  && [ -n "$base" ] \
  && [ "$base" != 0000000000000000000000000000000000000000 ] \
  && git rev-parse --verify --quiet "$base^{commit}" >/dev/null \
  && git diff --name-only "$base" HEAD >"$files" \
  && [ -s "$files" ]; then
  full=false
  while IFS= read -r path; do
    case "$path" in
      README|README.md|README.markdown|README.txt|README.rst|docs/*|docs-site/*) ;;
      *) full=true; break ;;
    esac
  done <"$files"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  printf 'full=%s\n' "$full" >>"$GITHUB_OUTPUT"
fi
printf 'full=%s\n' "$full"
