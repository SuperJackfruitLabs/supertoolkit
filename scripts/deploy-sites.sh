#!/usr/bin/env bash
# Build supertoolkit.dev and docs.supertoolkit.dev and deploy both as Cloudflare
# Workers with static assets.
#
# Run from the operator's machine with an existing `wrangler login`; no API token is
# created or stored anywhere. Each site's wrangler.jsonc names its Worker and its
# custom domain, so this attaches the domain too.
#
# --config is explicit and wrangler runs from a scratch directory: in a site directory
# without a config, wrangler's project detection scaffolds an adapter into the site and
# rewrites astro.config.mjs. Other products in this estate learned that against the live
# account; do not simplify it away.
#
# Usage: scripts/deploy-sites.sh [landing|docs|all]   (default: all)
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
which="${1:-all}"
case "$which" in landing|docs|all) ;; *) echo "usage: $0 [landing|docs|all]" >&2; exit 2 ;; esac

command -v wrangler >/dev/null 2>&1 || {
  echo "wrangler is not installed. npm i -g wrangler, then wrangler login." >&2; exit 1; }

scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

ship() { # <dir> <url>
  echo "==> building $1"
  # --force: the content layer caches into node_modules/.astro, and a stale store
  # reports an empty collection while the dev server works fine.
  (cd "$root/$1" && npm ci --silent && npx astro build --force)
  echo "==> deploying $1"
  (cd "$scratch" && wrangler deploy --config "$root/$1/wrangler.jsonc" --cwd "$root/$1")
  echo "==> $2"
}

[ "$which" = landing ] || [ "$which" = all ] && ship landing   "https://supertoolkit.dev"
[ "$which" = docs    ] || [ "$which" = all ] && ship docs-site "https://docs.supertoolkit.dev"

echo
echo "Both sites claim what the current source does. If a page and the repository"
echo "disagree, the page is wrong — check before telling anyone it is live."
