# docs.supertoolkit.dev

Starlight, with the landing page's palette and faces. The accent is vibekit's
indigo, read from the package at build time (`accent.mjs`, as
`landing/src/accent.ts` does for the landing page). Its job is to get somebody
from "I typed the domain" to a working broker, and then out of their way.

```
npm ci && npm run dev      # http://localhost:4330
npm run build              # dist/
```

Deployed on merge to main by `.github/workflows/sites.yml`, which runs
`scripts/deploy-sites.sh`. To deploy by hand: `scripts/deploy-sites.sh docs`.

**The pages here are derived from the repository's own documents** — `README.md`,
`docs/limitations.md`, `docs/measurements.md`. Where they disagree, the
repository wins and the page is wrong. The install commands must match the
landing page's.

## If the build says a sidebar slug "does not exist"

The content layer caches into `node_modules/.astro/data-store.json`, and a store
written before `src/content.config.ts` existed keeps reporting an empty
collection — the dev server works, the build fails, and the error names a slug
that is plainly there. `npx astro build --force` rebuilds it.

## The docs are checked against the code

`go test ./internal/docsclaims/` (part of `go test ./...`, and the `docs` job in
`.forgejo/workflows/ci.yml`, which runs on every pull request, docs-only ones
too) reads the public surface from the code — every command and subcommand,
flag, environment variable, `supertoolkit.yaml` key, `stk ui` route,
control-socket method, MCP tool, service and credential operation — and fails
when one is not named on any page here. It also checks the counts the pages
state (operations, services, MCP tools) against the catalogue.

`undocumented-baseline.json` lists what is undocumented on purpose, today only
the service key `scopes:`, which the policy file accepts and nothing reads. The
baseline may only shrink: the check fails when an item in it is documented, or
is no longer in the code, until it is taken out.

`scripts/sync-docs.sh --check` fails when `limitations.md` or `measurements.md`
is not what `docs/` generates.
