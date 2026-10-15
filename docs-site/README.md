# docs.supertoolkit.dev

Starlight, with the landing page's palette and faces. Its job is to get somebody
from "I typed the domain" to a working broker, and then out of their way.

```
npm ci && npm run dev      # http://localhost:4330
npm run build              # dist/
```

Deployed with `scripts/deploy-sites.sh docs`.

**The pages here are derived from the repository's own documents** — `README.md`,
`docs/limitations.md`, `docs/measurements.md`. Where they disagree, the
repository wins and the page is wrong. The install commands must match the
landing page's.

## If the build says a sidebar slug "does not exist"

The content layer caches into `node_modules/.astro/data-store.json`, and a store
written before `src/content.config.ts` existed keeps reporting an empty
collection — the dev server works, the build fails, and the error names a slug
that is plainly there. `npx astro build --force` rebuilds it.
