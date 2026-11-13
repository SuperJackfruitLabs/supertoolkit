# supertoolkit.dev

One page and a 404, wearing the suite frame (`@superjackfruit/frontdoor`, vendored in `vendor/`
beside vibekit), like the other product sites. Its job is to explain the product to somebody who
typed the domain, then send them to the docs or the source.

There is nothing to sign in to: SuperToolkit runs on your own machine, so the page sells nothing
it cannot hand over.

This directory is deliberately outside the Go module and has its own lockfile.
`go build ./...` never looks in here. Astro 7 needs Node 22.23.4 or newer.

```
npm ci && npm run dev      # http://localhost:4509
npm run build              # dist/, then checks the frame is in the HTML
```

Deployed on merge to main by `.github/workflows/sites.yml`, which runs
`scripts/deploy-sites.sh`. To deploy by hand: `scripts/deploy-sites.sh landing`
after `wrangler login`. `assets.not_found_handling: "404-page"` serves `dist/404.html` with a
real 404.

**Every claim on the page must be true of the current source**, and every
command must match the docs site's install page. If the two disagree, the page
is wrong. The service list is read from `internal/catalog/catalog.go` at build time; the comment
at the top of `src/pages/index.astro` says where every other string comes from.

**Colour.** SuperToolkit's colour is vibekit's indigo (OKLCH hue 277), named by
`PRODUCT_ACCENTS.supertoolkit` since vibekit 0.0.15. `src/accent.ts` reads its Daylight tokens for
light and dark from the package's `accents.css` at build time, so the page follows vibekit rather
than a copy; only the grounds are the page's own. The suite frame keeps its own SuperToolkit colour,
`#5b5fe0`, for its bar and header, and the mark in `public/favicon.svg` is frontdoor's
`brand/supertoolkit.svg`, byte for byte (the PNG icons are rendered from it).

**Discovery.** `public/llms.txt` (the docs site serves none, so the frame links this one), a
sitemap (`@astrojs/sitemap`), JSON-LD in the page head, and `public/og.png`, rendered from the
suite's one share-image template (see `og/README.md`).
