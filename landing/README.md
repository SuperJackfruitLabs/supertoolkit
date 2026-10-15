# supertoolkit.dev

One page, no framework, no scripts. Its job is to explain the product to
somebody who typed the domain, then send them to the docs or the source.

There is nothing to sign in to: supertoolkit runs on your own machine, so the
page sells nothing it cannot hand over.

This directory is deliberately outside the Go module and has its own lockfile.
`go build ./...` never looks in here.

```
npm ci && npm run dev      # http://localhost:4329
npm run build              # dist/
```

Deployed with `scripts/deploy-sites.sh landing` from a machine that has already
run `wrangler login`.

**Every claim on the page must be true of the current source**, and every
command must match the docs site's install page. If the two disagree, the page
is wrong.
