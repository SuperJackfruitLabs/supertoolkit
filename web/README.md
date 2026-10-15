# supertoolkit's web app

The five screens, built from vibekit, the suite design system, which is
vendored here as a tarball so this builds with no access to anything else
and served by the Go binary from `go:embed`.

## Why it is built this way

There is no node server in supertoolkit and there should not be one. The app is
a static build, embedded, so the single-binary promise survives having a UI.

vibekit is vendored as a packed tarball rather than taken from a registry,
which is how superpipeline already consumes it.

## Building

```
pnpm install
pnpm build          # writes web/build
cp -R build/. ../internal/webui/build/
```

The embedded copy under `internal/webui/build` is committed so `go build` works
for someone who has never run pnpm. A build with no assets still compiles and
serves a page saying how to produce them, rather than failing.

## What the browser may ask for

Everything in `src/lib/api.ts` is a read or a decision. There is deliberately no
call that returns a credential, because the broker exposes no such route.
