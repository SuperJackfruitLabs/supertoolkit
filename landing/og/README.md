# The link preview image

`public/og.png` is what a link to supertoolkit.dev shows when it is pasted into Slack, X or
iMessage: 1200×630, rendered from the suite's one share-image template in the frontdoor repo
(`scripts/og/render.mjs`), so every product's preview reads as one suite. The headline there must
match this page's `<h1>`.

To regenerate it after changing the headline or the mark, from a frontdoor checkout:

```bash
node scripts/og/render.mjs /tmp/og
cp /tmp/og/supertoolkit.png <this repo>/landing/public/og.png
```
