import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
export default {
  preprocess: vitePreprocess(),
  kit: {
    // A static build, because the Go binary serves these files from go:embed.
    // There is no node server in supertoolkit and there should not be one.
    //
    // The output goes straight into the directory go:embed reads. It used to
    // land in web/build, with nothing copying it across, so the UI source and
    // the embedded UI drifted silently: a frontend change would build cleanly,
    // the binary would rebuild cleanly, and the browser would still run the
    // previous version with no error anywhere to explain it. One directory
    // removes the possibility rather than fixing one instance of it.
    adapter: adapter({
      fallback: 'index.html',
      pages: '../internal/webui/build',
      assets: '../internal/webui/build',
    }),
  },
};
