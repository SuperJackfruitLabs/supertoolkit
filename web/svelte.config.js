import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
export default {
  preprocess: vitePreprocess(),
  kit: {
    // A static build, because the Go binary serves these files from go:embed.
    // There is no node server in supertoolkit and there should not be one.
    adapter: adapter({ fallback: 'index.html', pages: 'build', assets: 'build' }),
  },
};
