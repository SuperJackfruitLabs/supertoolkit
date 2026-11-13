// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://supertoolkit.dev',
  // The 404 page is served at mistyped paths; it is not an address, so it stays out.
  integrations: [sitemap({ filter: (page) => !/\/404\/?$/.test(page) })],
});
