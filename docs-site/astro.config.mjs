// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const REPO = 'https://github.com/SuperJackfruitLabs/supertoolkit';

export default defineConfig({
  site: 'https://docs.supertoolkit.dev',
  integrations: [
    starlight({
      title: 'supertoolkit',
      description:
        'A credential broker for agents. The agent asks for an effect by name; the broker substitutes, signs or mints on the wire. Self-hosted, Apache-2.0.',
      // The mark beside the name, as on the landing page. See the component for why it
      // replaces Starlight's own rather than using the `logo` option.
      components: { SiteTitle: './src/components/SiteTitle.astro' },
      // The landing page's palette and faces; see src/styles/theme.css for each value.
      customCss: ['./src/styles/theme.css'],
      favicon: '/favicon.svg',
      editLink: { baseUrl: `${REPO}/edit/main/docs-site/` },
      head: [
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.googleapis.com' } },
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: true } },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href:
              'https://fonts.googleapis.com/css2?family=Outfit:wght@600;700' +
              '&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap',
          },
        },
      ],
      social: [{ icon: 'github', label: 'GitHub', href: REPO }],
      // Three sections, in the order a reader needs them: what it is and how to stand it
      // up, then using it, then the things worth knowing before trusting it.
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'What supertoolkit is', slug: 'what-it-is' },
            { label: 'Install', slug: 'install' },
            { label: 'Connect a service', slug: 'connect' },
          ],
        },
        {
          label: 'Use',
          items: [
            { label: 'Policy and profiles', slug: 'use/policy' },
            { label: 'Approvals', slug: 'use/approvals' },
            { label: 'The audit ledger', slug: 'use/audit' },
            { label: 'From an agent', slug: 'use/from-an-agent' },
            { label: 'Services', slug: 'use/services' },
          ],
        },
        {
          label: 'Know',
          items: [
            { label: 'Limitations', slug: 'limitations' },
            { label: 'What is measured', slug: 'measurements' },
            { label: 'Security model', slug: 'security' },
          ],
        },
      ],
    }),
  ],
});
