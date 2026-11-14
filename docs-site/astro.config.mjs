// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import sjlDocs from '@superjackfruit/docs-theme';

const REPO = 'https://github.com/SuperJackfruitLabs/supertoolkit';

export default defineConfig({
  site: 'https://docs.supertoolkit.dev',
  integrations: [
    starlight({
      title: 'SuperToolkit',
      description:
        'A credential broker for agents. The agent asks for an effect by name; the broker substitutes, signs or mints on the wire. Self-hosted, Apache-2.0.',
      // The suite's docs theme: vibekit's indigo, the faces, the street, status badges, the footers,
      // the 404 and llms.txt. See @superjackfruit/docs-theme's README.
      plugins: [
        sjlDocs({
          product: 'supertoolkit',
          // It works and is released (v0.0.x binaries), and the Limitations page names its gaps.
          status: 'half-lit',
          // /llms.txt, /llms-full.txt and /llms-small.txt, for agents reading these docs. The
          // description is the one supertoolkit.dev's own llms.txt carries (landing/public/llms.txt).
          llms: {
            description:
              'A credential broker for agents: the agent asks for an effect by name and never holds, ' +
              'reads or receives the credential that causes it. SuperToolkit (`stk`) runs on your own ' +
              'machine, on Linux and macOS. A broker holds credentials in a process the agent cannot ' +
              'read; clients are started with `HTTPS_PROXY` pointing at it and a placeholder ' +
              '(`stk:ref:<service>:v1`) where their token would be, and the broker substitutes, signs, ' +
              'mints, refreshes or exchanges on the wire. Policy is one committed file with safe ' +
              'defaults: a read is agent-callable, a write needs approval. Every request is recorded in ' +
              'an audit ledger that holds a fingerprint of the credential, never its value. Agents use ' +
              'it over MCP (`stk mcp`, four tools). Apache-2.0, installed with a checksum-verified ' +
              'installer.',
          },
        }),
      ],
      favicon: '/favicon.svg',
      editLink: { baseUrl: `${REPO}/edit/main/docs-site/` },
      social: [{ icon: 'github', label: 'GitHub', href: REPO }],
      // The suite's five groups, in the order a reader needs them. No page moved, so no URL changed.
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
          label: 'Use it',
          items: [
            { label: 'Policy and profiles', slug: 'use/policy' },
            { label: 'Approvals', slug: 'use/approvals' },
            { label: 'The audit ledger', slug: 'use/audit' },
            { label: 'Services', slug: 'use/services' },
            { label: 'Gated publishing', slug: 'use/publish' },
          ],
        },
        {
          label: 'Build on it',
          items: [
            { label: 'From an agent', slug: 'use/from-an-agent' },
            { label: 'Fronted servers and egress', slug: 'use/mcp-serve' },
          ],
        },
        {
          label: 'Run it',
          items: [{ label: 'Run as a service', slug: 'run/serve' }],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Commands', slug: 'reference/cli' },
            { label: 'The web interface', slug: 'reference/web-ui' },
            { label: 'Security model', slug: 'security' },
            { label: 'Limitations', slug: 'limitations' },
            { label: 'What is measured', slug: 'measurements' },
          ],
        },
      ],
    }),
  ],
});
