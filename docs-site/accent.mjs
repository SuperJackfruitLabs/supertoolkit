// SuperToolkit's colour, read from vibekit at build time, the way landing/src/accent.ts reads it
// for supertoolkit.dev: PRODUCT_ACCENTS names the accent (indigo) and vibekit's generated
// accents.css holds its Daylight values for light and dark. No colour is typed by hand here, so
// a vibekit update changes both sites, and an accent vibekit no longer has fails the build.
//
// This file runs in Node (astro.config.mjs imports it), so it reads the CSS with fs rather than
// with Vite's `?raw` import as the landing page does.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { PRODUCT_ACCENTS } from '@superjackfruit/vibekit/appearance';

const VIBE = 'daylight';
const require = createRequire(import.meta.url);
const accentsCss = readFileSync(require.resolve('@superjackfruit/vibekit/accents.css'), 'utf8');

/** One theme's tokens: accent, text on it (fg), its pale ground (wash), and the accent as text. */
function read(accent, theme) {
  const selector = `[data-vibe="${VIBE}"][data-theme="${theme}"][data-accent="${accent}"]`;
  const at = accentsCss.indexOf(selector);
  if (at < 0) throw new Error(`vibekit accents.css has no ${selector}`);
  const body = accentsCss.slice(accentsCss.indexOf('{', at) + 1, accentsCss.indexOf('}', at));
  const token = (name) => {
    const m = body.match(new RegExp(`--vk-color-${name}:\\s*(#[0-9a-fA-F]{3,8})\\s*;`));
    if (!m) throw new Error(`vibekit accents.css: ${selector} has no --vk-color-${name}`);
    return m[1];
  };
  return { accent: token('accent'), fg: token('accent-fg'), wash: token('accent-wash'), text: token('accent-text') };
}

/** The product accent as CSS custom properties, dark on :root (Starlight's default) and light. */
export function accentCss(product = 'supertoolkit') {
  const accent = PRODUCT_ACCENTS[product];
  if (!accent) throw new Error(`vibekit names no accent for ${product}`);
  const vars = (t) =>
    `--stk-accent: ${t.accent}; --stk-accent-text: ${t.text}; --stk-accent-wash: ${t.wash}; --stk-accent-fg: ${t.fg};`;
  return `:root { ${vars(read(accent, 'dark'))} }\n:root[data-theme='light'] { ${vars(read(accent, 'light'))} }`;
}
