// The product's colour, read from vibekit at build time: PRODUCT_ACCENTS names the accent and
// vibekit's generated accents.css holds its values. The page has no vibe switch, so it takes the
// Daylight look, the suite's default, in light and in dark. No colour here is typed by hand: a
// vibekit update changes the page, and an accent vibekit no longer has fails the build.
import { PRODUCT_ACCENTS, type Product } from '@superjackfruit/vibekit/appearance';
import accentsCss from '@superjackfruit/vibekit/accents.css?raw';

const VIBE = 'daylight';

export interface AccentTokens {
  /** The accent: large text, buttons, borders, rules and marks. */
  accent: string;
  /** Text on the accent (the vibe's page colour). */
  fg: string;
  /** A pale ground in the accent's hue, for chips and the chosen option. */
  wash: string;
  /** The accent as body-size text, on the page, a surface or the wash. */
  text: string;
}

function read(accent: string, theme: 'light' | 'dark'): AccentTokens {
  const selector = `[data-vibe="${VIBE}"][data-theme="${theme}"][data-accent="${accent}"]`;
  const at = accentsCss.indexOf(selector);
  if (at < 0) throw new Error(`vibekit accents.css has no ${selector}`);
  const body = accentsCss.slice(accentsCss.indexOf('{', at) + 1, accentsCss.indexOf('}', at));
  const token = (name: string) => {
    const m = body.match(new RegExp(`--vk-color-${name}:\\s*(#[0-9a-fA-F]{3,8})\\s*;`));
    if (!m) throw new Error(`vibekit accents.css: ${selector} has no --vk-color-${name}`);
    return m[1];
  };
  return { accent: token('accent'), fg: token('accent-fg'), wash: token('accent-wash'), text: token('accent-text') };
}

export function productAccent(product: Product) {
  const accent = PRODUCT_ACCENTS[product];
  if (!accent) throw new Error(`vibekit names no accent for ${product}`);
  return { accent, light: read(accent, 'light'), dark: read(accent, 'dark') };
}
