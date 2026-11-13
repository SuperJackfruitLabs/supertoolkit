// Run after `npm run build`: the suite frame must be in the static HTML, the old masthead gone.
import { readFileSync } from 'node:fs';
const html = readFileSync(new URL('../dist/index.html', import.meta.url), 'utf8');
const fail = [];
for (const tag of ['<sjl-suite-bar', '<sjl-product-header', '<sjl-claims', '<sjl-footer']) if (!html.includes(tag)) fail.push(`missing ${tag}`);
if (/<header class/.test(html.replace(/<template[\s\S]*?<\/template>/g, ''))) fail.push('old masthead <header class> present');
if (html.includes('x-sjl-preview')) fail.push('x-sjl-preview present');
if (fail.length) { console.error(fail.join('\n')); process.exit(1); }
console.log('check-frame: ok');
