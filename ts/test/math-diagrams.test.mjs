// TeX math and Mermaid diagrams on the publish site.
//
// Math is rendered on the server by KaTeX, to MathML; Mermaid is drawn in the
// browser by site.js, so on the server side a diagram is only a code block
// plus the bundle site.js loads. Both must leave author markup unable to
// reach the page, both must work under the site's Content-Security-Policy,
// and neither may cost anything on a page that does not use it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, rm, appendFile, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { Site } from '../src/web/site.mjs';
import { Gatekeeper } from '../src/gatekeeper.mjs';
import { exportSite } from '../src/web/export.mjs';
import { createRenderer } from '../src/web/markdown.mjs';
import { buildResolver } from '../src/links.mjs';
import { corpusPath } from './support/spec.mjs';

const DEMO = corpusPath('vaults/demo/vault');

const render = (text) => createRenderer({
  resolver: buildResolver([]), canRead: () => true, byPath: new Map(), redactTitles: true,
}).render(text, 'N.md');

const isMath = (html) => html.includes('class="katex"');

// ---- math -------------------------------------------------------------------

test('math: $…$ renders inline, $$…$$ displayed, in a paragraph or as a block', () => {
  assert.match(render('Area is $\\pi r^2$ here.'), /<p>Area is <span class="katex"><math xmlns="http:\/\/www\.w3\.org\/1998\/Math\/MathML">/);
  assert.match(render('Then $$e=mc^2$$ inline.'), /<math [^>]*display="block"/);
  const block = render('Before\n$$\n\\sum_{i=1}^n x_i\n$$\nafter');
  assert.match(block, /<p>Before<\/p>\n<div class="math-display"><span class="katex"><math [^>]*display="block"/);
  assert.match(block, /<p>after<\/p>/);
});

test('math: MathML only, so nothing needs a style attribute, a stylesheet or a font', () => {
  // The site's CSP refuses all three; KaTeX's HTML output needs them.
  const html = render('$\\frac{a}{b} + \\sqrt{x}$');
  assert.ok(!html.includes('style='), 'KaTeX emitted an inline style the CSP would drop');
  assert.ok(!html.includes('katex-html'), 'KaTeX emitted its HTML rendering');
});

test('math: prices, escaped dollars and code spans stay text', () => {
  assert.equal(render('Costs $5 and $10 total.'), '<p>Costs $5 and $10 total.</p>\n');
  assert.equal(render('Escaped \\$x$ is not math.'), '<p>Escaped $x$ is not math.</p>\n');
  assert.equal(render('Run `echo $HOME$` here.'), '<p>Run <code>echo $HOME$</code> here.</p>\n');
});

test('math: emphasis rules do not reach inside a formula', () => {
  // Without the math tokenizer marked reads *b$ and $c* as emphasis.
  const html = render('$a*b$ and $c*d$');
  assert.ok(!html.includes('<em>'), 'emphasis crossed two formulas');
  assert.equal(html.match(/class="katex"/g).length, 2);
});

test('math: a TeX error shows the source instead of failing the page', () => {
  const html = render('Bad $\\frac{$ tex.');
  assert.match(html, /<span class="katex-error" title="ParseError:/);
});

test('math: author markup and \\href cannot reach the page (trust: false)', () => {
  const href = render('$\\href{javascript:alert(1)}{x}$');
  assert.ok(isMath(href));
  assert.ok(!/<a[\s>]/.test(href), '\\href produced a link');

  const tag = render('$<script>alert(1)</script>$');
  assert.ok(!tag.includes('<script'), 'a raw tag reached the page');
});

// ---- diagrams -----------------------------------------------------------------

test('diagrams: a mermaid fence stays an escaped code block for site.js to draw', () => {
  const html = render('```mermaid\ngraph TD; A-->B["<img src=x onerror=alert(1)>"]\n```');
  assert.match(html, /^<pre><code class="language-mermaid">graph TD; A--&gt;B\[&quot;&lt;img/);
});

// ---- site and export ----------------------------------------------------------

async function demoWithExtras() {
  const dir = path.join(tmpdir(), `basalt-math-${process.pid}-${Math.random().toString(36).slice(2)}`);
  await cp(DEMO, dir, { recursive: true });
  await appendFile(path.join(dir, 'content/Geology/Basalt.md'),
    '\n## Cooling\n\nRate $\\frac{dT}{dt} = -k(T - T_0)$.\n\n```mermaid\ngraph TD; Lava-->Basalt\n```\n');
  const vault = new Vault(new FsTransport(dir));
  await vault.load();
  await vault.reindex();
  return { dir, vault };
}

const get = (site, urlPath) =>
  site.handle({ urlPath, query: new URLSearchParams(), principal: 'anonymous' });

test('site: a page with math and a diagram needs nothing extra in its <head>', async (t) => {
  const { dir, vault } = await demoWithExtras();
  t.after(() => rm(dir, { recursive: true, force: true }));
  const site = new Site(vault);

  const page = String((await get(site, '/Geology/Basalt')).body);
  assert.match(page, /<math xmlns=/);
  assert.match(page, /<code class="language-mermaid">/);
  assert.ok(!/katex[^"]*\.css/.test(page), 'a KaTeX stylesheet is linked');
});

test('site: serves the Mermaid bundle, and nothing beside it', async (t) => {
  const { dir, vault } = await demoWithExtras();
  t.after(() => rm(dir, { recursive: true, force: true }));
  const site = new Site(vault);

  const js = await get(site, '/_assets/vendor/mermaid.min.js');
  assert.equal(js.status, 200);
  assert.match(js.headers['content-type'], /^text\/javascript/);
  assert.match(String(js.body).slice(-200), /globalThis\["mermaid"\]/, 'not the browser bundle');

  for (const p of [
    '/_assets/vendor/mermaid.LICENSE',
    '/_assets/vendor/../site.js',
    '/_assets/vendor/../../site.mjs',
    '/_assets/katex/katex.min.css',
  ]) {
    assert.equal((await get(site, p)).status, 404, `${p} was served`);
  }
});

test('site: the CSP admits same-origin <object> for PDFs and still no inline style', async (t) => {
  const v = new Vault(new FsTransport(DEMO));
  await v.load();
  await v.reindex();
  const g = new Gatekeeper(v, { identify: () => 'anonymous', site: new Site(v) });
  await g.listen(0);
  t.after(() => g.server.close());

  const res = await fetch(`http://127.0.0.1:${g.server.address().port}/Geology/Basalt`);
  assert.equal(res.status, 200);
  const csp = res.headers.get('content-security-policy');
  assert.match(csp, /(^|; )object-src 'self'(;|$)/);
  assert.match(csp, /(^|; )style-src 'self'(;|$)/);
  assert.ok(!csp.includes('unsafe-inline'), 'the policy admits inline style or script');
});

test('export: copies the Mermaid bundle only when a page has a diagram', async (t) => {
  const plain = path.join(tmpdir(), `basalt-export-plain-${process.pid}`);
  const v = new Vault(new FsTransport(DEMO));
  await v.load();
  await v.reindex();
  await exportSite({ vault: v, out: plain, clean: true });
  t.after(() => rm(plain, { recursive: true, force: true }));
  assert.ok(!existsSync(path.join(plain, '_assets/vendor')), 'Mermaid shipped with no diagram');

  const { dir, vault } = await demoWithExtras();
  const out = path.join(tmpdir(), `basalt-export-extras-${process.pid}`);
  t.after(() => rm(dir, { recursive: true, force: true }));
  t.after(() => rm(out, { recursive: true, force: true }));
  await exportSite({ vault, out, clean: true, base: '/repo' });

  assert.ok(existsSync(path.join(out, '_assets/vendor/mermaid.min.js')));
  const page = await readFile(path.join(out, 'Geology/Basalt/index.html'), 'utf8');
  assert.match(page, /<math xmlns=/);
});
