// PDF embeds on the publish site: `![[x.pdf]]` shows the PDF inline through
// the browser's own viewer, and never for a reader who may not see the file.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRenderer } from '../src/web/markdown.mjs';
import { applyBase } from '../src/web/export.mjs';
import { buildResolver } from '../src/links.mjs';

const ENTRIES = [
  { id: 'n1', path: 'Notes/Report.md', kind: 'note', title: 'Report' },
  { id: 'a1', path: 'Docs/Survey 2026.pdf', kind: 'asset', title: 'Q&A <survey>' },
  { id: 'a2', path: 'Private/Payroll.pdf', kind: 'asset', title: 'Payroll' },
];

function render(text) {
  const r = createRenderer({
    resolver: buildResolver(ENTRIES),
    canRead: (p) => !p.startsWith('Private/'),
    byPath: new Map(ENTRIES.map((e) => [e.path, e])),
    redactTitles: true,
  });
  return r.render(text, 'Notes/Report.md');
}

test('pdf embed: renders an <object> on the raw bytes, with a link to open it', () => {
  const html = render('![[Survey 2026.pdf]]');
  assert.match(html, /<object class="asset-pdf" data="\/_raw\/Docs\/Survey%202026\.pdf" type="application\/pdf"/);
  assert.match(html, /<span class="embed-fallback">[^<]*<a class="lk lk-note" href="\/Docs\/Survey%202026\.pdf">Open the PDF<\/a>/,
    'no way to open the PDF in a browser without a viewer');
  assert.match(html, /<figcaption><a class="lk lk-note" href="\/Docs\/Survey%202026\.pdf">/);
});

test('pdf embed: the title is escaped wherever it appears', () => {
  const html = render('![[Survey 2026.pdf]]');
  assert.ok(!html.includes('<survey>'), 'a raw title reached the HTML');
  assert.match(html, /aria-label="Q&amp;A &lt;survey&gt;"/);
  assert.match(html, />Q&amp;A &lt;survey&gt;<\/a>/);
});

test('pdf embed: #page=N opens that page; any other anchor is dropped', () => {
  assert.match(render('![[Survey 2026.pdf#page=3]]'), /data="\/_raw\/Docs\/Survey%202026\.pdf#page=3"/);
  assert.match(render('![[Survey 2026.pdf#Methods]]'), /data="\/_raw\/Docs\/Survey%202026\.pdf"/);
});

test('pdf embed: an alias labels the embed', () => {
  assert.match(render('![[Survey 2026.pdf|the survey]]'), /aria-label="the survey"/);
});

test('pdf embed: a PDF the reader may not see is redacted, not embedded', () => {
  const html = render('![[Payroll.pdf]]');
  assert.ok(!html.includes('<object'), 'a restricted PDF was embedded');
  assert.ok(!html.includes('_raw'), 'a restricted PDF URL reached the page');
  assert.match(html, /lk-locked/);
});

test('export: applyBase prefixes <object data> but not attributes ending in "data"', () => {
  const out = applyBase('<object data="/_raw/x.pdf"></object><i x-data="/y"></i>', '/repo');
  assert.ok(out.includes('data="/repo/_raw/x.pdf"'));
  assert.ok(out.includes('x-data="/y"'), 'an attribute merely ending in data was rewritten');
});
