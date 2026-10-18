// Static export, PROTOCOL §12.6.
//
// These are the highest-stakes tests here: everything the exporter writes is
// world-readable the moment it is published, and a leak looks exactly like a
// correct site from the outside.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir, rm, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { exportSite, applyBase } from '../src/web/export.mjs';

const DEMO = fileURLToPath(new URL('../../conformance/vaults/demo/vault', import.meta.url));
const MINIMAL = fileURLToPath(new URL('../../conformance/vaults/minimal/vault', import.meta.url));

/** The withheld note, by every string that could identify it. */
const WITHHELD = {
  path: 'Drafts/Unfinished Thoughts.md',
  id: '01jbq9d3m00000000000000014',
};

/**
 * Words that occur in the withheld note and in NO published note.
 *
 * Derived rather than hand-listed: a phrase picked by eye may also appear in
 * a public note — "denies the" does, in the note that explains the draft —
 * and the test then fails on the public note's own words. Only tokens unique
 * to the withheld note prove anything about leakage.
 */
async function withheldOnlyTokens(vault) {
  const tokens = (text) => new Set(
    (text.toLowerCase().match(/[\p{L}\p{N}_]{4,}/gu) ?? []));

  const entries = vault.indexes.nodes.entries;
  const draft = await vault.readNode('u:carter', WITHHELD.path);
  assert.equal(draft.status, 200, 'fixture: the withheld note should be readable by its owner');
  const unique = tokens(draft.text);

  for (const e of entries) {
    if (e.path === WITHHELD.path) continue;
    if (!vault.can('anonymous', e.path, ['read']).allowed) continue;
    const pub = await vault.readNode('anonymous', e.path);
    if (pub.status !== 200 || !pub.text) continue;
    for (const t of tokens(pub.text)) unique.delete(t);
  }
  return [...unique];
}

async function exportDemo(opts = {}) {
  const out = path.join(tmpdir(), `basalt-export-${process.pid}-${Math.random().toString(36).slice(2)}`);
  const v = new Vault(new FsTransport(DEMO));
  await v.load();
  await v.reindex();
  const result = await exportSite({ vault: v, out, clean: true, ...opts });
  return { out, result, vault: v };
}

/** Every file in the export, recursively, as [relativePath, contents]. */
async function allFiles(dir, base = dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...await allFiles(abs, base));
    else out.push([path.relative(base, abs), await readFile(abs)]);
  }
  return out;
}

test('export: emits a page per public node and none for the withheld one', async (t) => {
  const { out, result } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  assert.equal(result.published, 5);
  assert.deepEqual(result.withheld, [WITHHELD.path]);

  assert.ok(existsSync(path.join(out, 'Geology/Basalt/index.html')));
  assert.ok(existsSync(path.join(out, 'Geology/Columnar Jointing/index.html')));
  assert.ok(existsSync(path.join(out, 'index.html')));
  assert.ok(!existsSync(path.join(out, 'Drafts/Unfinished Thoughts/index.html')),
    'a page was emitted for a node that withholds publish');
});

test('export: the withheld node appears in NO file, by any identifier', async (t) => {
  const { out, vault } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  const files = await allFiles(out);
  assert.ok(files.length > 5, 'suspiciously few files to audit');

  // Subtract the site's own vocabulary. Words like "account" and "wrong"
  // are unique to the withheld note among vault NOTES, but they also occur
  // in the 404 page's copy and the stylesheet, so matching them would flag
  // the UI's boilerplate as a content leak.
  const chrome = new Set();
  for (const [rel, buf] of files) {
    if (rel !== '404.html' && !rel.startsWith('_assets')) continue;
    for (const t of buf.toString('utf8').toLowerCase()
      .match(/[\p{L}\p{N}_]{4,}/gu) ?? []) chrome.add(t);
  }
  const unique = (await withheldOnlyTokens(vault))
    .filter((t) => !chrome.has(t));

  assert.ok(unique.includes(WITHHELD.id.toLowerCase()),
    'the node id should always be a usable probe');
  assert.ok(unique.length >= 2,
    `fixture too weak: only ${unique.length} probe(s) survive, so this test ` +
    `would prove little`);

  for (const [rel, buf] of files) {
    const text = buf.toString('utf8');
    const lower = text.toLowerCase();
    assert.ok(!text.includes(WITHHELD.id),
      `${rel} contains the withheld node's id`);
    for (const token of unique) {
      assert.ok(!lower.includes(token),
        `${rel} contains "${token}", a word found only in the withheld note`);
    }
  }
});

test('export: never copies the vault index, which knows every private node (§8.8)', async (t) => {
  const { out } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  // The vault's own index/ must not be published under any name.
  for (const forbidden of ['index/nodes.json', 'index/links.json',
    'index/backlinks.json', 'index/search.json', 'meta', 'principals']) {
    assert.ok(!existsSync(path.join(out, forbidden)),
      `${forbidden} was published`);
  }
});

test('export: the shipped search index is rebuilt from the public subset', async (t) => {
  const { out, vault } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  const idx = JSON.parse(
    await readFile(path.join(out, '_assets/search-index.json'), 'utf8'));

  assert.ok(!idx.nodes.some((n) => n.path.startsWith('Drafts/')),
    'a withheld node is listed in the static search index');

  // Every posting must point at a node that is actually in the index.
  const ids = new Set(idx.nodes.map((n) => n.id));
  for (const [term, postings] of Object.entries(idx.terms)) {
    for (const p of postings) {
      assert.ok(ids.has(p.node),
        `term "${term}" points at ${p.node}, which is not a published node`);
    }
  }

  // A word that occurs ONLY in the withheld note must not be indexed at all.
  // ("unfinished" legitimately is, from the public note that links to it —
  // §15: redaction cannot retract what an author published elsewhere.)
  assert.ok(!idx.terms.absent, 'a word unique to the withheld note was indexed');
});

test('export: a link to a withheld node is redacted, not dropped (§9.5)', async (t) => {
  const { out } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  const home = await readFile(path.join(out, 'index.html'), 'utf8');
  assert.match(home, /lk-locked/,
    'the link to the withheld note vanished instead of being redacted');
  assert.ok(!home.includes('Unfinished Thoughts'),
    'the redacted link leaked the withheld title');
});

test('export: raw bytes exist for public nodes only', async (t) => {
  const { out } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  assert.ok(existsSync(path.join(out, '_raw/Geology/Basalt.md')));
  assert.ok(existsSync(path.join(out, '_raw/Assets/hexagons.svg')));
  assert.ok(!existsSync(path.join(out, '_raw/Drafts/Unfinished Thoughts.md')),
    'the withheld note’s source was published');
});

test('export: includes .nojekyll, so Pages serves _assets and _raw', async (t) => {
  const { out } = await exportDemo();
  t.after(() => rm(out, { recursive: true, force: true }));

  // Without it Jekyll drops every directory whose name starts with "_",
  // which is the stylesheet, the script and every image.
  assert.ok(existsSync(path.join(out, '.nojekyll')));
  assert.ok(existsSync(path.join(out, '_assets/site.css')));
  assert.ok(existsSync(path.join(out, '404.html')));
});

test('export: --base rewrites site-absolute URLs for a project page', async (t) => {
  const { out } = await exportDemo({ base: '/blackrockmcp' });
  t.after(() => rm(out, { recursive: true, force: true }));

  const page = await readFile(path.join(out, 'Geology/Basalt/index.html'), 'utf8');
  assert.match(page, /href="\/blackrockmcp\/_assets\/site\.css"/);
  assert.ok(!/href="\/_assets/.test(page), 'an unprefixed absolute URL survived');
  // External links and fragments must be left alone.
  assert.ok(!page.includes('/blackrockmcp/https'), 'an external URL was rewritten');
});

test('export: applyBase leaves external, protocol-relative and fragment URLs alone', () => {
  const html = '<a href="/a">a</a><img src="/_raw/b.png">' +
    '<a href="https://x.test/y">x</a><a href="//cdn.test/z">p</a><a href="#f">f</a>';
  const out = applyBase(html, '/repo');
  assert.ok(out.includes('href="/repo/a"'));
  assert.ok(out.includes('src="/repo/_raw/b.png"'));
  assert.ok(out.includes('href="https://x.test/y"'), 'external URL rewritten');
  assert.ok(out.includes('href="//cdn.test/z"'), 'protocol-relative URL rewritten');
  assert.ok(out.includes('href="#f"'), 'fragment rewritten');
});

test('export: refuses a vault with nothing public, rather than shipping an empty site', async () => {
  // The minimal vault is `gated`, so the anonymous ceiling (§12.2) denies
  // everything and the correct export is no export at all. Silently writing
  // an empty site would look like success.
  const out = path.join(tmpdir(), `basalt-empty-${process.pid}`);
  const v = new Vault(new FsTransport(MINIMAL));
  await v.load();
  await v.reindex();

  await assert.rejects(
    () => exportSite({ vault: v, out, clean: true }),
    (err) => err.code === 'NOTHING_PUBLIC',
    'a gated vault exported without complaint');

  await rm(out, { recursive: true, force: true });
});

test('export: --with-vault emits a re-servable filtered vault (§12.6)', async (t) => {
  const { out } = await exportDemo({ withVault: true });
  t.after(() => rm(out, { recursive: true, force: true }));

  assert.ok(existsSync(path.join(out, 'vault/basalt.yaml')));
  assert.ok(existsSync(path.join(out, 'vault/index/nodes.json')));

  // Its indexes describe the public subset only — they are rebuilt, not copied.
  const nodes = JSON.parse(
    await readFile(path.join(out, 'vault/index/nodes.json'), 'utf8'));
  assert.equal(nodes.entries.length, 5);
  assert.ok(!nodes.entries.some((e) => e.path.startsWith('Drafts/')),
    'the rebuilt index still lists a withheld node');

  // And it is a genuine vault: it loads and indexes.
  const exported = new Vault(new FsTransport(path.join(out, 'vault')));
  await exported.load();
  assert.equal(exported.manifest.publish.audience, 'public');
  const rebuilt = await exported.reindex();
  assert.equal(rebuilt.nodes.entries.length, 5);
});
