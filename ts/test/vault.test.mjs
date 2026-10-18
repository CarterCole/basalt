// End-to-end index build over the `minimal` conformance vault, PROTOCOL §14.2.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { canonicalJson } from '../src/canonical.mjs';

const VAULT = fileURLToPath(
  new URL('../../conformance/vaults/minimal/vault', import.meta.url));

async function loaded() {
  const v = new Vault(new FsTransport(VAULT));
  await v.load();
  await v.reindex();
  return v;
}

test('vault: loads the manifest and principals', async () => {
  const v = await loaded();
  assert.equal(v.manifest.basalt, 1);
  assert.equal(v.manifest.vault.id, '01JBQ7X8Z4N3VYK9M2T5HRWC6P');
  assert.equal(v.manifest.publish.audience, 'gated');
  // Nested membership: u:editor ∈ g:editors ∈ g:staff (§7.2).
  assert.ok(v.principals.groupsOf('u:editor').has('g:staff'));
});

test('vault: indexes every content object', async () => {
  const v = await loaded();
  const paths = v.indexes.nodes.entries.map((e) => e.path);
  assert.deepEqual(paths, [
    'Assets/diagram.png',
    'Notes/Columns.md',
    'Notes/Hexes.md',
    'Notes/Start Here.md',
  ]);
  // §5.1: kind is a function of the key alone.
  const kinds = Object.fromEntries(v.indexes.nodes.entries.map((e) => [e.path, e.kind]));
  assert.equal(kinds['Notes/Hexes.md'], 'note');
  assert.equal(kinds['Assets/diagram.png'], 'asset');
});

test('vault: an asset takes its id from the entry sidecar (§6.1)', async () => {
  const v = await loaded();
  const png = v.indexes.nodes.entries.find((e) => e.path === 'Assets/diagram.png');
  assert.equal(png.id, '01jbq100000000000000000004');
  assert.equal(png.title, 'Column jointing, annotated');
});

test('vault: resolves links and records the dangling one', async () => {
  const v = await loaded();
  const hexes = v.indexes.nodes.entries.find((e) => e.path === 'Notes/Hexes.md');
  const edges = v.indexes.links.entries.filter((e) => e.from === hexes.id);

  const raws = edges.map((e) => e.raw);
  // The fenced [[Fenced]] must not appear (§9.1).
  assert.ok(!raws.includes('Fenced'), 'a fenced link became an edge');
  assert.deepEqual(raws, ['Start Here', 'Columns', 'Does Not Exist']);

  const dangling = edges.find((e) => e.raw === 'Does Not Exist');
  assert.equal(dangling.to, null, 'a dangling link must keep its raw target, not vanish');

  const anchored = edges.find((e) => e.raw === 'Columns');
  assert.equal(anchored.anchor, 'jointing');
  assert.equal(anchored.anchor_resolved, true, '## Jointing should satisfy #jointing');
});

test('vault: embeds and externals are distinguished', async () => {
  const v = await loaded();
  const start = v.indexes.nodes.entries.find((e) => e.path === 'Notes/Start Here.md');
  const edges = v.indexes.links.entries.filter((e) => e.from === start.id);
  const byKind = Object.fromEntries(edges.map((e) => [e.raw, e.kind]));
  assert.equal(byKind['diagram.png'], 'embed');
  assert.equal(byKind['https://example.com/spec'], 'external');
  assert.equal(byKind['Hexes'], 'wiki');
  // An alias resolves to the same node as its canonical name (§9.2 step 4).
  const hexes = v.indexes.nodes.entries.find((e) => e.path === 'Notes/Hexes.md');
  assert.equal(edges.find((e) => e.raw === 'Hexes').to, hexes.id);
});

test('vault: backlinks are the exact inverse of links (§10.3)', async () => {
  const v = await loaded();
  const recomputed = {};
  for (const e of v.indexes.links.entries) {
    if (!e.to) continue;
    (recomputed[e.to] ??= new Set()).add(e.from);
  }
  for (const [to, froms] of Object.entries(recomputed)) {
    assert.deepEqual(
      v.indexes.backlinks.entries[to], [...froms].sort(),
      `backlinks for ${to} disagree with links.json`);
  }
});

test('vault: tags carry the implied-parent closure (§9.6)', async () => {
  const v = await loaded();
  const tags = Object.keys(v.indexes.tags.entries);
  assert.ok(tags.includes('nav'), '#nav/root must imply #nav');
  assert.ok(tags.includes('nav/root'));
  assert.ok(tags.includes('geometry'));
});

test('vault: the digest is stable and order-independent (§10.6)', async () => {
  const v = await loaded();
  const first = v.indexes.digest.root;
  const again = await v.reindex();
  assert.equal(again.digest.root, first, 'two passes over identical content differ');
  assert.equal(v.indexes.nodes.source_digest, first);
  assert.equal(v.indexes.digest.count, 4);
});

test('vault: a rebuild is byte-identical except for §13.2 fields', async () => {
  const v = new Vault(new FsTransport(VAULT));
  await v.load();
  const a = await v.reindex();
  const b = await v.reindex();
  for (const kind of ['nodes', 'links', 'backlinks', 'tags', 'digest']) {
    const strip = (o) => canonicalJson({ ...o, generated: 'EXCLUDED' });
    assert.equal(strip(a[kind]), strip(b[kind]),
      `${kind}.json is not reproducible across passes`);
  }
});

test('vault: canonical JSON sorts keys and ends with one newline (§13.1)', async () => {
  const v = await loaded();
  const json = canonicalJson(v.indexes.nodes);
  assert.ok(json.endsWith('}\n'));
  assert.ok(!json.endsWith('}\n\n'));
  const top = [...json.matchAll(/^  "(\w+)":/gm)].map((m) => m[1]);
  assert.deepEqual(top, [...top].sort(), 'top-level keys are not sorted');
});

// ---------------------------------------------------------------- security

test('security: the inherited-deny + explicit-allow node (§8.4)', async () => {
  const v = await loaded();
  // meta/acl/Notes/acl.yaml denies `read` to everyone on Columns.md and
  // allows full_control to u:carter.
  assert.equal(v.can('u:carter', 'Notes/Columns.md', ['read']).allowed, true);
  assert.equal(v.can('u:reader', 'Notes/Columns.md', ['read']).allowed, false);
  // The sibling note is readable: the deny is scoped to the one entry.
  assert.equal(v.can('u:reader', 'Notes/Hexes.md', ['read']).allowed, true);
});

test('security: gated audience denies anonymous outright (§12.2)', async () => {
  const v = await loaded();
  const d = v.can('anonymous', 'Notes/Hexes.md', ['read']);
  assert.equal(d.allowed, false);
  assert.equal(d.decisions.read.by, 'audience_ceiling');
});

test('security: readNode returns 403 vs 404 per discoverability (§12.3)', async () => {
  const v = await loaded();
  // u:reader may list Notes/ but not read Columns.md → it knows it exists.
  const forbidden = await v.readNode('u:reader', 'Notes/Columns.md');
  assert.equal(forbidden.status, 403);
  // A path that does not exist at all → 404, never 403.
  const missing = await v.readNode('u:carter', 'Notes/Nope.md');
  assert.equal(missing.status, 404);
  const ok = await v.readNode('u:carter', 'Notes/Columns.md');
  assert.equal(ok.status, 200);
  assert.match(ok.text, /Cooling contraction/);
});

test('security: listFolder hides what the principal cannot read', async () => {
  const v = await loaded();
  const asReader = v.listFolder('u:reader', 'Notes/');
  const asOwner = v.listFolder('u:carter', 'Notes/');
  const paths = (r) => r.entries.map((e) => e.path);
  assert.ok(!paths(asReader).includes('Notes/Columns.md'));
  assert.ok(paths(asOwner).includes('Notes/Columns.md'));
});

test('security: a link to an unreadable node is redacted, not dropped (§9.5)', async () => {
  const v = await loaded();
  // Hexes.md links to Columns.md, which u:reader cannot read.
  const r = v.links('u:reader', 'Notes/Hexes.md');
  assert.equal(r.status, 200);
  const edge = r.out.find((e) => e.raw === 'Columns');
  assert.ok(edge, 'the edge was dropped entirely');
  assert.equal(edge.to, 'redacted');
  assert.equal(edge.target.title, null, 'redact_titles is on, so the title must be withheld');
  // The owner sees it in full.
  const owner = v.links('u:carter', 'Notes/Hexes.md').out.find((e) => e.raw === 'Columns');
  assert.equal(owner.target.title, 'Columns');
});

test('security: search postings exclude non-public text (§8.8)', async () => {
  const v = await loaded();
  // The vault is `gated`, so no node grants read to `everyone`/anonymous and
  // the search index must carry no text at all.
  assert.deepEqual(v.indexes.search.terms, {},
    'a gated vault leaked text into search.json');
  assert.equal(v.indexes.search.stopwords, 'basalt-en-v1');
});

test('security: effective rights name the deciding ACE (§8.7)', async () => {
  const v = await loaded();
  const e = v.effective('u:carter', 'Notes/Columns.md');
  assert.ok(e.granted.includes('read'));
  assert.ok(e.granted.includes('write_acl'), 'full_control should expand');
  const denied = v.effective('u:reader', 'Notes/Columns.md');
  assert.ok(!denied.granted.includes('read'));
  assert.ok(denied.decisions.read.by, 'no deciding ACE reported');
});

test('vault: refuses to write an empty index over a non-empty one (§10.7)', async () => {
  // The failure this guards against is a transport pointed at the wrong
  // bucket, prefix or S3 addressing style, which characteristically returns
  // an empty listing rather than an error.
  const { MemoryTransport } = await import('../src/transport/memory.mjs');
  const t = new MemoryTransport();

  // Seed a real vault and index it.
  const fs = new FsTransport(VAULT);
  for (const key of (await fs.list('')).keys) {
    await t.put(key, await fs.get(key));
  }
  const v = new Vault(t);
  await v.load();
  const full = await v.reindex({ write: true });
  assert.equal(full.nodes.entries.length, 4);

  // Now empty the content tree, simulating a listing that came back empty.
  for (const key of (await t.list('content/')).keys) await t.delete(key);

  await assert.rejects(
    () => v.reindex({ write: true }),
    (err) => err.code === 'EMPTY_INDEX_REFUSED',
    'an empty index was written over a good one');

  // The stored index is untouched.
  const stored = JSON.parse(Buffer.from(await t.get('index/nodes.json')).toString());
  assert.equal(stored.entries.length, 4, 'the stored index was damaged');

  // force overrides, because sometimes the vault really is empty.
  const forced = await v.reindex({ write: true, force: true });
  assert.equal(forced.nodes.entries.length, 0);
});
