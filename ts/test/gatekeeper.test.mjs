// Gatekeeper behavior, PROTOCOL §12.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { Gatekeeper } from '../src/gatekeeper.mjs';

const VAULT = fileURLToPath(
  new URL('../../conformance/vaults/minimal/vault', import.meta.url));

/** A gatekeeper that reads the principal from a test-only header. */
async function serve() {
  const v = new Vault(new FsTransport(VAULT));
  await v.load();
  await v.reindex();
  const g = new Gatekeeper(v, {
    identify: (req) => req.headers['x-test-principal'] ?? 'anonymous',
  });
  await g.listen(0);
  const { port } = g.server.address();
  const call = async (path, principal) => {
    const res = await fetch(`http://127.0.0.1:${port}${path}`, {
      headers: principal ? { 'x-test-principal': principal } : {},
      redirect: 'manual',
    });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { body = text; }
    return { status: res.status, body, headers: res.headers };
  };
  return { v, g, call };
}

test('gatekeeper: serves a readable node and its links', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/node/Notes%2FHexes.md', 'u:reader');
  assert.equal(r.status, 200);
  assert.equal(r.body.node.title, 'Hexagons');
  assert.match(r.body.text, /Back to/);
  assert.equal(r.headers.get('x-basalt-vault'), '01JBQ7X8Z4N3VYK9M2T5HRWC6P');
  assert.ok(r.headers.get('x-basalt-index-state'));
});

test('gatekeeper: 403 when discoverable, 404 when not (§12.3)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  // u:reader may list Notes/ so it knows Columns.md exists, but cannot read it.
  const forbidden = await call('/api/v1/node/Notes%2FColumns.md', 'u:reader');
  assert.equal(forbidden.status, 403);

  // A path that does not exist must be 404 — never 403, which would confirm
  // the path to someone not allowed to discover it.
  const missing = await call('/api/v1/node/Notes%2FNope.md', 'u:reader');
  assert.equal(missing.status, 404);

  const owner = await call('/api/v1/node/Notes%2FColumns.md', 'u:carter');
  assert.equal(owner.status, 200);
});

test('gatekeeper: anonymous is denied under a gated audience (§12.2)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/node/Notes%2FHexes.md');
  assert.ok(r.status === 403 || r.status === 404,
    `anonymous got ${r.status} on a gated vault`);
});

test('gatekeeper: never serves the protocol trees (§12.4)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  // Even as the vault owner: these leak the private half of the graph (§8.8).
  for (const target of [
    'index/nodes.json', 'index/links.json', 'meta/acl/Notes/acl.yaml',
    'principals/users.yaml', 'basalt.yaml',
  ]) {
    const r = await call(`/api/v1/raw/${encodeURIComponent(target)}`, 'u:carter');
    assert.equal(r.status, 404, `${target} was served`);
  }
});

test('gatekeeper: raw bytes carry the right media type', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/raw/Notes%2FHexes.md', 'u:reader');
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /text\/markdown/);
});

test('gatekeeper: listing is filtered per principal', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const reader = await call('/api/v1/list/Notes%2F', 'u:reader');
  const owner = await call('/api/v1/list/Notes%2F', 'u:carter');
  const paths = (r) => r.body.entries.map((e) => e.path);

  assert.ok(!paths(reader).includes('Notes/Columns.md'));
  assert.ok(paths(owner).includes('Notes/Columns.md'));
});

test('gatekeeper: the response cache is keyed by subject set (§12.5)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  // THE leak test. Warm the cache as the owner, then ask as the reader: if
  // the cache key omits the subject set, the reader is served the owner's
  // visibility and sees a note it must not know the contents of.
  const owner = await call('/api/v1/list/Notes%2F', 'u:carter');
  assert.ok(owner.body.entries.some((e) => e.path === 'Notes/Columns.md'));

  const reader = await call('/api/v1/list/Notes%2F', 'u:reader');
  assert.ok(
    !reader.body.entries.some((e) => e.path === 'Notes/Columns.md'),
    'the cache served one principal’s visibility to another',
  );

  // And the reverse order, in case the first principal seen wins.
  const g2 = await serve();
  t.after(() => g2.g.close());
  const r2 = await g2.call('/api/v1/list/Notes%2F', 'u:reader');
  const o2 = await g2.call('/api/v1/list/Notes%2F', 'u:carter');
  assert.ok(!r2.body.entries.some((e) => e.path === 'Notes/Columns.md'));
  assert.ok(o2.body.entries.some((e) => e.path === 'Notes/Columns.md'));
});

test('gatekeeper: the tree is pruned to what the principal may see', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/tree', 'u:reader');
  assert.equal(r.status, 200);
  const json = JSON.stringify(r.body);
  assert.ok(!json.includes('Columns.md'), 'an unreadable node appeared in the tree');
  assert.ok(json.includes('Hexes.md'));
});

test('gatekeeper: links to unreadable nodes come back redacted (§9.5)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/links/Notes%2FHexes.md', 'u:reader');
  assert.equal(r.status, 200);
  const edge = r.body.out.find((e) => e.raw === 'Columns');
  assert.ok(edge, 'the edge was dropped instead of redacted');
  assert.equal(edge.to, 'redacted');
  assert.equal(edge.target.title, null);
});

test('gatekeeper: effective rights need read_acl (§8.7)', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  // u:carter holds full_control on Columns.md, which includes read_acl.
  const allowed = await call(
    '/api/v1/effective?path=Notes%2FColumns.md&principal=u:reader', 'u:carter');
  assert.equal(allowed.status, 200);
  assert.ok(!allowed.body.granted.includes('read'),
    'u:reader should not hold read on Columns.md');
  assert.ok(allowed.body.decisions.read.by, 'no deciding ACE reported');

  // u:reader cannot inspect anyone's rights on it.
  const denied = await call('/api/v1/effective?path=Notes%2FColumns.md', 'u:reader');
  assert.equal(denied.status, 403);
});

test('gatekeeper: search results are filtered, not just ranked', async (t) => {
  const { g, call } = await serve();
  t.after(() => g.close());

  const r = await call('/api/v1/search?q=cooling', 'u:reader');
  assert.equal(r.status, 200);
  // The vault is gated, so §8.8 left search.json empty; nothing may leak.
  assert.deepEqual(r.body.hits, []);
});

test('gatekeeper: rejects writes', async (t) => {
  const { g } = await serve();
  t.after(() => g.close());
  const { port } = g.server.address();
  const res = await fetch(`http://127.0.0.1:${port}/api/v1/node/Notes%2FHexes.md`,
    { method: 'POST' });
  assert.equal(res.status, 405);
});
