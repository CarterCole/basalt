// Regression: words that name Object.prototype members must index and search
// like any other word. Before the fix, one note containing "constructor"
// made the whole vault unindexable ("terms[t].push is not a function").

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSearchIndex } from '../src/indexer.mjs';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { corpusPath } from './support/spec.mjs';

const VAULT = corpusPath('vaults/minimal/vault');

test('search index: prototype-colliding words become ordinary terms', () => {
  const idx = buildSearchIndex({
    nodes: [
      { id: '01a', text: 'x', body: 'the constructor and __proto__ and zebra' },
      { id: '01b', text: 'y', body: 'another constructor' },
    ],
    vaultId: 'V',
    sourceDigest: 'sha256:0',
    isPublic: () => true,
  });
  for (const word of ['constructor', '__proto__', 'zebra']) {
    assert.ok(Object.hasOwn(idx.terms, word), `${word} should be an own term`);
  }
  assert.deepEqual(idx.terms.constructor.map((p) => p.node), ['01a', '01b']);
  assert.deepEqual(idx.terms.zebra, [{ node: '01a', tf: 1 }]);
  assert.equal(Object.getPrototypeOf(idx.terms), Object.prototype);
});

test('search: a query for a prototype member returns no hits, not an error', async () => {
  const v = new Vault(new FsTransport(VAULT));
  await v.load();
  await v.reindex();
  for (const q of ['constructor', '__proto__', 'hasownproperty']) {
    const r = v.search('u:editor', q);
    assert.equal(r.status, 200);
    assert.deepEqual(r.hits, []);
  }
});
