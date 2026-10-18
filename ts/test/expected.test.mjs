// Byte-exact index reproduction against the stored corpus, PROTOCOL §13/§14.2.
//
// This is the test every implementation must pass to claim L2. It is what
// makes "two independent implementations agree" a mechanical fact rather than
// a matter of opinion.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { canonicalJson } from '../src/canonical.mjs';

const ROOT = fileURLToPath(new URL('../../conformance/vaults/minimal/', import.meta.url));
const KINDS = ['nodes', 'links', 'backlinks', 'tags', 'search', 'digest', 'integrity'];

test('expected: a rebuild reproduces every stored index byte for byte', async () => {
  const v = new Vault(new FsTransport(ROOT + 'vault'));
  await v.load();
  const built = await v.reindex();

  for (const kind of KINDS) {
    const file = `${ROOT}expected/${kind}.json`;
    assert.ok(existsSync(file), `missing expected/${kind}.json`);

    // §13.2: `generated` is excluded from comparison. Everything else —
    // key order, indentation, escaping, element order — must match exactly.
    const want = readFileSync(file, 'utf8');
    const got = canonicalJson({ ...built[kind], generated: '1970-01-01T00:00:00Z' });

    if (got !== want) {
      // Report the first differing line rather than dumping two whole files.
      const g = got.split('\n');
      const w = want.split('\n');
      const at = g.findIndex((line, i) => line !== w[i]);
      assert.fail(
        `index/${kind}.json differs at line ${at + 1}\n` +
        `  expected: ${w[at] ?? '<end of file>'}\n` +
        `  actual:   ${g[at] ?? '<end of file>'}`);
    }
  }
});

test('expected: etag is excluded from comparison but content_hash is not', async () => {
  // §10.1 — etags differ between S3 implementations for multipart uploads and
  // are useless across stores, so the hash is authoritative. A stored index
  // must therefore never depend on an etag value.
  const stored = JSON.parse(readFileSync(`${ROOT}expected/nodes.json`, 'utf8'));
  for (const e of stored.entries) {
    assert.ok(e.content_hash?.startsWith('sha256:'),
      `${e.path} has no content_hash`);
  }
});

test('expected: the digest root in nodes.json matches digest.json', async () => {
  const nodes = JSON.parse(readFileSync(`${ROOT}expected/nodes.json`, 'utf8'));
  const digest = JSON.parse(readFileSync(`${ROOT}expected/digest.json`, 'utf8'));
  assert.equal(nodes.source_digest, digest.root,
    'every index must cite the same source digest (§10)');
  for (const kind of KINDS) {
    const o = JSON.parse(readFileSync(`${ROOT}expected/${kind}.json`, 'utf8'));
    assert.equal(o.source_digest, digest.root, `${kind}.json cites a different digest`);
    assert.equal(o.basalt, 1);
    assert.equal(o.vault, '01JBQ7X8Z4N3VYK9M2T5HRWC6P');
  }
});

test('expected: a gated vault leaks no text into search.json (§8.8)', async () => {
  const search = JSON.parse(readFileSync(`${ROOT}expected/search.json`, 'utf8'));
  assert.deepEqual(search.terms, {},
    'the committed search index contains text from a non-public vault');
});
