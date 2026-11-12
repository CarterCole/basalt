// Runs conformance/cases/store/creation.yaml, PROTOCOL §12.7.
//
// The same file is run by the Rust and Python runners, so the three
// implementations' write paths agree on every case it holds. Expectations live
// in the corpus, never here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import YAML from 'yaml';

import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { storeObject, checkProvenanceLabel, normalizeCaller } from '../src/store.mjs';
import { splitFrontmatter } from '../src/frontmatter.mjs';
import { corpusPath } from './support/spec.mjs';

const CORPUS = corpusPath('');
const FIXTURE = path.join(CORPUS, 'vaults/minimal/vault');
const suite = YAML.parse(readFileSync(path.join(CORPUS, 'cases/store/creation.yaml'), 'utf8'));

const ULID = /^[0-9a-hjkmnp-tv-z]{26}$/;
const AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function bytesOf(req) {
  return req.base64 !== undefined ? Buffer.from(req.base64, 'base64') : Buffer.from(req.text ?? '', 'utf8');
}

function storeArgs(req) {
  return {
    principal: req.principal ?? null,
    path: req.path,
    bytes: bytesOf(req),
    title: req.title,
    alt: req.alt,
    provenance: req.provenance ?? undefined,
  };
}

for (const c of suite.cases) {
  test(`store corpus: ${c.name}`, async (t) => {
    if (c.kind === 'label') {
      let ok = true;
      try { checkProvenanceLabel('agent', c.value); } catch { ok = false; }
      assert.equal(ok, c.ok);
      return;
    }
    if (c.kind === 'caller') {
      let out;
      try { out = normalizeCaller(c.value); } catch { out = null; }
      assert.equal(out, c.out);
      return;
    }

    const dir = await mkdtemp(path.join(tmpdir(), 'basalt-store-corpus-'));
    t.after(() => rm(dir, { recursive: true, force: true }));
    await cp(FIXTURE, dir, { recursive: true });
    const v = new Vault(new FsTransport(dir));
    await v.load();
    await v.reindex({ write: true });
    for (const g of c.given ?? []) await storeObject(v, storeArgs(g));

    const req = c.request;
    const key = `content/${req.path}`;
    const indexBefore = await readFile(path.join(dir, 'index/nodes.json'), 'utf8');
    const sidecarPath = (p) => path.join(dir, 'meta/folders', path.posix.dirname(p), 'entries.yaml');
    const sidecarBefore = req.path.includes('/')
      ? YAML.parse(await readFile(sidecarPath(req.path), 'utf8').catch(() => 'entries: {}')) : null;

    const fileAt = async () => {
      const st = await stat(path.join(dir, key)).catch(() => null);
      return st?.isFile() ? readFile(path.join(dir, key)) : null;
    };
    if (c.refused) {
      const before = await fileAt();
      let err;
      try { await storeObject(v, storeArgs(req)); } catch (e) { err = e; }
      assert.ok(err, 'expected a refusal');
      assert.equal(err.code, c.refused, err.message);
      assert.deepEqual(await fileAt(), before, 'the key is as it was');
      assert.equal(await readFile(path.join(dir, 'index/nodes.json'), 'utf8'), indexBefore);
      return;
    }

    const r = await storeObject(v, storeArgs(req));
    assert.equal(r.kind, c.stored);
    assert.match(r.id, ULID);

    const fresh = new Vault(new FsTransport(dir));
    await fresh.load();
    const idx = await fresh.reindex();
    const entry = idx.nodes.entries.find((e) => e.path === req.path);
    assert.ok(entry, 'the object is indexed');
    assert.equal(entry.id, r.id, 'bound to the id the store returned');
    assert.ok(!idx.nodes.entries.some((e) => e.path !== req.path && e.id === r.id), 'the id is fresh');
    const stored = JSON.parse(await readFile(path.join(dir, 'index/nodes.json'), 'utf8'));
    assert.ok(stored.entries.some((e) => e.path === req.path && e.id === r.id), 'stored indexes are fresh');
    if (c.title !== undefined) assert.equal(entry.title, c.title);

    const onDisk = await readFile(path.join(dir, key));
    let stamp;
    if (c.stored === 'note') {
      const fm = YAML.parse(splitFrontmatter(onDisk.toString('utf8')).raw);
      assert.equal(fm.basalt.id, r.id);
      stamp = fm.basalt.created_by;
    } else {
      assert.deepEqual(onDisk, bytesOf(req), 'stored byte for byte');
      const sc = YAML.parse(await readFile(sidecarPath(req.path), 'utf8'));
      const own = sc.entries[path.posix.basename(req.path)];
      assert.equal(own.id, r.id);
      if (c.alt !== undefined) assert.equal(own.alt, c.alt);
      for (const name of c.sidecar_keeps ?? []) {
        assert.deepEqual(sc.entries[name], sidecarBefore.entries[name], `${name} kept`);
      }
      stamp = own.created_by;
    }
    if (c.created_by === null) assert.equal(stamp, undefined);
    else if (c.created_by !== undefined) {
      assert.match(stamp.at, AT);
      const { at, ...rest } = stamp;
      assert.deepEqual(rest, c.created_by);
    }
  });
}
