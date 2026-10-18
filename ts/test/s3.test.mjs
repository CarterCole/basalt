// S3-compatible transport against a real store, PROTOCOL §1.
//
// Skipped unless BASALT_S3_ENDPOINT is set, so `npm test` stays hermetic.
// To run against MinIO:
//
//   docker run -d --name basalt-minio -p 9000:9000 \
//     -e MINIO_ROOT_USER=basalttest -e MINIO_ROOT_PASSWORD=basalttest123 \
//     minio/minio:latest server /data
//   BASALT_S3_ENDPOINT=http://127.0.0.1:9000 \
//   BASALT_S3_KEY=basalttest BASALT_S3_SECRET=basalttest123 \
//   BASALT_S3_FLAVOR=minio npm test
//
// The load-bearing test here is `same vault over two transports yields
// identical indexes`: §0 claims index generation depends only on content, and
// a store whose `list` is unordered and whose etags are not content hashes is
// the thing most likely to disprove it.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { S3Transport } from '../src/transport/s3.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { validateKey } from '../src/keys.mjs';

const ENDPOINT = process.env.BASALT_S3_ENDPOINT;
const FLAVOR = process.env.BASALT_S3_FLAVOR ?? 'minio';
const BUCKET = process.env.BASALT_S3_BUCKET ?? `basalt-test-${Date.now()}`;
const skip = ENDPOINT ? false : 'set BASALT_S3_ENDPOINT to run S3 tests';

const VAULT_DIR = fileURLToPath(
  new URL('../../conformance/vaults/minimal/vault', import.meta.url));
const EXPECTED = fileURLToPath(
  new URL('../../conformance/vaults/minimal/expected/', import.meta.url));

function makeTransport(prefix = '') {
  return new S3Transport({
    bucket: BUCKET,
    prefix,
    endpoint: ENDPOINT,
    flavor: FLAVOR,
    accessKeyId: process.env.BASALT_S3_KEY,
    secretAccessKey: process.env.BASALT_S3_SECRET,
  });
}

/** Create the bucket if it is not already there. */
async function ensureBucket() {
  const sdk = await import('@aws-sdk/client-s3');
  const client = new sdk.S3Client({
    region: FLAVOR === 'r2' ? 'auto' : 'us-east-1',
    endpoint: ENDPOINT,
    forcePathStyle: FLAVOR === 'minio',
    credentials: {
      accessKeyId: process.env.BASALT_S3_KEY,
      secretAccessKey: process.env.BASALT_S3_SECRET,
    },
  });
  try {
    await client.send(new sdk.CreateBucketCommand({ Bucket: BUCKET }));
  } catch (err) {
    const ok = ['BucketAlreadyOwnedByYou', 'BucketAlreadyExists'];
    if (!ok.includes(err.name)) throw err;
  }
}

/** Copy the local conformance vault into the bucket through the transport. */
async function uploadVault(t) {
  const fs = new FsTransport(VAULT_DIR);
  const { keys } = await fs.list('');
  let n = 0;
  for (const key of keys) {
    const bytes = await fs.get(key);
    if (bytes === null) continue;
    await t.put(key, bytes);
    n++;
  }
  return n;
}

before(async () => {
  if (skip) return;
  await ensureBucket();
});

test('s3: the five operations round-trip', { skip }, async () => {
  const t = makeTransport('probe/');
  const body = Buffer.from('hexagonal columns\n', 'utf8');

  const stat = await t.put('content/Notes/Probe.md', body);
  assert.ok(stat.size === body.length, `size ${stat.size}`);

  const got = await t.get('content/Notes/Probe.md');
  assert.deepEqual(Buffer.from(got), body, 'get did not return what put stored');

  const head = await t.stat('content/Notes/Probe.md');
  assert.equal(head.size, body.length);
  assert.ok(head.etag, 'no etag');
  assert.ok(head.mtime, 'no mtime');

  const { keys } = await t.list('content/');
  assert.ok(keys.includes('content/Notes/Probe.md'), `list missed it: ${keys}`);

  // §1.2: delete returns nothing, so the effect is verified by reading back.
  await t.delete('content/Notes/Probe.md');
  assert.equal(await t.get('content/Notes/Probe.md'), null,
    'get after delete must be null, not an error');
  assert.equal(await t.stat('content/Notes/Probe.md'), null);
});

test('s3: a missing key is null, never a throw', { skip }, async () => {
  const t = makeTransport('probe/');
  assert.equal(await t.get('content/does/not/exist.md'), null);
  assert.equal(await t.stat('content/does/not/exist.md'), null);
  // §1.2: delete is idempotent and reports nothing about prior existence.
  // Deleting an absent key must simply succeed, and deleting twice must not
  // throw. This is where a filesystem-only implementation diverges: it can
  // tell you the key was absent, and S3 cannot.
  await t.delete('content/does/not/exist.md');
  await t.delete('content/does/not/exist.md');
});

test('s3: list with a delimiter yields common prefixes', { skip }, async () => {
  const t = makeTransport('delim/');
  for (const k of ['content/A/1.md', 'content/A/2.md', 'content/B/1.md', 'content/top.md']) {
    await t.put(k, Buffer.from('x'));
  }
  const { keys, prefixes } = await t.list('content/', { delimiter: '/' });
  assert.deepEqual(keys, ['content/top.md']);
  assert.deepEqual(prefixes.sort(), ['content/A/', 'content/B/']);
});

test('s3: conditional put surfaces a conflict rather than losing a write', { skip }, async () => {
  const t = makeTransport('cond/');
  const key = 'content/Notes/Race.md';
  const first = await t.put(key, Buffer.from('v1'));

  // §11.3: a failed condition must be a visible conflict. Last-write-wins on
  // a knowledge vault silently destroys work.
  await assert.rejects(
    () => t.put(key, Buffer.from('v2'), { ifMatch: '"deadbeef"' }),
    (err) => err.code === 'PRECONDITION_FAILED',
    'a stale if-match should have been refused',
  );

  // The correct etag succeeds.
  const second = await t.put(key, Buffer.from('v2'), { ifMatch: first.etag });
  assert.ok(second.etag);
  assert.equal(Buffer.from(await t.get(key)).toString(), 'v2');
});

test('s3: key validation happens before the network call', { skip }, async () => {
  const t = makeTransport('probe/');
  // §1.1 is the transport's job, not the store's: S3 would happily accept
  // "content/../escape.md" as a literal key.
  await assert.rejects(() => t.put('content/../escape.md', Buffer.from('x')),
    (e) => e.code === 'KEY_DOT_SEGMENT');
  await assert.rejects(() => t.put('content/a//b.md', Buffer.from('x')),
    (e) => e.code === 'KEY_EMPTY_SEGMENT');
});

test('s3: presign is capped and bound to one key (§12.4)', { skip }, async () => {
  const t = makeTransport('presign/');
  await t.put('content/Notes/Signed.md', Buffer.from('signed body\n'));

  await assert.rejects(() => t.presign('content/Notes/Signed.md', { ttlSeconds: 3600 }),
    /caps TTL at 300s/, 'the §12.4 TTL cap was not enforced');

  const url = await t.presign('content/Notes/Signed.md', { ttlSeconds: 120 });
  assert.match(url, /X-Amz-Signature=/, 'not a signed URL');
  const res = await fetch(url);
  assert.equal(res.status, 200, 'the presigned URL did not work');
  assert.equal((await res.text()).trim(), 'signed body');
});

test('s3: a full vault loads and indexes from the bucket', { skip }, async () => {
  const t = makeTransport('vault/');
  const uploaded = await uploadVault(t);
  assert.ok(uploaded >= 12, `only uploaded ${uploaded} objects`);

  const v = new Vault(t);
  await v.load();
  assert.equal(v.manifest.vault.id, '01JBQ7X8Z4N3VYK9M2T5HRWC6P');

  const idx = await v.reindex();
  assert.equal(idx.nodes.entries.length, 4);
  assert.equal(idx.digest.count, 4);

  // The ACLs loaded from the bucket must enforce exactly as on disk.
  assert.equal(v.can('u:carter', 'Notes/Columns.md', ['read']).allowed, true);
  assert.equal(v.can('u:reader', 'Notes/Columns.md', ['read']).allowed, false);
});

test('s3: same vault over two transports yields identical indexes', { skip }, async () => {
  // This is the claim in §0 under its hardest test: one vault read from a
  // local filesystem and from an object store whose list order is arbitrary
  // and whose etags are not content hashes.
  const s3Vault = new Vault(makeTransport('vault/'));
  await s3Vault.load();
  const fromS3 = await s3Vault.reindex();

  const fsVault = new Vault(new FsTransport(VAULT_DIR));
  await fsVault.load();
  const fromFs = await fsVault.reindex();

  for (const kind of ['nodes', 'links', 'backlinks', 'tags', 'digest', 'integrity']) {
    // §13.2 excludes `generated` and the per-entry `etag` from comparison —
    // and the etag exclusion is exactly what makes this pass, since MinIO and
    // the filesystem compute them differently.
    const norm = (o) => canonicalJson({
      ...o,
      generated: 'EXCLUDED',
      ...(Array.isArray(o.entries)
        ? { entries: o.entries.map((e) => ({ ...e, etag: 'EXCLUDED' })) }
        : {}),
    });
    assert.equal(norm(fromS3[kind]), norm(fromFs[kind]),
      `${kind}.json differs between the S3 and filesystem transports`);
  }

  assert.equal(fromS3.digest.root, fromFs.digest.root,
    'the merkle root must not depend on the transport');
});

test('s3: the bucket-built index matches the committed expected output', { skip }, async () => {
  const v = new Vault(makeTransport('vault/'));
  await v.load();
  const built = await v.reindex();

  for (const kind of ['nodes', 'links', 'backlinks', 'tags', 'digest', 'integrity']) {
    const file = `${EXPECTED}${kind}.json`;
    if (!existsSync(file)) continue;
    const want = JSON.parse(readFileSync(file, 'utf8'));
    const norm = (o) => canonicalJson({
      ...o,
      generated: 'EXCLUDED',
      ...(Array.isArray(o.entries)
        ? { entries: o.entries.map((e) => ({ ...e, etag: 'EXCLUDED' })) }
        : {}),
    });
    assert.equal(norm(built[kind]), norm(want),
      `${kind}.json built from the bucket differs from expected/`);
  }
});

test('s3: a prefixed vault does not see a sibling vault in the same bucket', { skip }, async () => {
  // Multi-tenancy: §3.1 allows a key prefix, and a vault must be unable to
  // read past it.
  const a = makeTransport('tenant-a/');
  const b = makeTransport('tenant-b/');
  await a.put('content/Notes/OnlyA.md', Buffer.from('a'));
  await b.put('content/Notes/OnlyB.md', Buffer.from('b'));

  const { keys: aKeys } = await a.list('content/');
  assert.deepEqual(aKeys, ['content/Notes/OnlyA.md']);
  assert.equal(await a.get('content/Notes/OnlyB.md'), null,
    'a prefixed transport read outside its prefix');
});
