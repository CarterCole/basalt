// Storing notes, images and files, PROTOCOL §12.7.
//
// Every test works on a scratch copy of the `minimal` conformance vault: a
// write test that touched the fixture would turn the corpus into whatever the
// last run left behind.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { cp, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import { createHash } from 'node:crypto';

import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { MemoryTransport } from '../src/transport/memory.mjs';
import { Surface } from '../src/serve/core.mjs';
import { mcpMethods } from '../src/serve/mcp.mjs';
import { storeObject, normalizeCaller, MAX_STORE_BYTES } from '../src/store.mjs';
import YAML from 'yaml';
import { canonicalJson } from '../src/canonical.mjs';

const run = promisify(execFile);

const FIXTURE = fileURLToPath(
  new URL('../../conformance/vaults/minimal/vault', import.meta.url));
const CLI = fileURLToPath(new URL('../bin/basalt.mjs', import.meta.url));

/** A scratch copy of the fixture, opened and indexed. */
async function scratch(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'basalt-store-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await cp(FIXTURE, dir, { recursive: true });
  const v = new Vault(new FsTransport(dir));
  await v.load();
  await v.reindex();
  return { dir, v };
}

// A PNG signature plus bytes that are not valid UTF-8, so any code that
// decodes to a string on the way through corrupts it.
const PNG = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  Buffer.from([0xff, 0xfe, 0x00, 0x80, 0xc3, 0x28, 0xfd]),
]);

const sha = (b) => 'sha256:' + createHash('sha256').update(b).digest('hex');
const node = (v, p) => v.indexes.nodes.entries.find((e) => e.path === p);
const refusal = async (promise) => promise.then(
  () => assert.fail('expected a refusal'), (err) => err);

// ------------------------------------------------------------- what is stored

test('store: a note gets an id and a title, and is indexed and readable', async (t) => {
  const { v } = await scratch(t);
  const body = '# Basalt idea\n\nSee [[Columns]] and the #geology angle.\n';
  const r = await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Idea.md', bytes: Buffer.from(body), title: 'The idea',
  });

  assert.equal(r.created, true);
  assert.equal(r.kind, 'note');
  assert.match(r.id, /^[0-9a-hjkmnp-tv-z]{26}$/);

  const onDisk = await readFile(path.join(v.t.root, 'content/Notes/Idea.md'), 'utf8');
  assert.match(onDisk, new RegExp(`^---\\nbasalt:\\n  id: ${r.id}\\ntitle: The idea\\n---\\n`));
  assert.ok(onDisk.endsWith(body), 'the body is kept byte for byte');
  assert.equal(r.content_hash, sha(Buffer.from(onDisk)));

  const n = node(v, 'Notes/Idea.md');
  assert.equal(n.id, r.id);
  assert.equal(n.title, 'The idea');
  assert.deepEqual(n.tags, ['geology']);
  assert.ok(v.indexes.links.entries.some((e) => e.from === r.id && e.raw === 'Columns'));

  // Stored indexes match the content (§10.6) and a rebuild reproduces them:
  // a store must leave the vault exactly as fresh as it found it.
  assert.equal((await v.indexState()).fresh, true);
  const stored = JSON.parse(await readFile(path.join(v.t.root, 'index/nodes.json'), 'utf8'));
  const rebuilt = await v.reindex();
  const norm = (o) => canonicalJson({ ...o, generated: 'EXCLUDED' });
  assert.equal(norm(stored), norm(rebuilt.nodes));
  const unbound = rebuilt.integrity.entries.filter((i) => i.code === 'UNBOUND_NODE');
  assert.deepEqual(unbound, []);
});

test('store: an image round-trips byte for byte and is bound by a sidecar', async (t) => {
  const { v } = await scratch(t);
  const r = await storeObject(v, {
    principal: null, path: 'Assets/pixel.png', bytes: PNG,
    title: 'One pixel', alt: 'A single transparent pixel',
  });

  assert.equal(r.kind, 'asset');
  assert.equal(r.media_type, 'image/png');
  assert.equal(r.size, PNG.length);
  assert.deepEqual(await readFile(path.join(v.t.root, 'content/Assets/pixel.png')), PNG);

  const n = node(v, 'Assets/pixel.png');
  assert.equal(n.id, r.id);
  assert.equal(n.title, 'One pixel');
  assert.equal(n.content_hash, sha(PNG));

  const sidecar = await readFile(path.join(v.t.root, 'meta/folders/Assets/entries.yaml'), 'utf8');
  assert.match(sidecar, /alt: A single transparent pixel/);
  // The entry that was already there is untouched.
  assert.match(sidecar, /diagram\.png:\n\s+id: 01jbq100000000000000000004/);

  const read = await v.readNode('u:reader', 'Assets/pixel.png');
  assert.equal(read.status, 200);
  assert.deepEqual(read.bytes, PNG);
  assert.equal(read.text, null);
});

test('store: any other file is stored whole, with a sidecar', async (t) => {
  const { v } = await scratch(t);
  const zip = Buffer.from([0x50, 0x4b, 0x03, 0x04, 0xff, 0x00, 0xfe, 0x80]);
  const pdf = Buffer.from('%PDF-1.7\n\xff\xfe\x00binary', 'latin1');
  const data = Buffer.from('{"rows": [1, 2, 3]}\n');
  const a = await storeObject(v, { path: 'Files/bundle.zip', bytes: zip });
  const b = await storeObject(v, { path: 'Files/report.pdf', bytes: pdf });
  const c = await storeObject(v, { path: 'Files/rows.json', bytes: data });

  assert.deepEqual([a.kind, b.kind, c.kind], ['opaque', 'asset', 'data']);
  for (const [p, bytes, r] of [['bundle.zip', zip, a], ['report.pdf', pdf, b], ['rows.json', data, c]]) {
    assert.deepEqual(await readFile(path.join(v.t.root, 'content/Files', p)), bytes);
    assert.equal(node(v, `Files/${p}`).id, r.id);
  }
  assert.deepEqual(
    v.indexes.integrity.entries.filter((i) => i.code === 'UNBOUND_NODE'), []);
});

test('store: a hand-edited sidecar keeps its comments and neighbours', async (t) => {
  const { v, dir } = await scratch(t);
  const file = path.join(dir, 'meta/folders/Assets/entries.yaml');
  const original = await readFile(file, 'utf8');
  await writeFile(file, `# curated by hand - do not regenerate\n${original}`);

  await storeObject(v, { path: 'Assets/second.png', bytes: PNG });
  const after = await readFile(file, 'utf8');
  assert.ok(after.startsWith('# curated by hand - do not regenerate\n'));
  assert.match(after, /diagram\.png:/);
  assert.match(after, /second\.png:/);
});

test('store: an entry left behind by a deleted object is replaced, not inherited', async (t) => {
  const { v, dir } = await scratch(t);
  const file = path.join(dir, 'meta/folders/Assets/entries.yaml');
  await writeFile(file, (await readFile(file, 'utf8')) +
    '  ghost.png:\n    id: 01jbq1000000000000000000zz\n    title: gone\n');
  const r = await storeObject(v, { path: 'Assets/ghost.png', bytes: PNG });
  assert.notEqual(r.id, '01jbq1000000000000000000zz');
  assert.equal(node(v, 'Assets/ghost.png').id, r.id);
});

test('store: several at once all land, with no sidecar entry lost', async (t) => {
  const { v } = await scratch(t);
  const names = ['a', 'b', 'c', 'd', 'e', 'f'].map((n) => `Assets/${n}.png`);
  const results = await Promise.all(names.map((p) => storeObject(v, { path: p, bytes: PNG })));
  assert.equal(new Set(results.map((r) => r.id)).size, names.length);
  for (const [i, p] of names.entries()) assert.equal(node(v, p).id, results[i].id);
  assert.deepEqual(
    v.indexes.integrity.entries.filter((i) => i.code === 'UNBOUND_NODE'), []);
});

test('store: reindex:false defers the index until asked', async (t) => {
  const { v } = await scratch(t);
  await storeObject(v, { path: 'Assets/later.png', bytes: PNG, reindex: false });
  assert.equal(node(v, 'Assets/later.png'), undefined);
  assert.equal((await v.indexState()).fresh, false);
  await v.reindex({ write: true });
  assert.ok(node(v, 'Assets/later.png'));
  assert.equal((await v.indexState()).fresh, true);
});

test('store: works over any transport, create-only included', async () => {
  // The same fixture in memory, whose listing order is deliberately shuffled.
  const t = new MemoryTransport();
  const walk = async (dir, rel = '') => {
    for (const e of await readdir(path.join(dir, rel), { withFileTypes: true })) {
      const key = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) await walk(dir, key);
      else await t.put(key, await readFile(path.join(dir, key)));
    }
  };
  await walk(FIXTURE);
  const v = new Vault(t);
  await v.load();
  await v.reindex();

  const r = await storeObject(v, { path: 'Assets/mem.png', bytes: PNG, title: 'In memory' });
  assert.deepEqual(Buffer.from(await t.get('content/Assets/mem.png')), PNG);
  assert.equal(node(v, 'Assets/mem.png').id, r.id);
  const err = await refusal(storeObject(v, { path: 'Assets/mem.png', bytes: PNG }));
  assert.equal(err.code, 'conflict');
});

// ---------------------------------------------------------------- refusals

test('store: never overwrites, and a refusal leaves no trace', async (t) => {
  const { v, dir } = await scratch(t);
  const before = await readFile(path.join(dir, 'content/Notes/Hexes.md'));
  const indexBefore = await readFile(path.join(dir, 'index/nodes.json')).catch(() => null);

  const err = await refusal(storeObject(v, {
    principal: 'u:editor', path: 'Notes/Hexes.md', bytes: Buffer.from('# replaced') }));
  assert.equal(err.code, 'conflict');
  assert.equal(err.status, 409);
  assert.deepEqual(await readFile(path.join(dir, 'content/Notes/Hexes.md')), before);
  assert.deepEqual(await readFile(path.join(dir, 'index/nodes.json')).catch(() => null), indexBefore);
});

test('store: refuses names that would collide (§2.2)', async (t) => {
  const { v } = await scratch(t);
  await storeObject(v, { path: 'Notes/Deep/x.md', bytes: Buffer.from('x') });
  const cases = [
    ['a different case of an existing note', 'Notes/hexes.md'],
    ['an existing note, shouting', 'Notes/HEXES.md'],
    ['a folder that differs only in case', 'notes/Other.md'],
    ['a file where a folder already is', 'Notes/Deep'],
    ['a folder where a file already is', 'Notes/Hexes.md/inside.md'],
  ];
  for (const [what, p] of cases) {
    const err = await refusal(storeObject(v, { path: p, bytes: Buffer.from('x') }));
    assert.equal(err.code, 'conflict', `${what}: ${p}`);
  }
});

test('store: refuses a path nobody could read back, or that is not a valid key', async (t) => {
  const { v } = await scratch(t);
  const bytes = Buffer.from('x');
  const bad = [
    '', '/abs.md', 'Notes//double.md', 'Notes/../escape.md', 'Notes/./dot.md', 'Notes/',
    'Notes/\u0000nul.md', 'Notes/é.md',              // NUL; decomposed é (not NFC)
    'Notes/draft.md.tmp', 'Notes/.DS_Store', '.git/config.md',  // skipped by the fs listing
    'index/x.md', 'meta/x.md', 'principals/x.md', 'history/x.md', // withheld trees (§12.4)
    `Notes/${'x'.repeat(300)}.md`,                          // over the filename limit
    'logo.png', 'data.json',                                // non-notes at the root
  ];
  for (const p of bad) {
    const err = await refusal(storeObject(v, { path: p, bytes }));
    assert.equal(err.code, 'bad_request', `${JSON.stringify(p)} should be refused`);
  }
  assert.equal(v.indexes.nodes.entries.length, 4, 'nothing was added');
});

test('store: refuses content it cannot hold faithfully', async (t) => {
  const { v } = await scratch(t);
  // A note that is not UTF-8 would be indexed as replacement characters.
  let err = await refusal(storeObject(v, { path: 'Notes/latin1.md', bytes: Buffer.from([0x63, 0x61, 0x66, 0xe9]) }));
  assert.equal(err.code, 'bad_request');
  // The same bytes are fine as a binary asset.
  await storeObject(v, { path: 'Assets/latin1.bin', bytes: Buffer.from([0x63, 0x61, 0x66, 0xe9]) });

  err = await refusal(storeObject(v, { path: 'Assets/big.bin', bytes: Buffer.alloc(11), maxBytes: 10 }));
  assert.equal(err.code, 'too_large');
  assert.equal(err.status, 413);
  assert.ok(MAX_STORE_BYTES >= 1024 * 1024);

  err = await refusal(storeObject(v, { path: 'Assets/x.png', bytes: 'not bytes' }));
  assert.equal(err.code, 'bad_request');
  err = await refusal(storeObject(v, { path: 'Assets/x.png', bytes: PNG, title: 7 }));
  assert.equal(err.code, 'bad_request');
});

// ------------------------------------------------------------------ access

test('store: create_child on the folder is required (§8.1)', async (t) => {
  const { v, dir } = await scratch(t);
  const bytes = Buffer.from('# hi');

  // An editor holds create_child on Notes/ ...
  await storeObject(v, { principal: 'u:editor', path: 'Notes/Editors.md', bytes });

  // ... a reader may see the folder, so is told so plainly ...
  let err = await refusal(storeObject(v, { principal: 'u:reader', path: 'Notes/Readers.md', bytes }));
  assert.equal(err.code, 'forbidden');
  // ... and an editor has no create_child on Assets/ or the root.
  err = await refusal(storeObject(v, { principal: 'u:editor', path: 'Assets/e.png', bytes: PNG }));
  assert.equal(err.code, 'forbidden');
  err = await refusal(storeObject(v, { principal: 'u:editor', path: 'Top.md', bytes }));
  assert.equal(err.code, 'forbidden');

  // The gated audience denies anonymous everything, so it cannot even learn
  // the folder is there: 404, not 403 (§12.3).
  err = await refusal(storeObject(v, { principal: 'anonymous', path: 'Notes/Anon.md', bytes }));
  assert.equal(err.code, 'not_found');

  assert.equal(await stat(path.join(dir, 'content/Notes/Readers.md')).catch(() => null), null);
  assert.equal(await stat(path.join(dir, 'content/Notes/Anon.md')).catch(() => null), null);
});

test('store: an inline ACL in a new note needs write_acl, not just create_child', async (t) => {
  const { v } = await scratch(t);
  // Without this check, create_child would be a way to hand yourself (or
  // everyone) rights the folder never gave, since an inline ACL replaces the
  // folder file's entry (§8.6).
  const sneaky = Buffer.from(
    '---\nbasalt:\n  acl:\n    owner: u:editor\n    dacl:\n' +
    '      - {type: allow, subject: everyone, rights: [full_control], flags: []}\n---\nbody\n');
  const err = await refusal(storeObject(v, {
    principal: 'u:editor', path: 'Notes/Sneaky.md', bytes: sneaky }));
  assert.equal(err.code, 'forbidden');
  assert.match(err.detail, /write_acl/);
  assert.equal(node(v, 'Notes/Sneaky.md'), undefined);

  // The operator holds the credentials already, so this is not an escalation.
  await storeObject(v, { principal: null, path: 'Notes/Locked.md', bytes: sneaky });
  assert.ok(v.descriptors.forNode('Notes/Locked.md'), 'the inline ACL is in force');
});

test('store: a supplied id is never trusted', async (t) => {
  const { v } = await scratch(t);
  const hexes = node(v, 'Notes/Hexes.md');
  // A note copied from elsewhere arrives carrying an id. Keeping it would
  // make two nodes share one (§4.3), and attach the original's links and ACLs
  // to the copy.
  const copy = Buffer.from(`---\nbasalt:\n  id: ${hexes.id}\n---\ncopy\n`);
  const r = await storeObject(v, { principal: 'u:editor', path: 'Notes/Copy.md', bytes: copy });
  assert.notEqual(r.id, hexes.id);
  assert.equal(node(v, 'Notes/Hexes.md').id, hexes.id);
  assert.deepEqual(
    v.indexes.integrity.entries.filter((i) => i.code === 'DUPLICATE_ID'), []);
});

test('store: rights are read from the store at write time, not at startup', async (t) => {
  const { v, dir } = await scratch(t);
  // The owner revokes the editors' grant while a long-lived server holds the
  // vault open. The next write must see that.
  await storeObject(v, { principal: 'u:editor', path: 'Notes/Before.md', bytes: Buffer.from('a') });
  await writeFile(path.join(dir, 'meta/acl/Notes/acl.yaml'),
    'folder:\n  owner: u:carter\n  dacl:\n' +
    '    - {type: allow, subject: everyone, rights: [read, list, traverse], flags: [oi, ci]}\n');
  const err = await refusal(storeObject(v, {
    principal: 'u:editor', path: 'Notes/After.md', bytes: Buffer.from('b') }));
  assert.equal(err.code, 'forbidden');
});


// ---------------------------------------------------------- who stored it

/** A note's `basalt.created_by`, read the way any other reader would. */
const createdBy = async (dir, p) =>
  YAML.parse((await readFile(path.join(dir, 'content', p), 'utf8')).split('---\n')[1]).basalt.created_by;

test('store: provenance stamps a note with principal, agent, account, client and time', async (t) => {
  const { v, dir } = await scratch(t);
  const r = await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Stamped.md', bytes: Buffer.from('# Stamped\n'),
    provenance: { agent: 'claude-code', account: 'work', client: { name: 'claude-code', version: '2.1.0' } },
  });
  const by = await createdBy(dir, 'Notes/Stamped.md');
  assert.deepEqual(Object.keys(by), ['principal', 'agent', 'account', 'client', 'at']);
  assert.deepEqual({ ...by, at: undefined }, {
    principal: 'u:editor', agent: 'claude-code', account: 'work',
    client: { name: 'claude-code', version: '2.1.0' }, at: undefined,
  });
  assert.match(by.at, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  assert.deepEqual(r.created_by, by, 'the result says what was recorded');

  // The stamp is in the file the content hash covers, and the id is still
  // found and the note still indexed.
  assert.equal(node(v, 'Notes/Stamped.md').id, r.id);
  assert.equal((await v.indexState()).fresh, true);
});

test('store: without provenance nothing is stamped', async (t) => {
  const { v, dir } = await scratch(t);
  const r = await storeObject(v, { principal: 'u:editor', path: 'Notes/Plain.md', bytes: Buffer.from('# Plain\n') });
  assert.equal(r.created_by, undefined);
  assert.equal(await createdBy(dir, 'Notes/Plain.md'), undefined);
});

test('store: an image is stamped in its sidecar entry, beside the id', async (t) => {
  const { v, dir } = await scratch(t);
  await storeObject(v, {
    principal: 'u:editor', path: 'Notes/stamped.png', bytes: PNG, alt: 'a pixel',
    provenance: { agent: 'copilot', account: 'personal' },
  });
  const raw = await readFile(path.join(dir, 'meta/folders/Notes/entries.yaml'), 'utf8');
  // The fixture's file is a hand-written `entries: {}`. A nested stamp must not
  // turn it into one unreadable line.
  assert.ok(!raw.includes('{'), raw);
  const sidecar = YAML.parse(raw);
  const e = sidecar.entries['stamped.png'];
  assert.equal(e.alt, 'a pixel');
  assert.deepEqual({ ...e.created_by, at: undefined },
    { principal: 'u:editor', agent: 'copilot', account: 'personal', at: undefined });

  // The operator at the command line has no principal, so the stamp has none;
  // and an entry that was already there carries no stamp it never had.
  await storeObject(v, { path: 'Assets/by-operator.png', bytes: PNG, provenance: { account: 'work' } });
  const assets = YAML.parse(await readFile(path.join(dir, 'meta/folders/Assets/entries.yaml'), 'utf8'));
  assert.deepEqual(Object.keys(assets.entries['by-operator.png'].created_by), ['account', 'at']);
  assert.equal(assets.entries['diagram.png'].created_by, undefined);
});

test('store: a note cannot supply its own created_by', async (t) => {
  const { v, dir } = await scratch(t);
  const forged = Buffer.from(
    '---\nbasalt:\n  created_by:\n    principal: u:owner\n    account: boss\ntitle: Mine\n---\nbody\n');
  await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Forged.md', bytes: forged,
    provenance: { agent: 'claude-code', account: 'work' },
  });
  const by = await createdBy(dir, 'Notes/Forged.md');
  assert.equal(by.principal, 'u:editor');
  assert.equal(by.account, 'work');
  assert.equal(by.agent, 'claude-code');
  const onDisk = await readFile(path.join(dir, 'content/Notes/Forged.md'), 'utf8');
  assert.ok(!onDisk.includes('boss') && !onDisk.includes('u:owner'));
  assert.match(onDisk, /title: Mine/, 'the author\'s other keys survive');
});

test('store: what the client calls itself is kept as data, never as structure', async (t) => {
  const { v, dir } = await scratch(t);
  // A newline and a YAML-looking tail in a self-reported name must not turn
  // into another frontmatter key, in either branch of withId.
  const evil = 'x\n  account: boss\nbasalt: {id: 01jbq100000000000000000001}';
  for (const [p, body] of [['Notes/Evil1.md', '# a\n'], ['Notes/Evil2.md', '---\ntitle: t\n---\nb\n']]) {
    await storeObject(v, {
      principal: 'u:editor', path: p, bytes: Buffer.from(body),
      provenance: { account: 'work', client: { name: evil, version: 5 } },
    });
    const by = await createdBy(dir, p);
    assert.equal(by.account, 'work', p);
    assert.equal(typeof by.client.name, 'string', p);
    assert.ok(!by.client.name.includes('\n'), p);
    assert.equal(by.client.version, undefined, 'a non-string version is dropped');
  }
  const long = await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Long.md', bytes: Buffer.from('x'),
    provenance: { client: { name: 'n'.repeat(5000) } },
  });
  assert.equal(long.created_by.client.name.length, 100);
});

test('store: labels are short names, so an email address is refused before anything is written', async (t) => {
  const { v, dir } = await scratch(t);
  for (const provenance of [
    { account: 'someone@example.com' }, { agent: 'a b' }, { account: 'x'.repeat(65) },
    { agent: 'claude\n  account: boss' }, { account: 5 },
  ]) {
    const err = await refusal(storeObject(v, {
      principal: 'u:editor', path: 'Notes/Refused.md', bytes: Buffer.from('x'), provenance,
    }));
    assert.equal(err.code, 'bad_request', JSON.stringify(provenance));
    assert.ok(!String(err.message).includes('example.com'), 'the refusal does not echo the value');
  }
  assert.equal(await stat(path.join(dir, 'content/Notes/Refused.md')).catch(() => null), null);
});

// ------------------------------------------------- the caller the store names

const IAM_USER = 'arn:aws:iam::123456789012:user/alice';
const SSO_ROLE = 'arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Editor_0123abcd';
/** §12.7's spelling of a segment that holds an `@`, computed independently. */
const hashed = (seg) => `sha256:${createHash('sha256').update(seg.toLowerCase()).digest('hex').slice(0, 16)}`;

test('store: the caller is stamped between the declared labels and the client\'s claim', async (t) => {
  const { v, dir } = await scratch(t);
  await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Caller.md', bytes: Buffer.from('# c\n'),
    provenance: { agent: 'claude-code', account: 'work', caller: IAM_USER, client: { name: 'c' } },
  });
  const by = await createdBy(dir, 'Notes/Caller.md');
  assert.deepEqual(Object.keys(by), ['principal', 'agent', 'account', 'caller', 'client', 'at']);
  assert.equal(by.caller, IAM_USER, 'an ARN with no address in it is kept exactly');

  // An image carries it in its sidecar entry, like the rest of the stamp.
  await storeObject(v, { path: 'Assets/by-caller.png', bytes: PNG, provenance: { caller: IAM_USER } });
  const assets = YAML.parse(await readFile(path.join(dir, 'meta/folders/Assets/entries.yaml'), 'utf8'));
  assert.deepEqual(Object.keys(assets.entries['by-caller.png'].created_by), ['caller', 'at']);
});

test('store: an email address in the caller is written as a hash, never as itself', async (t) => {
  const { v, dir } = await scratch(t);
  const r = await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Sso.md', bytes: Buffer.from('# s\n'),
    provenance: { caller: `${SSO_ROLE}/Alice@Example.com` },
  });
  assert.equal(r.created_by.caller, `${SSO_ROLE}/${hashed('alice@example.com')}`);
  const onDisk = await readFile(path.join(dir, 'content/Notes/Sso.md'), 'utf8');
  assert.ok(!/example\.com/i.test(onDisk), onDisk);

  // The same person under another casing reads as the same person; someone
  // else does not. An IAM user may have an `@` in its name too.
  assert.equal(normalizeCaller(`${SSO_ROLE}/alice@example.com`), r.created_by.caller);
  assert.notEqual(normalizeCaller(`${SSO_ROLE}/bob@example.com`), r.created_by.caller);
  assert.equal(normalizeCaller('arn:aws:iam::123456789012:user/eng/a@example.com'),
    `arn:aws:iam::123456789012:user/eng/${hashed('a@example.com')}`);
});

test('store: a caller that is not an identity is refused before anything is written', async (t) => {
  const { v, dir } = await scratch(t);
  for (const caller of [
    'arn:aws:iam::1:user/a b', `${IAM_USER}\n  account: boss`, 'arn:aws:iam::1:user/<x>',
    `arn:aws:iam::1:user/${'x'.repeat(600)}`, 'x'.repeat(3000), 5,
  ]) {
    const err = await refusal(storeObject(v, {
      principal: 'u:editor', path: 'Notes/Refused.md', bytes: Buffer.from('x'), provenance: { caller },
    }));
    assert.equal(err.code, 'bad_request', JSON.stringify(caller).slice(0, 40));
  }
  assert.equal(await stat(path.join(dir, 'content/Notes/Refused.md')).catch(() => null), null);
  assert.equal(normalizeCaller(undefined), undefined);
  assert.equal(normalizeCaller(null), undefined);
});

test('store: a note cannot supply its own caller', async (t) => {
  const { v, dir } = await scratch(t);
  const forged = Buffer.from(
    `---\nbasalt:\n  created_by:\n    caller: arn:aws:iam::999999999999:user/boss\n---\nbody\n`);
  await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Forged.md', bytes: forged, provenance: { caller: IAM_USER },
  });
  assert.equal((await createdBy(dir, 'Notes/Forged.md')).caller, IAM_USER);
  // And with no caller to record, the forged one does not survive either.
  await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Forged2.md', bytes: forged, provenance: { account: 'work' },
  });
  assert.equal((await createdBy(dir, 'Notes/Forged2.md')).caller, undefined);
});

// --------------------------------------------------------------------- MCP

const text = (res) => JSON.parse(res.content[0].text);

async function mcpFor(t, principal, opts) {
  const { v } = await scratch(t);
  const surface = new Surface(v);
  return { v, surface, m: mcpMethods(surface, principal, opts) };
}

test('mcp: a read-only server neither lists nor accepts basalt_store', async (t) => {
  const { m } = await mcpFor(t, 'u:editor');
  const names = m['tools/list']().tools.map((x) => x.name);
  assert.ok(!names.includes('basalt_store'));
  assert.ok(!(await m.initialize({})).instructions.includes('basalt_store'));
  await assert.rejects(
    m['tools/call']({ name: 'basalt_store', arguments: { path: 'Notes/X.md', text: 'x' } }),
    (e) => e.code === -32602);
});

test('mcp: a writable server stores text, then the vault reads it back', async (t) => {
  const { m, v } = await mcpFor(t, 'u:editor', { writable: true });
  const tool = m['tools/list']().tools.find((x) => x.name === 'basalt_store');
  assert.deepEqual(tool.inputSchema.required, ['path']);
  assert.equal(tool.annotations.readOnlyHint, false);
  assert.equal(tool.annotations.destructiveHint, false);
  assert.match((await m.initialize({})).instructions, /never replaces/);

  // Listings are cached per principal (§12.5). A store that did not drop the
  // cache would leave the new note invisible until restart, which is exactly
  // the "saved but not found" bug this guards.
  const listed = async () => text(await m['tools/call']({
    name: 'basalt_list', arguments: { folder: 'Notes/' } })).entries.map((e) => e.path);
  assert.ok(!(await listed()).includes('Notes/Trip.md'));

  const res = await m['tools/call']({
    name: 'basalt_store',
    arguments: { path: 'Notes/Trip.md', text: '# Trip\n\nZanzibar in March, see [[Columns]].\n', title: 'Trip' },
  });
  assert.notEqual(res.isError, true, res.content[0].text);
  const stored = text(res);
  assert.equal(stored.path, 'Notes/Trip.md');
  assert.equal(stored.link, '[[Notes/Trip]]');
  assert.match(stored.id, /^[0-9a-hjkmnp-tv-z]{26}$/);

  assert.ok((await listed()).includes('Notes/Trip.md'));
  const read = text(await m['tools/call']({ name: 'basalt_node', arguments: { path: 'Notes/Trip.md' } }));
  assert.equal(read.node.id, stored.id);
  assert.equal((await v.indexState()).fresh, true);
});

test('mcp: a write records the operator\'s agent and account, and what the client said it was', async (t) => {
  const { m, v } = await mcpFor(t, 'u:editor', { writable: true, agent: 'claude-code', account: 'work' });
  await m.initialize({ protocolVersion: '2025-06-18', clientInfo: { name: 'claude-code', version: '2.1.0' } });
  const res = await m['tools/call']({ name: 'basalt_store', arguments: {
    path: 'Notes/Who.md', text: '# Who\n',
    // A model asserting its own identity, in every place it could try.
    account: 'boss', agent: 'someone-else', created_by: { account: 'boss' },
  } });
  assert.notEqual(res.isError, true, res.content[0].text);
  const stored = text(res);
  assert.equal(stored.created_by.principal, 'u:editor');
  assert.equal(stored.created_by.agent, 'claude-code');
  assert.equal(stored.created_by.account, 'work');
  assert.deepEqual(stored.created_by.client, { name: 'claude-code', version: '2.1.0' });

  const onDisk = await readFile(path.join(v.t.root, 'content/Notes/Who.md'), 'utf8');
  assert.ok(!onDisk.includes('boss') && !onDisk.includes('someone-else'));
});

test('mcp: the caller comes from whoever launched the server, never from the model', async (t) => {
  const { m, v } = await mcpFor(t, 'u:editor', { writable: true, agent: 'claude-code', caller: IAM_USER });
  const res = await m['tools/call']({ name: 'basalt_store', arguments: {
    path: 'Notes/Caller.md', text: '# c\n', caller: 'arn:aws:iam::999999999999:user/boss',
  } });
  assert.notEqual(res.isError, true, res.content[0].text);
  assert.equal(text(res).created_by.caller, IAM_USER);
  const onDisk = await readFile(path.join(v.t.root, 'content/Notes/Caller.md'), 'utf8');
  assert.ok(!onDisk.includes('999999999999'));
});

test('mcp: two accounts, same agent: each write names its own', async (t) => {
  const work = await mcpFor(t, 'u:editor', { writable: true, agent: 'claude-code', account: 'work' });
  const personal = await mcpFor(t, 'u:editor', { writable: true, agent: 'claude-code', account: 'personal' });
  const put = (m, p) => m['tools/call']({ name: 'basalt_store', arguments: { path: p, text: '# x\n' } })
    .then(text);
  assert.equal((await put(work.m, 'Notes/A.md')).created_by.account, 'work');
  assert.equal((await put(personal.m, 'Notes/B.md')).created_by.account, 'personal');
});

test('mcp: with no agent or account declared, a write still says who and when', async (t) => {
  const { m } = await mcpFor(t, 'u:editor', { writable: true });
  const by = text(await m['tools/call']({ name: 'basalt_store', arguments: { path: 'Notes/N.md', text: '# n\n' } })).created_by;
  assert.deepEqual(Object.keys(by).sort(), ['at', 'principal']);
});

test('mcp: the store tool tells the model it cannot set created_by', async (t) => {
  const { m } = await mcpFor(t, 'u:editor', { writable: true });
  const tool = m['tools/list']().tools.find((x) => x.name === 'basalt_store');
  assert.match(tool.description, /created_by/);
  assert.deepEqual(Object.keys(tool.inputSchema.properties).sort(), ['alt', 'base64', 'path', 'text', 'title']);
});

test('mcp: a writable server stores an image from base64, and an embed resolves to it', async (t) => {
  const { m, v } = await mcpFor(t, 'u:carter', { writable: true });
  // The owner holds create_child nowhere by default in this fixture; grant it
  // on Assets/ the way a vault author would.
  await writeFile(path.join(v.t.root, 'meta/acl/Assets/acl.yaml'),
    'folder:\n  owner: u:carter\n  dacl:\n' +
    '    - {type: allow, subject: u:carter, rights: [full_control], flags: [ci, oi]}\n' +
    '    - {type: allow, subject: everyone, rights: [read, list, traverse], flags: [oi]}\n');

  const img = text(await m['tools/call']({
    name: 'basalt_store',
    arguments: {
      path: 'Assets/photo.png', base64: PNG.toString('base64'),
      title: 'A photo', alt: 'Nothing much',
    },
  }));
  assert.equal(img.kind, 'asset');
  assert.equal(img.link, '![[Assets/photo.png]]');
  assert.equal(img.content_hash, sha(PNG));

  const back = text(await m['tools/call']({
    name: 'basalt_node', arguments: { path: 'Assets/photo.png', include_bytes: true, include_text: false } }));
  assert.deepEqual(Buffer.from(back.base64, 'base64'), PNG);
  assert.equal(back.node.title, 'A photo');

  // The `link` in the result is meant to be pasted into a note, so check that
  // it does what it promises: the embed resolves to the image, not dangling.
  const note = await storeObject(v, {
    principal: 'u:editor', path: 'Notes/WithImage.md', bytes: Buffer.from(`# Pic\n\n${img.link}\n`),
  });
  const edge = v.indexes.links.entries.find((e) => e.from === note.id);
  assert.equal(edge.to, img.id);
});

test('mcp: refusals come back as tool errors, and say why', async (t) => {
  const { m } = await mcpFor(t, 'u:reader', { writable: true });
  const call = async (args) => m['tools/call']({ name: 'basalt_store', arguments: args });

  let res = await call({ path: 'Notes/R.md', text: 'x' });
  assert.equal(res.isError, true);
  assert.equal(text(res).error, 'forbidden');

  const e = await mcpFor(t, 'u:editor', { writable: true });
  const ecall = async (args) => e.m['tools/call']({ name: 'basalt_store', arguments: args });
  res = await ecall({ path: 'Notes/Hexes.md', text: 'x' });
  assert.equal(text(res).error, 'conflict');
  assert.equal(text(res).status, 409);

  for (const args of [
    { path: 'Notes/X.md' },                                         // neither
    { path: 'Notes/X.md', text: 'x', base64: 'eA==' },              // both
    { path: 'Assets/x.png', base64: 'data:image/png;base64,AAAA' }, // a data: URI
    { path: 'Assets/x.png', base64: 'AAA' },                        // bad padding
    { path: 'Assets/x.png', base64: 'AA*A' },                       // not base64
    { path: 'Notes/X.md', text: 5 },                                // wrong type
  ]) {
    res = await ecall(args);
    assert.equal(res.isError, true, JSON.stringify(args));
    assert.equal(text(res).error, 'bad_request', JSON.stringify(args));
  }
});

// --------------------------------------------------------------------- CLI

const cli = (args, opts = {}) => run(process.execPath, [CLI, ...args], opts)
  .then((r) => ({ code: 0, ...r }), (e) => ({ code: e.code, stdout: e.stdout, stderr: e.stderr }));
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

test('cli: add stores a note, an image and a file, then refuses a repeat', async (t) => {
  const { dir } = await scratch(t);
  const src = await mkdtemp(path.join(tmpdir(), 'basalt-src-'));
  t.after(() => rm(src, { recursive: true, force: true }));
  await writeFile(path.join(src, 'pixel.png'), PNG);
  await writeFile(path.join(src, 'Idea.md'), '# Idea\n\nUses ![[pixel.png]].\n');
  await writeFile(path.join(src, 'data.bin'), Buffer.from([0, 255, 128]));

  const first = await cli(['add', path.join(src, 'pixel.png'), path.join(src, 'Idea.md'),
    path.join(src, 'data.bin'), '--vault', dir]);
  assert.equal(first.code, 0, first.stderr);
  const out = plain(first.stdout);
  assert.match(out, /stored\s+Assets\/pixel\.png/);
  assert.match(out, /stored\s+Notes\/Idea\.md/);
  assert.match(out, /stored\s+Assets\/data\.bin/);
  assert.match(out, /integrity 0 errors, 1 warnings/);   // the fixture's own dangling link

  assert.deepEqual(await readFile(path.join(dir, 'content/Assets/pixel.png')), PNG);
  const check = await cli(['check', '--vault', dir]);
  assert.equal(check.code, 0, plain(check.stdout));
  assert.match(plain(check.stdout), /reproduces stored indexes byte for byte/);

  const again = await cli(['add', path.join(src, 'pixel.png'), '--vault', dir]);
  assert.equal(again.code, 1);
  assert.match(plain(again.stderr), /conflict: Assets\/pixel\.png already exists/);
});

test('cli: add takes --to, --as, --title and stdin', async (t) => {
  const { dir } = await scratch(t);
  const src = await mkdtemp(path.join(tmpdir(), 'basalt-src-'));
  t.after(() => rm(src, { recursive: true, force: true }));
  await writeFile(path.join(src, 'scan.pdf'), '%PDF-1.4\n');

  const to = await cli(['add', path.join(src, 'scan.pdf'), '--to', 'Papers/2026', '--vault', dir]);
  assert.equal(to.code, 0, to.stderr);
  assert.ok(await stat(path.join(dir, 'content/Papers/2026/scan.pdf')));

  const child = spawn(process.execPath,
    [CLI, 'add', '-', '--as', 'Notes/Piped.md', '--title', 'Piped in', '--vault', dir]);
  child.stdin.end('piped **text**\n');
  const code = await new Promise((resolve) => child.on('close', resolve));
  assert.equal(code, 0);
  assert.match(await readFile(path.join(dir, 'content/Notes/Piped.md'), 'utf8'), /title: Piped in/);

  const noAs = await cli(['add', '-', '--vault', dir]);
  assert.equal(noAs.code, 1);
  assert.match(plain(noAs.stderr), /needs --as/);
  const dirArg = await cli(['add', src, '--vault', dir]);
  assert.equal(dirArg.code, 1);
  assert.match(plain(dirArg.stderr), /is a directory/);
});

test('cli: add --principal enforces the ACL; without it you are the operator', async (t) => {
  const { dir } = await scratch(t);
  const src = await mkdtemp(path.join(tmpdir(), 'basalt-src-'));
  t.after(() => rm(src, { recursive: true, force: true }));
  await writeFile(path.join(src, 'Note.md'), '# n\n');

  const reader = await cli(['add', path.join(src, 'Note.md'), '--principal', 'u:reader', '--vault', dir]);
  assert.equal(reader.code, 1);
  assert.match(plain(reader.stderr), /forbidden/);
  assert.equal(await stat(path.join(dir, 'content/Notes/Note.md')).catch(() => null), null);

  const editor = await cli(['add', path.join(src, 'Note.md'), '--principal', 'u:editor', '--vault', dir]);
  assert.equal(editor.code, 0, editor.stderr);
});

test('cli: mcp --writable is end to end over stdio, and needs a principal', async (t) => {
  const { dir } = await scratch(t);

  const anon = await cli(['mcp', '--writable', '--vault', dir]);
  assert.equal(anon.code, 1);
  assert.match(plain(anon.stderr), /--writable needs --principal/);

  const child = spawn(process.execPath,
    [CLI, 'mcp', '--writable', '--principal', 'u:editor', '--vault', dir,
      '--agent', 'claude-code', '--account', 'work']);
  const lines = [];
  let buf = '';
  child.stdout.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) !== -1) { lines.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); }
  });
  const send = (id, method, params) =>
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
  const reply = async (id) => {
    for (let i = 0; i < 200; i++) {
      const hit = lines.find((l) => l.id === id);
      if (hit) return hit;
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.fail(`no reply to ${id}`);
  };
  t.after(() => child.kill());

  send(1, 'initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'test-client', version: '9' } });
  await reply(1);
  send(2, 'tools/list', {});
  assert.ok((await reply(2)).result.tools.some((x) => x.name === 'basalt_store'));

  send(3, 'tools/call', { name: 'basalt_store', arguments: {
    path: 'Notes/OverStdio.md', text: '# Over stdio\n\nQuokka.\n' } });
  const stored = JSON.parse((await reply(3)).result.content[0].text);
  assert.equal(stored.path, 'Notes/OverStdio.md');

  send(4, 'tools/call', { name: 'basalt_node', arguments: { path: 'Notes/OverStdio.md' } });
  assert.match(JSON.parse((await reply(4)).result.content[0].text).text, /Quokka/);

  assert.match(await readFile(path.join(dir, 'content/Notes/OverStdio.md'), 'utf8'), /Quokka/);

  // The flags and the handshake both reached the file.
  const by = await createdBy(dir, 'Notes/OverStdio.md');
  assert.equal(by.principal, 'u:editor');
  assert.equal(by.agent, 'claude-code');
  assert.equal(by.account, 'work');
  assert.deepEqual(by.client, { name: 'test-client', version: '9' });
});

test('cli: --agent and --account are labels, and only mean something with --writable', async (t) => {
  const { dir } = await scratch(t);
  const email = await cli(['mcp', '--writable', '--principal', 'u:editor', '--account', 'me@example.com', '--vault', dir]);
  assert.equal(email.code, 1);
  assert.match(plain(email.stderr), /--account must be a short label/);
  assert.ok(!email.stderr.includes('example.com'), 'the value is not echoed');

  const readOnly = await cli(['mcp', '--principal', 'u:editor', '--account', 'work', '--vault', dir]);
  assert.equal(readOnly.code, 1);
  assert.match(plain(readOnly.stderr), /need --writable/);
});

test('cli: add stamps only when asked, and then with the labels given', async (t) => {
  const { dir } = await scratch(t);
  const src = await mkdtemp(path.join(tmpdir(), 'basalt-src-'));
  t.after(() => rm(src, { recursive: true, force: true }));
  await writeFile(path.join(src, 'A.md'), '# a\n');
  await writeFile(path.join(src, 'B.md'), '# b\n');

  assert.equal((await cli(['add', path.join(src, 'A.md'), '--vault', dir])).code, 0);
  assert.equal(await createdBy(dir, 'Notes/A.md'), undefined);

  const r = await cli(['add', path.join(src, 'B.md'), '--agent', 'claude-code', '--account', 'personal',
    '--principal', 'u:editor', '--vault', dir]);
  assert.equal(r.code, 0, r.stderr);
  const by = await createdBy(dir, 'Notes/B.md');
  assert.deepEqual({ ...by, at: undefined },
    { principal: 'u:editor', agent: 'claude-code', account: 'personal', at: undefined });
});
