// Folders to and from GitHub gists: the name mapping from the corpus, the API
// client, `gist export` and `gist import`, and a whole vault living in a gist.
//
// Everything talks to a local stand-in for the gist API (support/gist-server),
// so no test touches the network or anyone's GitHub account.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import YAML from 'yaml';

import { Vault } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import {
  GistApi, GistError, GistTransport, encodeName, decodeName, parseGistId, whyNotText,
} from '../src/transport/gist.mjs';
import { exportToGist, importFromGist, collect } from '../src/gist.mjs';
import { storeObject } from '../src/store.mjs';
import { gistServer, TOKEN } from './support/gist-server.mjs';
import { corpusPath } from './support/spec.mjs';

const exec = promisify(execFile);
const CORPUS = corpusPath('');
const FIXTURE = path.join(CORPUS, 'vaults/minimal/vault');
const CLI = fileURLToPath(new URL('../bin/basalt.mjs', import.meta.url));
const mapping = YAML.parse(readFileSync(path.join(CORPUS, 'cases/gist/mapping.yaml'), 'utf8'));

// ------------------------------------------------------------------ corpus

for (const c of mapping.cases) {
  test(`gist corpus: ${c.name}`, () => {
    if (c.kind === 'name') {
      assert.equal(encodeName(c.path), c.file, 'encode');
      assert.equal(decodeName(c.file), c.path, 'decode');
    } else if (c.kind === 'decode') {
      assert.equal(decodeName(c.file), c.path);
    } else if (c.kind === 'id') {
      assert.equal(parseGistId(c.input), c.id);
    } else if (c.kind === 'eligible') {
      const bytes = c.base64 !== undefined
        ? Buffer.from(c.base64, 'base64') : Buffer.from(c.text, 'utf8');
      assert.equal(whyNotText(bytes), c.ok ? null : c.reason);
    } else {
      assert.fail(`unknown case kind ${c.kind}`);
    }
  });
}

// ----------------------------------------------------------------- helpers

async function server(t, opts) {
  const s = await gistServer(opts);
  t.after(() => s.close());
  return s;
}

const apiFor = (s, token = TOKEN) => new GistApi({ token, apiUrl: s.url });

async function copyOfVault(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'basalt-gist-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  await cp(FIXTURE, dir, { recursive: true });
  const v = new Vault(new FsTransport(dir));
  await v.load();
  return { dir, v };
}

const files = (g) => Object.fromEntries(g.files);

// ------------------------------------------------------------------ client

test('client: a new gist is secret unless asked, and carries the description', async (t) => {
  const s = await server(t);
  const a = await apiFor(s).create({ files: { 'a.md': 'hi' }, description: 'notes' });
  assert.equal(a.public, false);
  assert.equal(s.gists.get(a.id).description, 'notes');
  const b = await apiFor(s).create({ files: { 'a.md': 'hi' }, public: true });
  assert.equal(b.public, true);
});

test('client: writing without a token fails before any request is made', async (t) => {
  const s = await server(t);
  await assert.rejects(apiFor(s, null).create({ files: { 'a.md': 'hi' } }),
    (e) => e instanceof GistError && e.code === 'no_token' && /GITHUB_TOKEN/.test(e.message));
  assert.equal(s.requests.length, 0);
});

test('client: a wrong token is reported as one, and a missing gist as missing', async (t) => {
  const s = await server(t);
  await assert.rejects(apiFor(s, 'nope').create({ files: { 'a.md': 'hi' } }),
    (e) => e.code === 'unauthorized');
  await assert.rejects(apiFor(s).get('0123456789abcdef'), (e) => e.code === 'not_found');
  await assert.rejects(apiFor(s).get('../etc'), (e) => e.code === 'bad_id');
});

test('client: a rate limit says so, and when it ends', async (t) => {
  const s = await server(t, { limitReads: true });
  await assert.rejects(apiFor(s, null).get('0123456789abcdef'),
    (e) => e.code === 'rate_limited' && /resets 2033/.test(e.message) && /GITHUB_TOKEN/.test(e.message));
});

test('client: the token never goes to a plain-http host, nor to the raw-file host', async (t) => {
  // An http API that is not loopback: a write refuses, a read goes out bare.
  const sent = [];
  const fetchSpy = async (url, init) => {
    sent.push({ url, headers: init.headers });
    return new Response(JSON.stringify({ id: 'abcde', files: {} }), { status: 200 });
  };
  const api = new GistApi({ token: TOKEN, apiUrl: 'http://gists.example.com', fetch: fetchSpy });
  await assert.rejects(api.create({ files: { 'a.md': 'x' } }), (e) => e.code === 'insecure_api');
  await api.get('abcde');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].headers.authorization, undefined);

  // A truncated file is fetched from its raw URL, with no credentials at all.
  const s = await server(t, { truncateOver: 10 });
  const id = s.seed({ 'big.md': 'x'.repeat(50) });
  const g = await apiFor(s).get(id);
  assert.equal(g.files.get('big.md').truncated, true);
  assert.equal((await apiFor(s).content(g.files.get('big.md'))).length, 50);
  const raw = s.requests.filter((r) => r.path.startsWith('/raw/'));
  assert.equal(raw.length, 1);
  assert.equal(raw[0].auth, null);
});

// ------------------------------------------------------------------ export

test('export: a folder becomes a secret gist with flat names, and says what it left out', async (t) => {
  const s = await server(t);
  const { dir, v } = await copyOfVault(t);
  // The fixture's "diagram.png" is a text placeholder; this one is a real PNG header.
  await writeFile(path.join(dir, 'content/Assets/real.png'),
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d]));

  // The whole content tree: three notes and the placeholder go; the PNG cannot.
  const r = await exportToGist(v, { folder: '', api: apiFor(s) });
  assert.equal(r.created, true);
  assert.equal(r.public, false);
  assert.deepEqual(r.skipped, [{ path: 'Assets/real.png', reason: 'not_text' }]);
  assert.deepEqual(r.names.sort(), ['Assets%2Fdiagram.png',
    'Notes%2FColumns.md', 'Notes%2FHexes.md', 'Notes%2FStart Here.md']);

  const sent = s.gists.get(r.id);
  assert.equal(sent.public, false);
  assert.equal(sent.files.get('Notes%2FHexes.md'),
    readFileSync(path.join(FIXTURE, 'content/Notes/Hexes.md'), 'utf8'));
});

test('export: a subfolder is named relative to itself', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  const r = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), public: true, description: 'd' });
  assert.deepEqual(r.names.sort(), ['Columns.md', 'Hexes.md', 'Start Here.md']);
  assert.equal(r.public, true);
  assert.equal(s.gists.get(r.id).description, 'd');
});

test('export: a principal sends only what it may read, and the rest is counted, not named', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  await v.reindex();
  const r = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), principal: 'u:reader' });
  assert.deepEqual(r.names.sort(), ['Hexes.md', 'Start Here.md']);
  assert.equal(r.withheld, 1);
  assert.ok(!JSON.stringify(r).includes('Columns'), 'a withheld path must not be named');
  const owner = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), principal: 'u:carter' });
  assert.equal(owner.names.length, 3);
});

test('export: --dry-run works out the files and makes no request', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  const r = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), dryRun: true });
  assert.equal(r.dryRun, true);
  assert.equal(r.count, 3);
  assert.equal(s.requests.length, 0);
  assert.equal(s.gists.size, 0);
});

test('export: empty and blank files are left out, named, and an all-empty folder is an error', async (t) => {
  const s = await server(t);
  const { dir, v } = await copyOfVault(t);
  await mkdir(path.join(dir, 'content/Odd'), { recursive: true });
  await writeFile(path.join(dir, 'content/Odd/zero.md'), '');
  await writeFile(path.join(dir, 'content/Odd/blank.md'), ' \n\n');
  await assert.rejects(exportToGist(v, { folder: 'Odd/', api: apiFor(s) }), /nothing to export/);
  await writeFile(path.join(dir, 'content/Odd/real.md'), '# real\n');
  const r = await exportToGist(v, { folder: 'Odd/', api: apiFor(s) });
  assert.deepEqual(r.names, ['real.md']);
  assert.deepEqual(r.skipped.map((x) => [x.path, x.reason]),
    [['Odd/blank.md', 'empty'], ['Odd/zero.md', 'empty']]);
  assert.equal(s.requests.length, 1, 'one create; the empty files never went out');
});

test('export: a file name the protocol forbids is named as left out, not lost quietly', async (t) => {
  const s = await server(t);
  const { dir, v } = await copyOfVault(t);
  // "Café" spelled with a combining accent: §1.1 requires NFC, so it is no object of the vault.
  await writeFile(path.join(dir, 'content/Notes/Cafe\u0301.md'), '# decomposed\n');
  const r = await exportToGist(v, { folder: 'Notes/', api: apiFor(s) });
  assert.deepEqual(r.skipped.map((x) => x.reason), ['invalid_key']);
  assert.equal(r.count, 3);
});

test('export: more files than a gist shows is refused before anything is sent', async (t) => {
  const s = await server(t);
  const { dir, v } = await copyOfVault(t);
  await mkdir(path.join(dir, 'content/Many'), { recursive: true });
  for (let i = 0; i < 301; i++) await writeFile(path.join(dir, `content/Many/n${i}.md`), `n${i}\n`);
  await assert.rejects(exportToGist(v, { folder: 'Many/', api: apiFor(s) }), /more than a gist shows/);
  assert.equal(s.requests.length, 0);
});

test('export: --public goes with a new gist only, and --prune with --update only', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  await assert.rejects(
    exportToGist(v, { folder: 'Notes/', api: apiFor(s), update: 'abcde', public: true }), /cannot change sides/);
  await assert.rejects(
    exportToGist(v, { folder: 'Notes/', api: apiFor(s), prune: true }), /--prune is for --update/);
  await assert.rejects(
    exportToGist(v, { whole: true, folder: '', api: apiFor(s), principal: 'u:reader' }), /operator/);
  assert.equal(s.requests.length, 0);
});

test('export --update: writes what changed, leaves the gist\'s other files unless pruned', async (t) => {
  const s = await server(t);
  const { dir, v } = await copyOfVault(t);
  const first = await exportToGist(v, { folder: 'Notes/', api: apiFor(s) });
  s.gists.get(first.id).files.set('mine.txt', 'something I added on the website');

  // Nothing changed: no PATCH at all.
  const before = s.requests.length;
  const same = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), update: first.id });
  assert.equal(same.updated, false);
  assert.equal(same.unchanged, 3);
  assert.deepEqual(same.left, ['mine.txt']);
  assert.equal(s.requests.slice(before).filter((r) => r.method === 'PATCH').length, 0);

  // One note edited, one added: those two are written, the rest untouched.
  await writeFile(path.join(dir, 'content/Notes/Hexes.md'), '# changed\n');
  await writeFile(path.join(dir, 'content/Notes/New.md'), '# new\n');
  const r = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), update: first.id });
  assert.equal(r.written, 2);
  assert.equal(r.unchanged, 2);
  assert.equal(r.removed, 0);
  assert.ok(s.gists.get(first.id).files.has('mine.txt'), 'a file basalt did not write is kept');
  assert.equal(s.gists.get(first.id).files.get('Hexes.md'), '# changed\n');

  // --prune takes out what the folder no longer has, and only that.
  await rm(path.join(dir, 'content/Notes/New.md'));
  const p = await exportToGist(v, { folder: 'Notes/', api: apiFor(s), update: first.id, prune: true });
  assert.equal(p.removed, 2); // New.md and mine.txt
  assert.deepEqual([...s.gists.get(first.id).files.keys()].sort(),
    ['Columns.md', 'Hexes.md', 'Start Here.md']);
});

// ------------------------------------------------------------------ import

test('import: every file lands as a new object with an id, and a second import refuses, not replaces', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  const id = s.seed({
    'Intro.md': '# Intro\n\nSee [[Hexes]].\n',
    'Deep%2FNested%2Fnote.md': 'nested\n',
    'data.json': '{"a": 1}\n',
  });

  const r = await importFromGist(v, { api: apiFor(s, null), id, to: 'Gists/x/' });
  assert.equal(r.refused.length, 0);
  assert.deepEqual(r.stored.map((o) => o.path).sort(),
    ['Gists/x/Deep/Nested/note.md', 'Gists/x/Intro.md', 'Gists/x/data.json']);
  for (const o of r.stored) assert.match(o.id, /^[0-9a-hjkmnp-tv-z]{26}$/);
  const intro = await v.t.get('content/Gists/x/Intro.md');
  assert.match(Buffer.from(intro).toString('utf8'), /^---\nbasalt:\n {2}id: [0-9a-z]{26}\n---\n# Intro/);
  const idx = await v.reindex();
  assert.equal(idx.integrity.entries.filter((e) => e.severity === 'error').length, 0);

  const again = await importFromGist(v, { api: apiFor(s, null), id, to: 'Gists/x/' });
  assert.equal(again.stored.length, 0);
  assert.equal(again.refused.length, 3);
  assert.match(again.refused[0].error, /already exists/);
  // Reading a gist took no token, and sent none.
  assert.ok(s.requests.every((q) => q.auth === null));
});

test('import: one bad name is refused and the others still go', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  const id = s.seed({ 'ok.md': 'fine\n', 'a%2F..%2Fb.md': 'escapes\n', 'Notes%2FHexes.md': 'taken?\n' });
  // Into the vault root, so "Notes/Hexes.md" is a path that is already taken.
  const r = await importFromGist(v, { api: apiFor(s, null), id, to: '' });
  assert.deepEqual(r.stored.map((o) => o.path), ['ok.md']);
  assert.equal(r.refused.length, 2);
  assert.ok(r.refused.some((x) => /not a valid path/.test(x.error)));
  assert.ok(r.refused.some((x) => /already exists/.test(x.error)));
  // The note that was taken is untouched, and nothing went outside the vault.
  assert.match(Buffer.from(await v.t.get('content/Notes/Hexes.md')).toString('utf8'), /Hexagons/);
});

test('import: a principal needs create_child on the folder', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  await v.reindex();
  const id = s.seed({ 'a.md': 'x\n' });
  const r = await importFromGist(v, { api: apiFor(s, null), id, to: 'Notes/', principal: 'u:reader' });
  assert.equal(r.stored.length, 0);
  assert.equal(r.refused.length, 1);
  assert.equal(await v.t.get('content/Notes/a.md'), null);
});

test('import: a file the listing truncated is fetched whole', async (t) => {
  const s = await server(t, { truncateOver: 20 });
  const { v } = await copyOfVault(t);
  const body = `# Long\n\n${'word '.repeat(40)}\n`;
  const id = s.seed({ 'long.md': body });
  const r = await importFromGist(v, { api: apiFor(s, null), id, to: 'In/' });
  assert.equal(r.stored.length, 1);
  assert.ok(Buffer.from(await v.t.get('content/In/long.md')).toString('utf8').endsWith(body));
});

test('round trip: export a folder, import it elsewhere, the text survives', async (t) => {
  const s = await server(t);
  const a = await copyOfVault(t);
  const b = await copyOfVault(t);
  const out = await exportToGist(a.v, { folder: 'Notes/', api: apiFor(s) });
  const back = await importFromGist(b.v, { api: apiFor(s, null), id: out.id, to: 'Copy/' });
  assert.equal(back.refused.length, 0);
  assert.equal(back.stored.length, 3);
  const strip = (x) => x.replace(/^---\n[\s\S]*?\n---\n/, '');
  for (const name of ['Columns', 'Hexes', 'Start Here']) {
    const orig = Buffer.from(await a.v.t.get(`content/Notes/${name}.md`)).toString('utf8');
    const copy = Buffer.from(await b.v.t.get(`content/Copy/${name}.md`)).toString('utf8');
    assert.equal(strip(copy), strip(orig), name);
    // A fresh identity, not the source vault's.
    assert.notEqual(copy.match(/id: (\w+)/)[1], orig.match(/id: (\w+)/)?.[1]);
  }
});

// ------------------------------------------------------------- gist store

test('store: a whole vault in a gist opens, reads, and a batch of writes is one revision', async (t) => {
  const s = await server(t);
  const { v } = await copyOfVault(t);
  const out = await exportToGist(v, { whole: true, folder: '', api: apiFor(s) });
  assert.ok(out.names.includes('basalt.yaml'));
  assert.ok(out.names.includes('content%2FNotes%2FHexes.md'));

  const g = new Vault(new GistTransport({ id: out.id, api: apiFor(s) }));
  await g.t.ready();
  await g.load();
  const idx = await g.reindex();
  assert.equal(idx.nodes.entries.filter((e) => e.path.startsWith('Notes/')).length, 3);

  const patches = () => s.requests.filter((r) => r.method === 'PATCH').length;
  assert.equal(patches(), 0);
  const stored = await storeObject(g, { path: 'Notes/Added.md', bytes: Buffer.from('# Added\n') });
  assert.equal(stored.created, true);
  assert.equal(patches(), 1, 'the note and the refreshed indexes went out as one PATCH');
  assert.ok(s.gists.get(out.id).files.has('content%2FNotes%2FAdded.md'));
  assert.ok(s.gists.get(out.id).files.has('index%2Fnodes.json'));

  // A second process sees it.
  const other = new Vault(new GistTransport({ id: out.id, api: apiFor(s, null), ttlMs: 0 }));
  await other.t.ready();
  await other.load();
  assert.notEqual(await other.t.get('content/Notes/Added.md'), null);
  await assert.rejects(storeObject(g, { path: 'Notes/Added.md', bytes: Buffer.from('again') }), /never overwrite/);
});

test('store: what a gist cannot hold is refused by name, not mangled', async (t) => {
  const s = await server(t);
  const id = s.seed({ 'basalt.yaml': 'basalt: 1\n' });
  const tr = new GistTransport({ id, api: apiFor(s) });
  await tr.ready();
  await assert.rejects(tr.put('content/Assets/a.png', Buffer.from([0x89, 0x50, 0, 1])),
    (e) => e.code === 'UNSUPPORTED' && /not UTF-8 text/.test(e.message));
  await assert.rejects(tr.put('content/Notes/empty.md', Buffer.alloc(0)),
    (e) => e.code === 'UNSUPPORTED' && /empty/.test(e.message));
  await assert.rejects(tr.put('content/' + 'x'.repeat(300) + '.md', Buffer.from('x')),
    (e) => e.code === 'UNSUPPORTED' && /longer than/.test(e.message));
  assert.equal(s.requests.filter((r) => r.method === 'PATCH').length, 0);
});

test('store: list, stat, delete and a conditional put behave like the others', async (t) => {
  const s = await server(t);
  const id = s.seed({ 'basalt.yaml': 'basalt: 1\n', 'content%2FA%2Fb.md': 'hello\n', 'content%2FA%2Fc.md': 'c\n' });
  const tr = new GistTransport({ id, api: apiFor(s), ttlMs: 0 });
  await tr.ready();

  assert.deepEqual((await tr.list('content/A/')).keys.sort(), ['content/A/b.md', 'content/A/c.md']);
  const top = await tr.list('', { delimiter: '/' });
  assert.deepEqual(top.keys, ['basalt.yaml']);
  assert.deepEqual(top.prefixes, ['content/']);
  const st = await tr.stat('content/A/b.md');
  assert.equal(st.size, 6);
  assert.match(st.etag, /^"[0-9a-f]{32}"$/);
  assert.equal(await tr.get('content/A/zzz.md'), null);
  assert.equal(await tr.stat('content/A/zzz.md'), null);

  // Create-only: refused when the key exists, allowed when it does not.
  await assert.rejects(tr.put('content/A/b.md', Buffer.from('x'), { ifMatch: null }),
    (e) => e.code === 'PRECONDITION_FAILED');
  await tr.put('content/A/new.md', Buffer.from('n\n'), { ifMatch: null });
  assert.equal(s.gists.get(id).files.get('content%2FA%2Fnew.md'), 'n\n');
  // Stale etag.
  await assert.rejects(tr.put('content/A/b.md', Buffer.from('x'), { ifMatch: '"stale"' }),
    (e) => e.code === 'PRECONDITION_FAILED');

  await tr.delete('content/A/c.md');
  await tr.delete('content/A/never-existed.md'); // idempotent, and sends nothing for it
  assert.equal(s.gists.get(id).files.has('content%2FA%2Fc.md'), false);
});

test('store: a gist too big for the API to list is refused up front', async (t) => {
  const s = await server(t);
  const id = s.seed(Object.fromEntries(Array.from({ length: 301 }, (_, i) => [`f${i}.md`, 'x'])));
  await assert.rejects(new GistTransport({ id, api: apiFor(s) }).ready(),
    (e) => e.code === 'too_big' && /clone it with git/.test(e.message));
});

// --------------------------------------------------------------------- CLI

async function cli(s, args, { token = TOKEN, cwd } = {}) {
  // `gh` is left off the PATH so a developer's own login cannot be found.
  const env = { PATH: '/nonexistent', HOME: tmpdir(), GITHUB_TOKEN: token ?? '', GH_TOKEN: '' };
  try {
    const { stdout, stderr } = await exec(process.execPath,
      [CLI, ...args, '--api-url', s.url], { env, cwd });
    return { code: 0, stdout: plain(stdout), stderr: plain(stderr) };
  } catch (e) {
    return { code: e.code, stdout: plain(e.stdout), stderr: plain(e.stderr) };
  }
}
const plain = (x) => String(x ?? '').replace(/\x1b\[[0-9;]*m/g, '');

test('cli: export --dry-run, export, then import into a vault, end to end', async (t) => {
  const s = await server(t);
  const { dir } = await copyOfVault(t);
  const other = await copyOfVault(t);
  await writeFile(path.join(dir, 'content/Assets/real.png'), Buffer.from([0x89, 0x50, 0, 1]));

  const dry = await cli(s, ['gist', 'export', 'Notes/', '--vault', dir, '--dry-run']);
  assert.equal(dry.code, 0, dry.stderr);
  assert.match(dry.stdout, /would send 3 file\(s\).*secret gist/);
  assert.match(dry.stdout, /Hexes\.md/);
  assert.equal(s.requests.length, 0);

  const out = await cli(s, ['gist', 'export', '', '--vault', dir]);
  assert.equal(out.code, 0, out.stderr);
  assert.match(out.stdout, /created secret gist https:\/\/gist\.github\.com\/test\/[0-9a-f]{32}/);
  assert.match(out.stdout, /Secret means unlisted, not private/);
  assert.match(out.stdout, /Assets\/real\.png.*not text a gist can hold/);
  const id = [...s.gists.keys()][0];

  const imp = await cli(s, ['gist', 'import', `https://gist.github.com/someone/${id}`,
    '--vault', other.dir, '--to', 'From/'], { token: null });
  assert.equal(imp.code, 0, imp.stderr);
  assert.match(imp.stdout, /stored\s+From\/Notes\/Hexes\.md/);
  assert.match(imp.stdout, /4 stored, 0 refused/);
  assert.match(await readFile(path.join(other.dir, 'content/From/Notes/Hexes.md'), 'utf8'), /Hexagons/);

  const again = await cli(s, ['gist', 'import', id, '--vault', other.dir, '--to', 'From/'], { token: null });
  assert.equal(again.code, 1);
  assert.match(again.stderr, /already exists/);
});

test('cli: no token means no export, and it says how to fix that', async (t) => {
  const s = await server(t);
  const { dir } = await copyOfVault(t);
  const r = await cli(s, ['gist', 'export', 'Notes/', '--vault', dir], { token: null });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /GITHUB_TOKEN/);
  assert.equal(s.requests.length, 0);
});

test('cli: --gist opens a vault from a gist, and a token is never taken as a flag', async (t) => {
  const s = await server(t);
  const { dir } = await copyOfVault(t);
  const whole = await cli(s, ['gist', 'export', '--whole', '--vault', dir]);
  assert.equal(whole.code, 0, whole.stderr);
  const id = [...s.gists.keys()][0];

  const check = await cli(s, ['index', '--gist', id], { token: null });
  assert.equal(check.code, 0, check.stderr);
  assert.match(check.stdout, /4 nodes/);

  const two = await cli(s, ['index', '--gist', id, '--vault', dir]);
  assert.match(two.stderr, /pick one store/);

  // There is no --token flag: it would end up in shell history and `ps`.
  const posts = () => s.requests.filter((r) => r.method === 'POST').length;
  const before = posts();
  const t1 = await cli(s, ['gist', 'export', 'Notes/', '--vault', dir, '--token', 'x'], { token: null });
  assert.equal(t1.code, 1);
  assert.match(t1.stderr, /no --token flag/);
  assert.equal(posts(), before);
});

test('collect: the same listing for an operator whatever order the store lists in', async (t) => {
  const { v } = await copyOfVault(t);
  const a = await collect(v, { folder: '' });
  const b = await collect(v, { folder: '' });
  assert.deepEqual(a.files.map((f) => f.name), b.files.map((f) => f.name));
  assert.deepEqual(a.files.map((f) => f.name), [...a.files.map((f) => f.name)].sort());
});
