// Git working-tree transport, PROTOCOL §1.
//
// Every test makes its own repositories in a temp folder, with git's global
// and system config shut out, so the result does not depend on whoever runs
// it: their hooks, signing, default branch or identity. Remotes are bare
// repositories on disk; nothing here touches the network.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { cp, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';

import { Vault } from '../src/vault.mjs';
import { GitTransport } from '../src/transport/git.mjs';
import { INDEX } from '../src/keys.mjs';
import { storeObject } from '../src/store.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { corpusPath } from './support/spec.mjs';

const exec = promisify(execFile);

const FIXTURE = corpusPath('vaults/minimal/vault');
const EXPECTED = corpusPath('vaults/minimal/expected/');
const CLI = fileURLToPath(new URL('../bin/basalt.mjs', import.meta.url));

// This test process only: the transport inherits it, and so do the git
// commands below.
const HOME = await mkdtemp(path.join(tmpdir(), 'basalt-git-home-'));
await writeFile(path.join(HOME, 'gitconfig'),
  '[user]\n\tname = Basalt Test\n\temail = test@example.com\n' +
  '[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n');
process.env.GIT_CONFIG_GLOBAL = path.join(HOME, 'gitconfig');
process.env.GIT_CONFIG_NOSYSTEM = '1';
process.on('exit', () => { try { execFile('rm', ['-rf', HOME]); } catch { /* best effort */ } });

async function git(cwd, ...args) {
  const { stdout } = await exec('git', args, { cwd, env: process.env });
  return stdout.trim();
}

async function tmp(t, name) {
  const dir = await mkdtemp(path.join(tmpdir(), `basalt-git-${name}-`));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

/** A fresh repository holding a copy of the minimal vault, committed. */
async function repoWithVault(t, { sub = '', ignoreIndex = false } = {}) {
  const top = await tmp(t, 'repo');
  await git(top, 'init', '-q');
  const root = path.join(top, sub);
  await cp(FIXTURE, root, { recursive: true });
  if (ignoreIndex) await writeFile(path.join(root, '.gitignore'), 'index/\n');
  await git(top, 'add', '-A');
  await git(top, 'commit', '-q', '-m', 'Import the vault');
  return { top, root };
}

async function openVault(root, opts) {
  const warnings = [];
  const tr = new GitTransport(root, { derived: [INDEX], warn: (m) => warnings.push(m), ...opts });
  await tr.ready();
  const v = new Vault(tr);
  await v.load();
  await v.reindex();
  tr.rederive = async () => { await v.load(); await v.reindex({ write: true }); };
  return { v, tr, warnings };
}

const subjects = async (cwd, n = 20) =>
  (await git(cwd, 'log', `-${n}`, '--format=%s')).split('\n').filter(Boolean);
const changed = async (cwd, rev = 'HEAD') =>
  (await git(cwd, 'show', '--format=', '--name-only', rev)).split('\n').filter(Boolean).sort();

// ------------------------------------------------------------- the contract

test('git: the five operations round-trip, one commit per write', async (t) => {
  const top = await tmp(t, 'ops');
  await git(top, 'init', '-q');
  const tr = new GitTransport(top, { warn: () => {} });
  const body = Buffer.from('hexagonal columns\n');

  const st = await tr.put('content/Notes/Probe.md', body);
  assert.equal(st.size, body.length);
  assert.deepEqual(await tr.get('content/Notes/Probe.md'), body);
  const head = await tr.stat('content/Notes/Probe.md');
  assert.equal(head.size, body.length);
  assert.ok(head.etag && head.mtime);
  assert.ok((await tr.list('content/')).keys.includes('content/Notes/Probe.md'));
  assert.deepEqual(await subjects(top), ['Write content/Notes/Probe.md']);

  // Same bytes again: the store is unchanged, so git gets no empty commit.
  await tr.put('content/Notes/Probe.md', body);
  assert.equal((await subjects(top)).length, 1);

  // §1.2: delete says nothing; a key that was never there is no commit.
  await tr.delete('content/Notes/Probe.md');
  await tr.delete('content/Notes/Never.md');
  assert.equal(await tr.get('content/Notes/Probe.md'), null);
  assert.equal(await tr.stat('content/Notes/Probe.md'), null);
  assert.deepEqual(await subjects(top),
    ['Write content/Notes/Probe.md', 'Write content/Notes/Probe.md']);
  assert.equal(await git(top, 'ls-files'), '');
});

test('git: conditional put still turns a lost update into a conflict (§11.3)', async (t) => {
  const top = await tmp(t, 'cas');
  await git(top, 'init', '-q');
  const tr = new GitTransport(top, { warn: () => {} });
  const first = await tr.put('meta/x.yaml', Buffer.from('a: 1\n'), { ifMatch: null });
  await assert.rejects(tr.put('meta/x.yaml', Buffer.from('a: 2\n'), { ifMatch: null }),
    (e) => e.code === 'PRECONDITION_FAILED');
  await tr.put('meta/x.yaml', Buffer.from('a: 3\n'), { ifMatch: first.etag });
  await assert.rejects(tr.put('meta/x.yaml', Buffer.from('a: 4\n'), { ifMatch: first.etag }),
    (e) => e.code === 'PRECONDITION_FAILED');
  assert.equal((await tr.get('meta/x.yaml')).toString(), 'a: 3\n');
});

test('git: a vault in a subfolder indexes byte for byte as the corpus expects (§0)', async (t) => {
  const { root } = await repoWithVault(t, { sub: 'vaults/minimal' });
  const { v } = await openVault(root);
  for (const kind of ['nodes', 'links', 'backlinks', 'tags', 'search', 'digest', 'integrity']) {
    const want = await readFile(path.join(EXPECTED, `${kind}.json`), 'utf8');
    const got = canonicalJson({ ...v.indexes[kind], generated: '1970-01-01T00:00:00Z' });
    assert.equal(got, want, `index/${kind}.json differs over the git store`);
  }
});

test('git: paths are literal, never globs', async (t) => {
  const top = await tmp(t, 'glob');
  await git(top, 'init', '-q');
  const tr = new GitTransport(top, { warn: () => {} });
  await tr.put('content/Notes/plain.md', Buffer.from('plain\n'));
  await tr.put('content/Notes/[draft] *.md', Buffer.from('draft\n'));
  assert.deepEqual(await changed(top), ['content/Notes/[draft] *.md']);
});

// ------------------------------------------------------------- commits

test('git: a stored note, its indexes and the provenance are one commit', async (t) => {
  const { top, root } = await repoWithVault(t);
  const { v } = await openVault(root);
  await storeObject(v, {
    principal: 'u:editor', path: 'Notes/Idea.md', bytes: Buffer.from('# Idea\n\nSee [[Columns]].\n'),
    provenance: { agent: 'claude-code', account: 'laptop', client: { name: 'Test Client', version: '1.0' } },
  });
  assert.deepEqual(await subjects(top, 2), ['Add Notes/Idea.md', 'Import the vault']);
  const files = await changed(top);
  assert.ok(files.includes('content/Notes/Idea.md'), files.join(', '));
  assert.ok(files.includes('index/nodes.json'), 'the indexes go in the same commit');
  const body = await git(top, 'log', '-1', '--format=%B');
  assert.match(body, /^Basalt-Principal: u:editor$/m);
  assert.match(body, /^Basalt-Agent: claude-code$/m);
  assert.match(body, /^Basalt-Account: laptop$/m);
  assert.match(body, /^Basalt-Client: Test Client 1\.0$/m);
  assert.equal(await git(top, 'log', '-1', '--format=%an <%ae>'), 'Basalt Test <test@example.com>',
    'commits use the git identity, nothing basalt makes up');
  assert.equal(await git(top, 'status', '--porcelain'), '');
});

test('git: an asset and its sidecar are one commit too', async (t) => {
  const { top, root } = await repoWithVault(t);
  const { v } = await openVault(root);
  await storeObject(v, { principal: null, path: 'Assets/dot.png', bytes: Buffer.from([0x89, 0x50, 0x4e, 0x47]) });
  const files = await changed(top);
  assert.ok(files.includes('content/Assets/dot.png'));
  assert.ok(files.includes('meta/folders/Assets/entries.yaml'), files.join(', '));
  assert.equal((await subjects(top, 1))[0], 'Add Assets/dot.png');
});

test('git: what you have staged or are editing is left alone', async (t) => {
  const { top, root } = await repoWithVault(t);
  const columns = path.join(root, 'content/Notes/Columns.md');
  await writeFile(path.join(root, 'scratch.txt'), 'staged by hand\n');
  await git(top, 'add', 'scratch.txt');
  await writeFile(columns, (await readFile(columns, 'utf8')) + '\nhalf-written thought\n');
  const before = await git(top, 'status', '--porcelain');

  const { v } = await openVault(root);
  await storeObject(v, { principal: null, path: 'Notes/New.md', bytes: Buffer.from('# New\n') });

  const files = await changed(top);
  assert.ok(!files.includes('scratch.txt') && !files.includes('content/Notes/Columns.md'),
    `swept into the commit: ${files.join(', ')}`);
  assert.equal(await git(top, 'status', '--porcelain'), before);
});

test('git: a key .gitignore excludes is stored but not committed', async (t) => {
  const { top, root } = await repoWithVault(t, { ignoreIndex: true });
  assert.equal(await git(top, 'ls-files', 'index'), '', 'precondition: index/ untracked');
  const { v } = await openVault(root);
  await storeObject(v, { principal: null, path: 'Notes/New.md', bytes: Buffer.from('# New\n') });
  assert.deepEqual(await changed(top), ['content/Notes/New.md']);
  // Still in the store: the indexes on disk name the new note.
  const nodes = JSON.parse(await readFile(path.join(root, 'index/nodes.json'), 'utf8'));
  assert.ok(nodes.entries.some((e) => e.path === 'Notes/New.md'));
});

test('git: reindex and mint are a commit each, and only when something changed', async (t) => {
  const { top, root } = await repoWithVault(t);
  const { v } = await openVault(root);
  await v.reindex({ write: true });
  const n = (await subjects(top)).length;
  await writeFile(path.join(root, 'content/Notes/Bare.md'), '# Bare\n');
  await v.mintIds();
  assert.equal((await subjects(top, 1))[0], 'Mint ids for 1 object');
  await v.reindex({ write: true });
  assert.equal((await subjects(top, 1))[0], 'Rebuild indexes');
  await v.reindex({ write: true });
  assert.equal((await subjects(top)).length, n + 2, 'an unchanged reindex makes no commit');
});

test('git: mtime is the last commit that touched a file, not the checkout', async (t) => {
  const top = await tmp(t, 'mtime');
  await git(top, 'init', '-q');
  await mkdir(path.join(top, 'content'), { recursive: true });
  await writeFile(path.join(top, 'content/Old.md'), 'old\n');
  await writeFile(path.join(top, 'content/Edited.md'), 'edited\n');
  await git(top, 'add', '-A');
  await exec('git', ['commit', '-q', '-m', 'old'], {
    cwd: top, env: { ...process.env, GIT_COMMITTER_DATE: '2020-01-02T03:04:05Z' } });
  const clone = await tmp(t, 'clone');
  await git(clone, 'clone', '-q', top, '.');
  await writeFile(path.join(clone, 'content/Edited.md'), 'edited again\n');

  const tr = new GitTransport(clone, { warn: () => {} });
  assert.equal((await tr.stat('content/Old.md')).mtime, '2020-01-02T03:04:05.000Z');
  const edited = (await tr.stat('content/Edited.md')).mtime;
  assert.ok(edited > '2024', `a modified file keeps its filesystem time, got ${edited}`);
});

// ------------------------------------------------------------- refusals

test('git: a folder outside a repository, or a bare one, is refused plainly', async (t) => {
  const plain = await tmp(t, 'plain');
  await assert.rejects(new GitTransport(plain).ready(), /not in a git repository/);
  const bare = await tmp(t, 'bare');
  await git(bare, 'init', '-q', '--bare');
  await assert.rejects(new GitTransport(bare).ready(), /bare repository/);
  await assert.rejects(new GitTransport(path.join(plain, 'nope')).ready(), /does not exist/);
});

test('git: the CLI stores through --git as one commit, and refuses two stores', async (t) => {
  const { top, root } = await repoWithVault(t);
  const file = path.join(await tmp(t, 'src'), 'Field Notes.md');
  await writeFile(file, '# Field notes\n');
  await exec('node', [CLI, 'add', file, '--git', root, '--to', 'Notes/'], { env: process.env });
  assert.equal((await subjects(top, 1))[0], 'Add Notes/Field Notes.md');
  const files = await changed(top);
  assert.ok(files.includes('content/Notes/Field Notes.md') && files.includes('index/nodes.json'));

  await assert.rejects(exec('node', [CLI, 'check', '--git', root, '--vault', root], { env: process.env }),
    (e) => /pick one store/.test(e.stdout + e.stderr));
  await assert.rejects(exec('node', [CLI, 'check', '--vault', root, '--remote', 'origin'], { env: process.env }),
    (e) => /--remote is for a git store/.test(e.stdout + e.stderr));
});

// ------------------------------------------------------------- sync

/** A bare remote seeded with the vault, and `n` clones of it. */
async function remoteAndClones(t, n) {
  const { top } = await repoWithVault(t);
  const remote = await tmp(t, 'remote');
  await git(remote, 'clone', '-q', '--bare', top, '.');
  const clones = [];
  for (let i = 0; i < n; i++) {
    const dir = await tmp(t, `clone${i}`);
    await git(dir, 'clone', '-q', remote, '.');
    clones.push(dir);
  }
  return { remote, clones };
}

test('git: two clones writing through one remote both land, with fresh indexes', async (t) => {
  const { remote, clones: [a, b] } = await remoteAndClones(t, 2);
  // B writes while it cannot reach the remote, so its commit is local only.
  const offline = await openVault(b);
  await storeObject(offline.v, { principal: null, path: 'Notes/From B offline.md', bytes: Buffer.from('# B0\n') });

  const A = await openVault(a, { remote: 'origin' });
  await storeObject(A.v, { principal: null, path: 'Notes/From A.md', bytes: Buffer.from('# A\n') });
  assert.deepEqual(A.warnings, []);

  // Now B, syncing: the two histories have diverged and both rewrote
  // index/*.json. Those are derived, so the merge keeps B's and the store's
  // own reindex brings them up to date before anything is pushed.
  const B = await openVault(b, { remote: 'origin' });
  await storeObject(B.v, { principal: null, path: 'Notes/From B.md', bytes: Buffer.from('# B1\n') });
  assert.deepEqual(B.warnings, []);

  const check = await tmp(t, 'check');
  await git(check, 'clone', '-q', remote, '.');
  for (const name of ['From A', 'From B offline', 'From B']) {
    assert.ok(existsSync(path.join(check, `content/Notes/${name}.md`)), `${name} missing on the remote`);
  }
  const fresh = await openVault(check);
  const stored = JSON.parse(await readFile(path.join(check, 'index/nodes.json'), 'utf8'));
  assert.equal(stored.source_digest, fresh.v.indexes.digest.root,
    'the indexes on the remote are not stale');
  assert.equal(await git(b, 'status', '--porcelain'), '');
});

test('git: a real conflict is aborted and reported; the write still succeeds', async (t) => {
  const { remote, clones: [a, b] } = await remoteAndClones(t, 2);
  const edit = async (dir, line) => {
    const p = path.join(dir, 'content/Notes/Columns.md');
    await writeFile(p, (await readFile(p, 'utf8')) + `\n${line}\n`);
    await git(dir, 'commit', '-q', '-am', line);
  };
  await edit(a, 'from A');
  await git(a, 'push', '-q', 'origin', 'main');
  await edit(b, 'from B');

  const B = await openVault(b, { remote: 'origin' });
  await storeObject(B.v, { principal: null, path: 'Notes/Safe.md', bytes: Buffer.from('# Safe\n') });

  assert.ok(B.warnings.some((w) => /both changed content\/Notes\/Columns\.md.*merge by hand/.test(w)),
    B.warnings.join('\n'));
  assert.ok(existsSync(path.join(b, 'content/Notes/Safe.md')));
  assert.equal((await subjects(b, 1))[0], 'Add Notes/Safe.md');
  assert.ok(!existsSync(path.join(b, '.git/MERGE_HEAD')), 'the merge was not left half-done');
  assert.equal(await git(b, 'status', '--porcelain'), '');
  const remoteHead = await git(remote, 'log', '-1', '--format=%s', 'main');
  assert.equal(remoteHead, 'from A', 'nothing was forced over the remote');
});

test('git: an unreachable remote is a warning, not a failed write', async (t) => {
  const { clones: [a] } = await remoteAndClones(t, 1);
  await git(a, 'remote', 'set-url', 'origin', path.join(a, 'no-such-remote.git'));
  const A = await openVault(a, { remote: 'origin' });
  await storeObject(A.v, { principal: null, path: 'Notes/Local.md', bytes: Buffer.from('# Local\n') });
  assert.equal((await subjects(a, 1))[0], 'Add Notes/Local.md');
  assert.ok(A.warnings.some((w) => /could not fetch/.test(w)), A.warnings.join('\n'));
  assert.ok(A.warnings.some((w) => /could not push.*next push/.test(w)), A.warnings.join('\n'));
});

test('git: --remote must name a remote that exists', async (t) => {
  const { clones: [a] } = await remoteAndClones(t, 1);
  await assert.rejects(new GitTransport(a, { remote: 'upstream' }).ready(), /no remote named upstream/);
});

test('git: a push that has to merge first rebuilds the indexes before it goes out', async (t) => {
  const { remote, clones: [a, b] } = await remoteAndClones(t, 2);
  const A = await openVault(a, { remote: 'origin' });
  const B = await openVault(b, { remote: 'origin' });
  // A pushes while B is in the middle of a write, after B's own pull: B's
  // push is rejected, B merges (index/*.json conflict on both sides), and the
  // indexes it pushes must cover A's note as well as its own.
  await B.tr.batch({ message: 'B writes' }, async () => {
    await B.tr.put('content/Notes/From B.md', Buffer.from('# B\n'));
    await storeObject(A.v, { principal: null, path: 'Notes/From A.md', bytes: Buffer.from('# A\n') });
    await B.v.reindex({ write: true });
  });
  assert.deepEqual([...A.warnings, ...B.warnings], []);
  assert.match((await subjects(b, 1))[0], /^Rebuild indexes after merging origin\/main$/);

  const check = await tmp(t, 'check');
  await git(check, 'clone', '-q', remote, '.');
  const fresh = await openVault(check);
  const stored = JSON.parse(await readFile(path.join(check, 'index/nodes.json'), 'utf8'));
  assert.equal(stored.source_digest, fresh.v.indexes.digest.root, 'pushed indexes are stale');
  assert.ok(stored.entries.some((e) => e.path === 'Notes/From A.md'));
  assert.ok(stored.entries.some((e) => e.path === 'Notes/From B.md'));
});

test('git: writers in two processes take turns, and a dead one\'s lock is taken over', async (t) => {
  const { top, root } = await repoWithVault(t);
  // A lock left by a process that no longer exists.
  const lock = path.join(top, '.git/basalt-write.lock');
  await writeFile(lock, `999999 ${new Date().toISOString()}\n`);
  const src = await tmp(t, 'src');
  const runs = [];
  for (let i = 0; i < 4; i++) {
    const f = path.join(src, `Turn ${i}.md`);
    await writeFile(f, `# Turn ${i}\n`);
    runs.push(exec('node', [CLI, 'add', f, '--git', root, '--to', 'Notes/'], { env: process.env }));
  }
  const out = await Promise.all(runs);
  assert.ok(out.every((r) => !/refused|error:|basalt:/.test(r.stdout + r.stderr)),
    out.map((r) => r.stdout + r.stderr).join('\n'));
  const adds = (await subjects(top)).filter((s) => s.startsWith('Add Notes/Turn'));
  assert.equal(adds.length, 4, adds.join(', '));
  assert.equal(await git(top, 'status', '--porcelain'), '');
  assert.ok(!existsSync(lock), 'the lock is released');
  const { v } = await openVault(root);
  const stored = JSON.parse(await readFile(path.join(root, 'index/nodes.json'), 'utf8'));
  assert.equal(stored.source_digest, v.indexes.digest.root);
});
