#!/usr/bin/env node
// Copy the conformance corpus into each wrapper package's assets/ directory.
//
// The corpus lives once, at conformance/. It is NOT duplicated in git: these
// copies are gitignored and exist only between this script running and the
// release being published. Run it immediately before packaging:
//
//   node scripts/sync-corpus.mjs
//   cd packaging/crates && cargo package
//
// `--check` verifies the copies match the source instead of writing, which is
// what CI runs to catch a stale assets/ directory left behind by a local run.

import { cp, rm, mkdir, readdir, readFile, stat } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CORPUS = path.join(ROOT, 'conformance');
const TARGETS = [
  path.join(ROOT, 'packaging/crates/assets'),
  path.join(ROOT, 'packaging/npm/assets'),
  path.join(ROOT, 'packaging/pypi/assets'),
];

/** A digest over the tree, so --check compares content and not timestamps. */
async function digest(dir) {
  const files = [];
  const walk = async (d, base) => {
    for (const e of await readdir(d, { withFileTypes: true })) {
      if (e.name === '.DS_Store') continue;
      const abs = path.join(d, e.name);
      const rel = path.join(base, e.name);
      if (e.isDirectory()) await walk(abs, rel);
      else files.push([rel, await readFile(abs)]);
    }
  };
  await walk(dir, '');
  files.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const h = createHash('sha256');
  for (const [rel, bytes] of files) {
    h.update(rel); h.update('\0'); h.update(bytes); h.update('\0');
  }
  return { hash: h.digest('hex'), count: files.length };
}

const check = process.argv.includes('--check');
const source = await digest(CORPUS);
let failed = false;

for (const target of TARGETS) {
  const name = path.relative(ROOT, target);
  if (check) {
    if (!existsSync(target)) { console.log(`  absent  ${name}`); continue; }
    const got = await digest(target);
    if (got.hash === source.hash) {
      console.log(`  ok      ${name} (${got.count} files)`);
    } else {
      console.log(`  STALE   ${name} — run: node scripts/sync-corpus.mjs`);
      failed = true;
    }
    continue;
  }
  await rm(target, { recursive: true, force: true });
  await mkdir(path.dirname(target), { recursive: true });
  await cp(CORPUS, target, { recursive: true });
  console.log(`  synced  ${name} (${source.count} files)`);
}

if (check && failed) process.exitCode = 1;
