// Where the shared spec checkout lives: the directory holding `conformance/`
// (the language-neutral corpus, §14.2) and `protocol/`.
//
// In the monorepo it is the repository root, two levels above this file. In
// the per-language repository it is a git submodule at `spec/`, a checkout of
// CarterCole/basalt pinned to the commit this release was tested against. The
// search walks up from the package root and takes the first directory (or its
// `spec/` child) that has `conformance/manifest.yaml`, so the same tests run in
// both layouts with no path edits.

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url));

function findSpec() {
  for (let dir = PACKAGE_ROOT; ; dir = path.dirname(dir)) {
    for (const candidate of [path.join(dir, 'spec'), dir]) {
      if (existsSync(path.join(candidate, 'conformance', 'manifest.yaml'))) return candidate;
    }
    if (path.dirname(dir) === dir) break;
  }
  throw new Error(
    'the conformance corpus was not found: run `git submodule update --init` ' +
    'in a per-language checkout, or run from the monorepo');
}

export const SPEC = findSpec();

const under = (top, rel) => {
  const p = path.join(SPEC, top, rel);
  // A directory path keeps its trailing separator, because callers concatenate
  // onto it (`${ROOT}expected/x.json`); path.join adds none for an empty `rel`.
  return (rel === '' || rel.endsWith('/')) && !p.endsWith(path.sep) ? p + path.sep : p;
};

/** A path inside `conformance/`; `corpusPath('')` is the directory itself. */
export const corpusPath = (rel = '') => under('conformance', rel);

/** A path inside `protocol/`. */
export const protocolPath = (rel = '') => under('protocol', rel);
