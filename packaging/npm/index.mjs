// The Basalt conformance corpus, as a package.
//
// The corpus is language-neutral YAML plus whole vaults with expected index
// output (PROTOCOL §14.2). This package exists so a *published*
// implementation can reach it: the corpus lives at the repository root,
// outside every package directory, and a published tarball would otherwise
// contain zero fixture files.

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/**
 * The corpus root.
 *
 * Resolves two ways on purpose. Published, the fixtures sit in `assets/`
 * inside the package. In the repository they do not — the corpus is the
 * repo's own `conformance/` directory, and reading it directly is what makes
 * a fixture fix break every implementation's tests the same minute, rather
 * than when someone remembers to re-sync.
 */
export function corpusDir() {
  const embedded = path.join(HERE, 'assets');
  if (existsSync(embedded)) return embedded;
  return path.resolve(HERE, '../../conformance');
}

/** A path within the corpus, e.g. `cases/acl/evaluation.yaml`. */
export const casePath = (rel) => path.join(corpusDir(), rel);

/** A conformance vault, e.g. `minimal`. */
export const vaultPath = (name) => path.join(corpusDir(), 'vaults', name, 'vault');

/** A vault's committed expected index output. */
export const expectedPath = (name) => path.join(corpusDir(), 'vaults', name, 'expected');
