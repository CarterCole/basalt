#!/usr/bin/env node
// Refresh the vendored Mermaid browser bundle the publish site loads.
//
// The site needs ONE self-contained file from Mermaid, dist/mermaid.min.js
// (it sets globalThis.mermaid). The npm package around it is over 120 MB
// with 22 dependencies, so depending on it would make every
// `npm install basalt-vault` pay for a file most vaults never load. The file
// is vendored into ts/src/web/public/vendor/ instead, and this script is how
// it is updated:
//
//   node scripts/vendor-mermaid.mjs            # the pinned version below
//   node scripts/vendor-mermaid.mjs 12.4.0     # move the pin
//
// It downloads the package tarball with `npm pack` and extracts only the
// bundle and its licence; nothing from the package is executed.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, copyFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const PINNED = '12.3.0';
const version = process.argv[2] ?? PINNED;
const OUT = fileURLToPath(new URL('../ts/src/web/public/vendor/', import.meta.url));

const tmp = mkdtempSync(path.join(tmpdir(), 'basalt-mermaid-'));
try {
  const packed = JSON.parse(execFileSync(
    'npm', ['pack', `mermaid@${version}`, '--pack-destination', tmp, '--json'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }));
  const { filename, version: got } = packed[0];

  execFileSync('tar', ['-xzf', path.join(tmp, filename), '-C', tmp,
    'package/dist/mermaid.min.js', 'package/LICENSE']);

  mkdirSync(OUT, { recursive: true });
  copyFileSync(path.join(tmp, 'package/dist/mermaid.min.js'), path.join(OUT, 'mermaid.min.js'));
  copyFileSync(path.join(tmp, 'package/LICENSE'), path.join(OUT, 'mermaid.LICENSE'));
  writeFileSync(path.join(OUT, 'mermaid.VERSION'), `${got}\n`);
  console.log(`vendored mermaid ${got} → ${path.relative(process.cwd(), OUT)}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
