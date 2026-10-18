#!/usr/bin/env node
// Basalt CLI. `check` is the self-check PROTOCOL §14.3 requires of a
// conforming implementation: without it, "is my private note actually
// private" is unanswerable.

import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { Vault, INDEX_KEYS } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { S3Transport } from '../src/transport/s3.mjs';
import { Gatekeeper } from '../src/gatekeeper.mjs';
import { Site } from '../src/web/site.mjs';
import { exportSite } from '../src/web/export.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { RIGHTS } from '../src/acl.mjs';

const args = process.argv.slice(2);
const cmd = args[0];

function flag(name, fallback = undefined) {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : (args[i + 1] ?? true);
}

/** Build a transport from flags: --vault for a local path, --bucket for S3. */
function transport() {
  const bucket = flag('bucket');
  if (bucket) {
    return new S3Transport({
      bucket,
      prefix: flag('prefix', ''),
      endpoint: flag('endpoint'),
      region: flag('region'),
      flavor: flag('flavor', 's3'),
    });
  }
  return new FsTransport(path.resolve(flag('vault', '.')));
}

const C = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
};

async function open() {
  const v = new Vault(transport());
  await v.load();
  return v;
}

const USAGE = `basalt — reference implementation of the Basalt Protocol v1

  basalt check   [--vault DIR | --bucket B] [--principal ID] [--path P]
                 Self-check (§14.3): integrity, index freshness, whether a
                 rebuild reproduces the stored indexes byte for byte, and the
                 ACL evaluation of a principal against a path.

  basalt index   [--vault DIR | --bucket B] [--write] [--force]
                 Rebuild every index from content alone. --write persists them.
                 Writing an empty index over a non-empty one is refused
                 (§10.7) unless --force; the usual cause is a transport
                 pointed at the wrong bucket or prefix.

  basalt mint    [--vault DIR | --bucket B]
                 Mint node ids for unbound objects (§4.3).

  basalt serve   [--vault DIR | --bucket B] [--port N] [--principal ID]
                 Serve the publish site and the API (§12). --principal forces
                 an identity for local testing; without it every request is
                 anonymous. --api-only omits the HTML site.

  basalt effective --path P --principal ID
                 Effective rights with the deciding ACE per right (§8.7).

  basalt tree    [--principal ID]
                 The visible tree for a principal.

  basalt export  [--vault DIR | --bucket B] [--out DIR] [--base /repo]
                 [--clean] [--with-vault]
                 Export the PUBLIC subset as a static site (§12.6): only
                 nodes granting both read and publish to anonymous, with
                 indexes rebuilt from that subset rather than copied.
                 --base sets a path prefix for a GitHub Pages project site.
                 --with-vault also emits a re-servable filtered vault.

  basalt conformance-regen [--vault DIR] [--out DIR]
                 Regenerate a conformance vault's expected/ index output.

S3-compatible stores: --bucket NAME --endpoint URL --flavor s3|minio|r2
`;

try {
  switch (cmd) {
    case 'check': {
      const v = await open();
      const built = await v.reindex();
      await v.loadIndexes();
      const stored = v.indexes;
      const fresh = await v.reindex();

      console.log(C.bold(`vault ${v.manifest.vault.id}`),
        C.dim(v.manifest.vault.title ?? ''));
      console.log(C.dim(`audience=${v.manifest.publish?.audience} ` +
        `bypass_traverse=${v.manifest.security?.bypass_traverse ?? false}`));

      // 1. Integrity (§10.7)
      const issues = fresh.integrity.entries;
      const errors = issues.filter((i) => i.severity === 'error');
      const warnings = issues.filter((i) => i.severity === 'warning');
      console.log(`\n${C.bold('integrity')}  ` +
        `${errors.length ? C.red(`${errors.length} error(s)`) : C.green('0 errors')}, ` +
        `${warnings.length ? C.yellow(`${warnings.length} warning(s)`) : '0 warnings'}`);
      for (const i of issues.slice(0, 20)) {
        const tag = i.severity === 'error' ? C.red('error') : C.yellow('warn ');
        console.log(`  ${tag} ${i.code} ${C.dim(i.path ?? '')} ${i.detail ?? ''}`);
      }
      if (issues.length > 20) console.log(C.dim(`  …${issues.length - 20} more`));

      // 2. Freshness (§10.6) — one digest comparison, never timestamps.
      const storedDigest = stored?.nodes?.source_digest ?? null;
      const current = fresh.digest.root;
      console.log(`\n${C.bold('index')}      ` + (
        storedDigest === null ? C.yellow('no stored index')
          : storedDigest === current ? C.green('fresh')
            : C.yellow('stale')));
      console.log(C.dim(`  current ${current}`));
      if (storedDigest) console.log(C.dim(`  stored  ${storedDigest}`));

      // 3. Byte-for-byte reproduction (§13)
      let reproduced = true;
      if (stored) {
        for (const kind of ['nodes', 'links', 'backlinks', 'tags', 'digest']) {
          if (!stored[kind]) continue;
          const norm = (o) => canonicalJson({ ...o, generated: 'EXCLUDED' });
          if (norm(stored[kind]) !== norm(fresh[kind])) {
            reproduced = false;
            console.log(`  ${C.red('differs')} index/${kind}.json`);
          }
        }
      }
      console.log(`\n${C.bold('rebuild')}    ` + (
        !stored ? C.dim('nothing stored to compare')
          : reproduced ? C.green('reproduces stored indexes byte for byte')
            : C.red('does NOT reproduce stored indexes')));

      // 4. ACL evaluation (§8.7)
      const who = flag('principal');
      const what = flag('path');
      if (who && what) {
        const e = v.effective(who, what);
        console.log(`\n${C.bold('access')}     ${who} on ${what}`);
        for (const r of RIGHTS) {
          const d = e.decisions[r];
          const mark = d.decision === 'allow' ? C.green('allow') : C.red('deny ');
          console.log(`  ${mark} ${r.padEnd(15)} ${C.dim(`by ${d.by}`)}` +
            (d.failed_at !== undefined ? C.dim(` at ${d.failed_at}`) : ''));
        }
      } else {
        console.log(C.dim('\n  (pass --principal and --path for an ACL evaluation)'));
      }

      process.exitCode = errors.length || !reproduced ? 1 : 0;
      break;
    }

    case 'index': {
      const v = await open();
      const write = args.includes('--write');
      const idx = await v.reindex({ write, force: args.includes('--force') });
      console.log(`${idx.nodes.entries.length} nodes, ` +
        `${idx.links.entries.length} edges, ` +
        `${Object.keys(idx.tags.entries).length} tags`);
      console.log(`digest ${idx.digest.root}`);
      if (write) console.log(`wrote ${Object.keys(INDEX_KEYS).length} index objects`);
      else console.log(C.dim('(dry run; pass --write to persist)'));
      break;
    }

    case 'mint': {
      const v = await open();
      const minted = await v.mintIds();
      if (!minted.length) console.log('every object already carries an id');
      for (const m of minted) console.log(`  ${m.id}  ${m.path} ${C.dim(`(${m.where})`)}`);
      break;
    }

    case 'serve': {
      const v = await open();
      await v.reindex();
      const forced = flag('principal');
      const g = new Gatekeeper(v, {
        identify: () => forced ?? 'anonymous',
        delivery: flag('delivery', 'proxy'),
        site: args.includes('--api-only') ? null : new Site(v),
      });
      const port = Number(flag('port', 4380));
      await g.listen(port);
      console.log(`gatekeeper on http://127.0.0.1:${port}`);
      console.log(C.dim(`  audience=${v.manifest.publish?.audience} ` +
        `principal=${forced ?? 'anonymous'}`));
      if (!args.includes('--api-only')) {
        console.log(C.dim('  the publish site is at /  (pass --api-only to serve just the API)'));
      }
      console.log(C.dim('  GET /api/v1/{manifest,tree,node/<path>,raw/<path>,' +
        'list/<folder>,links/<path>,search?q=,effective?path=}'));
      break;
    }

    case 'effective': {
      const v = await open();
      await v.reindex();
      const e = v.effective(flag('principal', 'anonymous'), flag('path', ''));
      for (const r of RIGHTS) {
        const d = e.decisions[r];
        console.log(`${d.decision === 'allow' ? C.green('allow') : C.red('deny ')} ` +
          `${r.padEnd(15)} ${C.dim(`by ${d.by}`)}`);
      }
      break;
    }

    case 'tree': {
      const v = await open();
      await v.reindex();
      const { tree } = v.tree(flag('principal', 'anonymous'));
      const show = (n, depth = 0) => {
        if (!n) return;
        const pad = '  '.repeat(depth);
        console.log(`${pad}${C.bold(n.title ?? n.folder)} ${C.dim(n.folder)}`);
        for (const e of n.entries) console.log(`${pad}  ${e.title} ${C.dim(e.path)}`);
        for (const f of n.folders) show(f, depth + 1);
      };
      show(tree);
      break;
    }

    case 'export': {
      const v = await open();
      await v.reindex();
      const out = flag('out', './dist');
      const result = await exportSite({
        vault: v,
        out,
        base: flag('base', ''),
        withVault: args.includes('--with-vault'),
        clean: args.includes('--clean'),
        log: (msg, kind) => console.log(
          kind === 'dim' ? C.dim('  ' + msg)
            : kind === 'warn' ? C.yellow('  ' + msg) : msg),
      });
      console.log();
      console.log(`${C.green(String(result.pages))} pages → ${result.outDir}`);
      if (result.withheld.length) {
        console.log(C.dim(`  ${result.withheld.length} node(s) withheld; ` +
          `indexes were rebuilt from the public subset only (§12.6)`));
      }
      break;
    }

    case 'conformance-regen': {
      // Regenerate conformance/vaults/<name>/expected/ from the reference
      // implementation. A change in this diff is a change to the protocol's
      // observable output, so it is reviewed by hand, never rubber-stamped.
      const dir = flag('vault', '../conformance/vaults/minimal/vault');
      const out = flag('out', path.join(dir, '..', 'expected'));
      const v = new Vault(new FsTransport(path.resolve(dir)));
      await v.load();
      const idx = await v.reindex();
      await mkdir(path.resolve(out), { recursive: true });
      for (const kind of ['nodes', 'links', 'backlinks', 'tags', 'search',
                          'digest', 'integrity']) {
        if (!idx[kind]) continue;
        // §13.2: `generated` is excluded from comparison, so it is pinned to
        // a constant here rather than left as a wall-clock timestamp that
        // would make every regeneration a diff.
        const obj = { ...idx[kind], generated: '1970-01-01T00:00:00Z' };
        const file = path.resolve(out, `${kind}.json`);
        await writeFile(file, canonicalJson(obj), 'utf8');
        console.log(`  wrote ${path.relative(process.cwd(), file)}`);
      }
      break;
    }

    default:
      console.log(USAGE);
      process.exitCode = cmd ? 1 : 0;
  }
} catch (err) {
  console.error(C.red(`error: ${err.message}`));
  process.exitCode = 1;
}
