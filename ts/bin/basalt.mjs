#!/usr/bin/env node
// Basalt CLI. `check` is the self-check PROTOCOL §14.3 requires of a
// conforming implementation: without it, "is my private note actually
// private" is unanswerable.

import { writeFile, mkdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { Vault, INDEX_KEYS } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { S3Transport } from '../src/transport/s3.mjs';
import { Gatekeeper, ALL_SURFACES } from '../src/gatekeeper.mjs';
import { Router } from '../src/serve/router.mjs';
import { Site } from '../src/web/site.mjs';
import { openapiDocument } from '../src/serve/rest.mjs';
import { printSchema } from '../src/serve/graphql.mjs';
import { mcpMethods } from '../src/serve/mcp.mjs';
import { serveStdio } from '../src/serve/jsonrpc.mjs';
import { Surface } from '../src/serve/core.mjs';
import { exportSite } from '../src/web/export.mjs';
import { canonicalJson } from '../src/canonical.mjs';
import { RIGHTS } from '../src/acl.mjs';
import { storeObject, checkProvenanceLabel } from '../src/store.mjs';
import { kindFor } from '../src/frontmatter.mjs';

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

  basalt add     <FILE>... [--to FOLDER/] [--vault DIR | --bucket B]
                 [--title T] [--alt A] [--principal ID]
                 [--agent LABEL] [--account LABEL]
                 basalt add - --as PATH        (content from stdin)
                 Store a note, an image or any other file as a NEW object
                 (§12.7): it gets an id, an entry sidecar if it cannot carry
                 frontmatter, and the indexes are refreshed. Never
                 overwrites. Without --to, notes go to Notes/ and everything
                 else to Assets/. --as gives the exact vault path of a single
                 file. Without --principal you act as the operator who holds
                 the vault's credentials; with it, that principal's
                 create_child right on the folder is enforced. --agent and
                 --account stamp the new object "created_by" (a note's
                 frontmatter, or the entry sidecar) with those labels. Here
                 they are whatever you type, so they are only as true as
                 you are.

  basalt serve   [--vault DIR | --bucket B] [--port N] [--principal ID]
                 [--surfaces LIST] [--public-url URL] [--cors ORIGIN]
                 Serve the publish site and every interop surface (§12,
                 INTEROP): REST+OpenAPI, GraphQL, JSON-RPC, MCP, Connect/gRPC
                 (JSON), read-only WebDAV, Atom/RSS/sitemap/OpenSearch and
                 RDF. --principal forces an identity for local testing;
                 without it every request is anonymous. --api-only omits the
                 HTML site. Without --surfaces the vault's own
                 publish.interop decides; --surfaces overrides it with a
                 subset of
                 rest,graphql,jsonrpc,mcp,connect,webdav,feeds,rdf.
                 --public-url sets the absolute base used by feeds and RDF
                 IRIs behind a proxy. --cors is off by default on purpose:
                 these responses are per-principal.

  basalt mcp     [--vault DIR | --bucket B] [--principal ID] [--writable]
                 [--agent LABEL] [--account LABEL]
                 Serve one vault to an MCP client over stdio (INTEROP §4.2).
                 Nothing but JSON-RPC goes to stdout; diagnostics go to
                 stderr. The principal is fixed for the life of the process.
                 --writable adds basalt_store, which creates new notes,
                 images and files (never overwrites) subject to that
                 principal's ACL; it requires --principal. --agent and
                 --account name who is behind this process ("claude-code",
                 "work"): every object it creates is stamped "created_by"
                 with them, the principal, the time, and what the client
                 called itself. Labels, not emails; each account's MCP
                 config passes its own.

  basalt schema  <openapi|graphql|proto|discovery> [--vault DIR] [--base URL]
                 Print the machine-readable description of a surface: the
                 OpenAPI 3.1 document, the GraphQL SDL, the protobuf service,
                 or the /.well-known/basalt discovery document.

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

    case 'add': {
      // Flags that take a value, so the remaining words are the files.
      const takesValue = new Set(['vault', 'bucket', 'prefix', 'endpoint', 'region',
        'flavor', 'to', 'as', 'title', 'alt', 'principal', 'agent', 'account']);
      const sources = [];
      for (let i = 1; i < args.length; i++) {
        if (args[i].startsWith('--')) {
          if (takesValue.has(args[i].slice(2))) i++;
        } else sources.push(args[i]);
      }
      if (!sources.length) throw new Error('add needs a file to store, or - for stdin with --as PATH');

      const as = flag('as');
      const to = flag('to');
      const title = flag('title');
      const alt = flag('alt');
      if (as && to) throw new Error('--as names the whole path; --to names only the folder');
      if (sources.length > 1 && (as || title || alt)) {
        throw new Error('--as, --title and --alt describe one file; add several with --to FOLDER/');
      }
      // No --principal: you are the operator, who holds the credentials and
      // could write the file by hand. With one, §8 applies as for anyone.
      const principal = flag('principal') || null;
      const agent = checkProvenanceLabel('--agent', flag('agent'));
      const account = checkProvenanceLabel('--account', flag('account'));
      // Stamp only when asked: an operator filing a PDF by hand has not said
      // who they are, and inventing a record of it would be worse than none.
      const provenance = agent || account ? { agent, account } : undefined;
      const folderFor = (name) => {
        if (to === undefined) return kindFor(name) === 'note' ? 'Notes/' : 'Assets/';
        const f = String(to).replace(/^\/+/, '');
        return f === '' || f.endsWith('/') ? f : f + '/';
      };
      const size = (n) => n < 1024 ? `${n} B`
        : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;

      const v = await open();
      let stored = 0;
      let refused = 0;
      for (const src of sources) {
        try {
          let bytes;
          let name;
          if (src === '-') {
            if (!as) throw new Error('content from stdin needs --as PATH');
            const chunks = [];
            for await (const c of process.stdin) chunks.push(c);
            bytes = Buffer.concat(chunks);
          } else {
            if ((await stat(src)).isDirectory()) {
              throw new Error('is a directory; add the files in it');
            }
            bytes = await readFile(src);
            // macOS hands out decomposed (NFD) filenames, which §1.1 rejects.
            name = path.basename(src).normalize('NFC');
          }
          const dest = as ?? folderFor(name) + name;
          const r = await storeObject(v, {
            principal, path: dest, bytes, title, alt, provenance, reindex: false,
          });
          stored++;
          console.log(`${C.green('stored')}  ${r.path}  ${C.dim(`${r.id}  ${r.kind}, ${size(r.size)}`)}`);
        } catch (err) {
          refused++;
          console.error(`${C.red('refused')} ${src === '-' ? 'stdin' : src}: ${err.message}`);
        }
      }
      if (stored) {
        // One index pass for the whole batch (the stores skip it for speed).
        const idx = await v.reindex({ write: true });
        const issues = idx.integrity.entries;
        const errs = issues.filter((i) => i.severity === 'error').length;
        const warns = issues.length - errs;
        console.log(C.dim(`indexes refreshed · integrity ${errs} errors, ${warns} warnings`));
      }
      process.exitCode = refused ? 1 : 0;
      break;
    }

    case 'serve': {
      const v = await open();
      // §10.6: report the state honestly. `serve` rebuilds in memory, so the
      // answer is `fresh` only when the stored indexes already matched the
      // content it just hashed.
      await v.loadIndexes();
      const before = await v.indexState().catch(() => ({ fresh: false }));
      await v.reindex();
      const forced = flag('principal');
      // Left out, the manifest's publish.interop decides (§3.1); a manifest
      // that says nothing about profiles mounts everything.
      const picked = flag('surfaces');
      const chosen = picked && picked !== true
        ? new Set(String(picked).split(',').map((x) => x.trim()).filter(Boolean))
        : undefined;
      for (const name of chosen ?? []) {
        if (!ALL_SURFACES.includes(name)) {
          throw new Error(`unknown surface ${name}; known: ${ALL_SURFACES.join(', ')}`);
        }
      }
      const g = new Gatekeeper(v, {
        identify: () => forced ?? 'anonymous',
        delivery: flag('delivery', 'proxy'),
        site: args.includes('--api-only') ? null : new Site(v),
        surfaces: chosen,
        publicUrl: flag('public-url') || undefined,
        cors: flag('cors') || null,
      });
      g.indexState = before.fresh ? 'fresh' : 'rebuilt';
      const port = Number(flag('port', 4380));
      await g.listen(port);
      const origin = `http://127.0.0.1:${port}`;
      console.log(`gatekeeper on ${origin}`);
      console.log(C.dim(`  audience=${v.manifest.publish?.audience} ` +
        `principal=${forced ?? 'anonymous'}`));
      if (!args.includes('--api-only')) {
        console.log(C.dim('  the publish site is at /  (pass --api-only to serve just the API)'));
      }
      // One line per surface, so the thing to paste into a client is on screen.
      const lines = {
        rest: 'GET  /api/v1/{manifest,me,tree,nodes,node/<path>,raw/<path>,list/<folder>,links/<path>,search?q=,tags,effective?path=}',
        graphql: 'POST /graphql          · SDL at /graphql/schema.graphql',
        jsonrpc: 'POST /rpc              · basalt.operations lists the methods',
        mcp: 'POST /mcp              · or `basalt mcp` over stdio',
        connect: 'POST /basalt.v1.BasaltRead/<Method>  (JSON codec)',
        webdav: 'DAV  /dav/             · read-only; mount it in Finder or rclone',
        feeds: 'GET  /feed.atom /feed.xml /sitemap.xml /opensearch.xml /robots.txt',
        rdf: 'GET  /graph.jsonld /graph.ttl',
      };
      for (const name of ALL_SURFACES) {
        if (g.router.enabled.has(name)) console.log(C.dim(`  ${lines[name]}`));
      }
      console.log(C.dim(`  every surface at once: ${origin}/.well-known/basalt`));
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

    case 'mcp': {
      // The stdio transport an MCP client spawns. stdout carries JSON-RPC and
      // nothing else, so the usual startup chatter goes to stderr.
      const v = await open();
      await v.reindex();
      const principal = flag('principal', 'anonymous');
      const writable = args.includes('--writable');
      const agent = checkProvenanceLabel('--agent', flag('agent'));
      const account = checkProvenanceLabel('--account', flag('account'));
      if ((agent || account) && !writable) {
        throw new Error('--agent and --account label what this process writes; they need --writable');
      }
      if (writable && principal === 'anonymous') {
        // An anonymous writer is whatever the ACL says anonymous may do, and
        // for a vault that never meant to be written that is nothing: fail
        // loudly here instead of offering a tool that always refuses.
        throw new Error('--writable needs --principal ID: a write is judged against who made it');
      }
      const surface = new Surface(v);
      const who = [agent && `agent ${agent}`, account && `account ${account}`]
        .filter(Boolean).join(', ');
      process.stderr.write(
        `basalt mcp: vault ${v.manifest.vault.id} as ${principal}` +
        `${writable ? ' (may create notes, images and files' +
          `${who ? `; stamped ${who}` : '; stamped with no agent or account, see --agent/--account'})` : ''}\n`);
      await serveStdio(mcpMethods(surface, principal, { writable, agent, account }));
      break;
    }

    case 'schema': {
      const which = args[1];
      const base = flag('base', 'http://127.0.0.1:4380');
      if (which === 'proto') {
        const file = new URL('../../protocol/basalt.proto', import.meta.url);
        process.stdout.write(await readFile(file, 'utf8'));
        break;
      }
      if (which === 'graphql') {
        process.stdout.write(printSchema() + '\n');
        break;
      }
      const v = await open();
      if (which === 'openapi') {
        process.stdout.write(canonicalJson(openapiDocument(new Surface(v), { baseUrl: base })));
        break;
      }
      if (which === 'discovery') {
        await v.reindex();
        process.stdout.write(canonicalJson(new Router(v, { site: null }).discovery(base)));
        break;
      }
      throw new Error('schema takes one of: openapi, graphql, proto, discovery');
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
