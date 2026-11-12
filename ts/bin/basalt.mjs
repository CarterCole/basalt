#!/usr/bin/env node
// Basalt CLI. `check` is the self-check PROTOCOL §14.3 requires of a
// conforming implementation: without it, "is my private note actually
// private" is unanswerable.

import { writeFile, mkdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { Vault, INDEX_KEYS } from '../src/vault.mjs';
import { FsTransport } from '../src/transport/fs.mjs';
import { S3Transport } from '../src/transport/s3.mjs';
import { GitTransport } from '../src/transport/git.mjs';
import { GistTransport, GistApi, parseGistId } from '../src/transport/gist.mjs';
import { exportToGist, importFromGist, folderPath } from '../src/gist.mjs';
import { INDEX } from '../src/keys.mjs';
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
import { storeObject, checkProvenanceLabel, normalizeCaller } from '../src/store.mjs';
import { kindFor } from '../src/frontmatter.mjs';

const args = process.argv.slice(2);
const cmd = args[0];

function flag(name, fallback = undefined) {
  const i = args.indexOf(`--${name}`);
  return i === -1 ? fallback : (args[i + 1] ?? true);
}

/**
 * Build a transport from flags. One store per process: --vault for a plain
 * folder (the default, "."), --git for a folder in a git working tree,
 * --bucket for S3, MinIO or R2, --gist for a GitHub gist. Adding a store is
 * adding a row here.
 */
const STORES = {
  vault: (dir) => new FsTransport(path.resolve(dir)),
  git: (dir) => new GitTransport(path.resolve(dir), {
    remote: stringFlag('remote'),
    // Indexes are rebuilt from content (§10), so a merge that conflicts only
    // in them keeps this side's and lets the next reindex settle it.
    derived: [INDEX],
  }),
  bucket: (bucket) => new S3Transport({
    bucket,
    prefix: flag('prefix', ''),
    endpoint: flag('endpoint'),
    region: flag('region'),
    flavor: flag('flavor', 's3'),
  }),
  gist: (id) => new GistTransport({ id, api: gistApi() }),
};

/** The GitHub client. The token comes from the environment, never a flag. */
function gistApi() {
  return new GistApi({ apiUrl: stringFlag('api-url') });
}

/** Flags that take a value, so the words left over are the positional ones. */
const VALUE_FLAGS = new Set(['vault', 'git', 'remote', 'bucket', 'prefix', 'endpoint', 'region',
  'flavor', 'gist', 'api-url', 'to', 'as', 'title', 'alt', 'principal', 'agent', 'account',
  'update', 'description', 'out', 'base', 'port', 'surfaces', 'public-url', 'cors', 'delivery', 'path']);

function positionals(from) {
  const out = [];
  for (let i = from; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      if (VALUE_FLAGS.has(args[i].slice(2))) i++;
    } else out.push(args[i]);
  }
  return out;
}

function stringFlag(name) {
  const v = flag(name);
  if (v === true) throw new Error(`--${name} needs a value`);
  return v;
}

function transport() {
  const given = Object.keys(STORES).filter((name) => flag(name) !== undefined);
  if (given.length > 1) {
    throw new Error(`pick one store: ${given.map((n) => `--${n}`).join(' and ')} were both given`);
  }
  const name = given[0] ?? 'vault';
  if (flag('remote') !== undefined && name !== 'git') {
    throw new Error('--remote is for a git store (--git DIR)');
  }
  return STORES[name](given.length ? stringFlag(name) : '.');
}

const C = {
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
};

async function open() {
  const t = transport();
  // A git store checks it is in a working tree and, with --remote, pulls.
  if (typeof t.ready === 'function') await t.ready();
  const v = new Vault(t);
  await v.load();
  // After a push that had to merge first, rebuild the indexes so what goes
  // out matches the merged content.
  if (t instanceof GitTransport) {
    t.rederive = async () => { await v.load(); await v.reindex({ write: true }); };
  }
  return v;
}

/**
 * What the store says the credentials behind this process belong to (§12.7
 * `caller`), for the writes to record. Asked once, because every write this
 * process makes is signed with the same credentials. A store that cannot say
 * gives nothing; one that fails to answer is reported and the writes go
 * ahead without it, as they did before there was a caller to record.
 */
async function lookupCaller(v) {
  if (typeof v.t.callerIdentity !== 'function') return undefined;
  try {
    return normalizeCaller(await v.t.callerIdentity());
  } catch (err) {
    // Plain, like the rest of what `basalt mcp` writes to stderr: an MCP
    // client keeps it in a log file, where colour codes are noise.
    process.stderr.write('basalt: could not name the caller, so writes will not ' +
      `record one: ${err.message}\n`);
    return undefined;
  }
}

const USAGE = `basalt — reference implementation of the Basalt Protocol v1

  basalt check   [--vault DIR | --git DIR | --bucket B] [--principal ID] [--path P]
                 Self-check (§14.3): integrity, index freshness, whether a
                 rebuild reproduces the stored indexes byte for byte, and the
                 ACL evaluation of a principal against a path.

  basalt index   [--vault DIR | --git DIR | --bucket B] [--write] [--force]
                 Rebuild every index from content alone. --write persists them.
                 Writing an empty index over a non-empty one is refused
                 (§10.7) unless --force; the usual cause is a transport
                 pointed at the wrong bucket or prefix.

  basalt mint    [--vault DIR | --git DIR | --bucket B]
                 Mint node ids for unbound objects (§4.3).

  basalt add     <FILE>... [--to FOLDER/] [--vault DIR | --git DIR | --bucket B]
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
                 you are. On AWS S3 the stamp also names the caller: the
                 ARN AWS reports for the credentials doing the write.

  basalt gist export FOLDER/ | --whole  [--update ID [--prune]] [--public]
                 [--description TEXT] [--dry-run] [--principal ID]
                 [--vault DIR | --git DIR | --bucket B]
                 Send a vault folder to a GitHub gist: a NEW secret gist, or
                 --update to write into one you already have. A gist is flat
                 and holds non-empty text, so a file's path inside FOLDER/
                 becomes one file name ("Notes/A.md" is "Notes%2FA.md"), and
                 a binary or empty file is left out and listed, never dropped
                 silently. --whole sends every key of the vault, so the gist
                 opens as a vault with --gist. A secret gist is unlisted, not
                 private: anyone with its URL can read it, whatever
                 basalt.yaml says. --public lists it. --dry-run prints what
                 would be sent and sends nothing. --update only adds and
                 changes files; --prune also removes the gist's files the
                 folder no longer has. --principal sends only what that
                 principal may read. The token is read from GITHUB_TOKEN or
                 GH_TOKEN (or \`gh auth token\`), never from a flag.

  basalt gist import ID|URL [--to FOLDER/] [--principal ID]
                 [--agent LABEL] [--account LABEL]
                 [--vault DIR | --git DIR | --bucket B]
                 Store every file of a gist as a NEW object under FOLDER/
                 (default Gists/<id>/), as \`basalt add\` does: each gets an
                 id, and one whose path is taken is refused, never replaced.
                 A public or secret gist needs no token to read.

  basalt serve   [--vault DIR | --git DIR | --bucket B] [--port N] [--principal ID]
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

  basalt mcp     [--vault DIR | --git DIR | --bucket B] [--principal ID] [--writable]
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
                 config passes its own. On AWS S3 it also records the
                 caller, the ARN AWS reports for the process's credentials,
                 which is the one part of the stamp nobody types.

  basalt schema  <openapi|graphql|proto|discovery> [--vault DIR] [--base URL]
                 Print the machine-readable description of a surface: the
                 OpenAPI 3.1 document, the GraphQL SDL, the protobuf service,
                 or the /.well-known/basalt discovery document.

  basalt effective --path P --principal ID
                 Effective rights with the deciding ACE per right (§8.7).

  basalt tree    [--principal ID]
                 The visible tree for a principal.

  basalt export  [--vault DIR | --git DIR | --bucket B] [--out DIR] [--base /repo]
                 [--clean] [--with-vault]
                 Export the PUBLIC subset as a static site (§12.6): only
                 nodes granting both read and publish to anonymous, with
                 indexes rebuilt from that subset rather than copied.
                 --base sets a path prefix for a GitHub Pages project site.
                 --with-vault also emits a re-servable filtered vault.

  basalt conformance-regen [--vault DIR] [--out DIR]
                 Regenerate a conformance vault's expected/ index output.

Stores (pick one; every command takes the same flags):
  --vault DIR    a plain folder (the default, ".")
  --git DIR      a folder in a git working tree. Reads come from disk; each
                 write (a stored note, a reindex, a mint) is one commit, made
                 with your git identity, of only the files basalt wrote.
                 Files .gitignore excludes are written but not committed.
    --remote NAME  also pull before each write and push after it (never
                 forced). Offline or rejected, the write still succeeds and
                 the commit goes out with the next push. Pushing copies the
                 vault to that remote: a private audience is enforced by
                 basalt's server, not by the git host.
  --bucket NAME  S3, MinIO or R2: --endpoint URL --flavor s3|minio|r2
                 [--prefix P/] [--region R]
  --gist ID|URL  a whole vault inside one gist (made with \`gist export
                 --whole\`). Text only, at most 300 files; a batch of writes
                 is one gist revision. Writes need GITHUB_TOKEN. --api-url
                 URL points at GitHub Enterprise.
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
      // The words left once the flags and their values are set aside are the files.
      const sources = positionals(1);
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
      const v = await open();
      // Stamp only when there is something true to say: the labels you typed,
      // or the caller the store itself names. An operator filing a PDF by hand
      // into a local folder has said neither, and inventing a record of who
      // they are would be worse than none.
      const caller = await lookupCaller(v);
      const provenance = agent || account || caller ? { agent, account, caller } : undefined;
      if (caller) console.log(C.dim(`storing as ${caller}`));
      const folderFor = (name) => {
        if (to === undefined) return kindFor(name) === 'note' ? 'Notes/' : 'Assets/';
        const f = String(to).replace(/^\/+/, '');
        return f === '' || f.endsWith('/') ? f : f + '/';
      };
      const size = (n) => n < 1024 ? `${n} B`
        : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;

      let stored = 0;
      let refused = 0;
      const storedPaths = [];
      // On a git store the whole command is one commit: every file it stored
      // and the one index refresh at the end.
      await v.batch({
        message: () => storedPaths.length === 1 ? `Add ${storedPaths[0]}`
          : `Add ${storedPaths.length} files`,
        trailers: principal ? { 'Basalt-Principal': principal } : {},
      }, async () => {
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
            storedPaths.push(r.path);
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
      });
      process.exitCode = refused ? 1 : 0;
      break;
    }

    case 'gist': {
      if (args.some((a) => a === '--token' || a.startsWith('--token='))) {
        // A token on the command line lands in shell history and `ps`.
        throw new Error('there is no --token flag: set GITHUB_TOKEN (or GH_TOKEN), or sign in with `gh auth login`');
      }
      const sub = args[1];
      const rest = positionals(2);
      const api = gistApi();
      const principal = flag('principal') || null;
      const size = (n) => n < 1024 ? `${n} B`
        : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
      const why = { empty: 'empty', not_text: 'not text a gist can hold', name_too_long: 'name too long', invalid_key: 'not a valid vault path' };
      const skippedLines = (skipped) => {
        if (!skipped.length) return;
        console.log(C.yellow(`left out ${skipped.length} file(s) a gist cannot hold:`));
        for (const s of skipped.slice(0, 20)) console.log(C.yellow(`  ${s.path}  (${why[s.reason] ?? s.reason})`));
        if (skipped.length > 20) console.log(C.dim(`  …${skipped.length - 20} more`));
      };

      if (sub === 'export') {
        const whole = args.includes('--whole');
        if (whole ? rest.length : rest.length !== 1) {
          throw new Error('gist export needs one folder (e.g. Projects/), or --whole');
        }
        const update = flag('update') === undefined ? undefined : parseGistId(stringFlag('update'));
        if (flag('update') !== undefined && !update) throw new Error('--update needs a gist id or URL');
        const v = await open();
        // A principal's view needs inline ACLs, which come from a reindex.
        if (principal) await v.reindex();
        const r = await exportToGist(v, {
          folder: whole ? '' : folderPath(rest[0]),
          whole,
          api,
          update,
          prune: args.includes('--prune'),
          public: args.includes('--public'),
          description: flag('description') === undefined ? undefined : stringFlag('description'),
          principal,
          dryRun: args.includes('--dry-run'),
        });
        const where = r.public ? C.red('PUBLIC') : 'secret';
        if (r.dryRun) {
          console.log(`would send ${r.count} file(s), ${size(r.bytes)}, as a new ${where} gist` +
            C.dim(' (nothing sent: --dry-run)'));
          for (const n of r.names) console.log(`  ${n}`);
        }
        skippedLines(r.skipped);
        if (r.withheld) {
          console.log(C.dim(`${r.withheld} file(s) withheld: ${principal} may not read them`));
        }
        if (!r.dryRun) {
          if (r.created) {
            console.log(`${C.green('created')} ${where} gist ${r.url}`);
            console.log(C.dim(`  ${r.count} file(s), ${size(r.bytes)}` + (r.public
              ? '. It is public: anyone can find and read it.'
              : '. Secret means unlisted, not private: anyone with the URL can read it.')));
          } else if (!r.updated) {
            console.log(`${C.green('up to date')}  ${r.url}  ${C.dim(`${r.unchanged} file(s) unchanged`)}`);
          } else {
            console.log(`${C.green('updated')} ${where} gist ${r.url}`);
            console.log(C.dim(`  ${r.written} written, ${r.unchanged} unchanged` +
              (r.removed ? `, ${r.removed} removed` : '')));
          }
          if (r.left?.length) {
            console.log(C.yellow(`${r.left.length} file(s) in the gist are not in the folder ` +
              `(--prune removes them): ${r.left.slice(0, 5).join(', ')}${r.left.length > 5 ? ', …' : ''}`));
          }
        }
        break;
      }

      if (sub === 'import') {
        if (rest.length !== 1) throw new Error('gist import needs one gist id or URL');
        const id = parseGistId(rest[0]);
        if (!id) throw new Error(`not a gist id or URL: ${rest[0]}`);
        const agent = checkProvenanceLabel('--agent', flag('agent'));
        const account = checkProvenanceLabel('--account', flag('account'));
        const v = await open();
        const caller = await lookupCaller(v);
        const provenance = agent || account || caller ? { agent, account, caller } : undefined;
        const to = flag('to') === undefined ? `Gists/${id}/` : folderPath(stringFlag('to'));
        const r = await importFromGist(v, {
          api, id, to, principal, provenance,
          log: (o) => console.log(`${C.green('stored')}  ${o.path}  ` +
            C.dim(`${o.id}  ${o.kind}, ${size(o.size)}`)),
        });
        for (const x of r.refused) console.error(`${C.red('refused')} ${x.name}: ${x.error}`);
        console.log(C.dim(`${r.stored.length} stored, ${r.refused.length} refused, from ` +
          `${r.gist.public ? 'public' : 'secret'} gist ${r.gist.url ?? r.gist.id}` +
          (r.stored.length ? ' · indexes refreshed' : '')));
        process.exitCode = r.refused.length ? 1 : 0;
        break;
      }

      throw new Error('gist takes export or import (basalt gist export FOLDER/, basalt gist import ID)');
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
      const caller = writable ? await lookupCaller(v) : undefined;
      const who = [agent && `agent ${agent}`, account && `account ${account}`]
        .filter(Boolean).join(', ');
      const where = v.t instanceof GitTransport
        ? ` (git${v.t.remote ? `, syncing with ${v.t.remote} ${v.t.remoteUrl}` : ', local only'})` : '';
      process.stderr.write(
        `basalt mcp: vault ${v.manifest.vault.id}${where} as ${principal}` +
        `${writable ? ' (may create notes, images and files' +
          `${who ? `; stamped ${who}` : '; stamped with no agent or account, see --agent/--account'}` +
          `${caller ? `; caller ${caller}` : ''})` : ''}\n`);
      await serveStdio(mcpMethods(surface, principal, { writable, agent, account, caller }));
      break;
    }

    case 'schema': {
      const which = args[1];
      const base = flag('base', 'http://127.0.0.1:4380');
      if (which === 'proto') {
        // basalt.proto belongs to the spec checkout (protocol/), not to this
        // package: the monorepo has it two levels up, a per-language repository
        // carries the spec as a submodule at spec/, and an installed package
        // has neither.
        let proto = null;
        for (const rel of ['../../protocol/basalt.proto', '../spec/protocol/basalt.proto']) {
          try {
            proto = await readFile(new URL(rel, import.meta.url), 'utf8');
            break;
          } catch (err) {
            if (err.code !== 'ENOENT') throw err;
          }
        }
        if (proto === null) {
          process.stderr.write('basalt.proto is part of the spec, not of this package: ' +
            'https://github.com/CarterCole/basalt/blob/main/protocol/basalt.proto\n');
          process.exitCode = 1;
          break;
        }
        process.stdout.write(proto);
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
