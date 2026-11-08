// Creating objects, PROTOCOL §12.7 — storing a note, an image or any other
// file in a vault.
//
// This is the write path the read surfaces deliberately do not have, and it is
// create-only on purpose. Replacing or deleting an object destroys work, and
// §11 (history) is what makes that recoverable; until a vault has history,
// the only write that cannot lose anything is the one that refuses to touch an
// object that already exists.
//
// What a store has to get right, in the order it happens:
//
//   1. The path must be one a reader can address: a valid key (§1.1), not a
//      name a filesystem transport silently skips, not under a withheld tree
//      (§12.4), and not colliding with anything already there (§2.2).
//   2. The principal needs `create_child` on the folder (§8.1). A note that
//      carries its own inline ACL additionally needs `write_acl`, because an
//      inline ACL replaces the folder file's entry (§8.6) and so would
//      otherwise be a way to grant yourself rights you were never given.
//   3. The object gets an identity at birth (§4.3): a frontmatter id for a
//      note, an entry sidecar (§6.1) for anything that cannot carry
//      frontmatter. Never an unbound object. The same place records who
//      stored it (`created_by`: principal, agent, account), so that a vault
//      written to by several agents and several accounts can say which.
//   4. The indexes are rebuilt and persisted, so the vault is exactly as
//      fresh after a store as before it.

import YAML from 'yaml';
import { createHash } from 'node:crypto';
import {
  CONTENT, META, pathToKey, parentFolder, basename, validateKey,
  findCollisions, findFolderCaseDivergence,
} from './keys.mjs';
import { kindFor, parseNote, withId } from './frontmatter.mjs';
import { ulid } from './vault.mjs';
import { Fault, WITHHELD, mediaFor } from './serve/core.mjs';

/**
 * The largest object a store accepts. A bound, not a recommendation: the same
 * call arrives base64-encoded inside a JSON-RPC line over MCP, and a model
 * should not be able to hand the process an unbounded allocation.
 */
export const MAX_STORE_BYTES = 25 * 1024 * 1024;

const MAX_LABEL = 1000;       // a title or alt text
const MAX_SEGMENT_BYTES = 255; // the filename limit on the filesystems that matter

/** Names the filesystem transport's listing skips: stored, they would vanish. */
const INVISIBLE = new Set(['.git', '.DS_Store']);

/**
 * A refusal that is not one of the shared surface faults.
 *
 * The shared table (core.mjs FAULTS) is owned by the conformance corpus and
 * has no 409 or 413, because no read can conflict or be too large. Adding
 * rows there would be a corpus change for a feature the corpus does not cover
 * yet, so these carry their own code and status and travel as a Fault.
 */
export class StoreFault extends Fault {
  constructor(code, status, detail) {
    super('bad_request', detail);
    this.code = code;
    this.status = status;
    this.message = `${code}: ${detail}`;
  }
}

const bad = (detail) => new Fault('bad_request', detail);

/**
 * An operator's name for an agent or an account: "claude-code", "work",
 * "copilot:acme". Deliberately has no `@`, so an email address cannot be
 * pasted in by mistake; these end up in files that get shared and published.
 */
const PROVENANCE_LABEL = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/;
const MAX_CLIENT_FIELD = 100;

export function checkProvenanceLabel(name, value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string' || !PROVENANCE_LABEL.test(value)) {
    throw bad(`${name} must be a short label such as "work" or "claude-code" ` +
      `(letters, digits and . _ : / -, at most 64), not an email address or a token`);
  }
  return value;
}

/** A client-reported string, made safe to keep: printable, one line, bounded. */
function cleanClientField(value) {
  if (typeof value !== 'string') return undefined;
  const s = value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, ' ')
    .replace(/\s+/g, ' ').trim().slice(0, MAX_CLIENT_FIELD);
  return s || undefined;
}

/**
 * The `created_by` record (PROTOCOL §12.7).
 *
 * `principal`, `agent` and `account` are what the operator declared when it
 * started the process; `client` is what the connecting program called itself
 * in its MCP `initialize`, which nothing verifies. They are kept apart so
 * that a reader can tell a fact from a claim. None of them is read from tool
 * arguments, so the model being served cannot choose its own.
 */
export function buildCreatedBy({ principal, agent, account, client }, now = new Date()) {
  const name = cleanClientField(client?.name);
  const version = cleanClientField(client?.version);
  const by = {};
  if (principal) by.principal = principal;
  const a = checkProvenanceLabel('agent', agent);
  if (a) by.agent = a;
  const acct = checkProvenanceLabel('account', account);
  if (acct) by.account = acct;
  if (name) by.client = { name, ...(version ? { version } : {}) };
  by.at = now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  return by;
}

const conflict = (detail) => new StoreFault('conflict', 409, detail);

// One store at a time per vault. The sidecar is a read-modify-write and the
// collision check reads a listing; interleaving two stores in one process
// would make both of them racy for no benefit.
const chains = new WeakMap();
function serialized(vault, fn) {
  const prev = chains.get(vault) ?? Promise.resolve();
  const run = prev.then(fn);
  chains.set(vault, run.catch(() => {}));
  return run;
}

/** Validate a content path; returns the key. Throws a Fault. */
function checkPath(path) {
  if (typeof path !== 'string' || path === '') throw bad('path is required');
  const key = pathToKey(path);
  try {
    validateKey(key);
  } catch (err) {
    throw bad(`not a valid path: ${err.code ?? err.message}`);
  }
  for (const seg of path.split('/')) {
    if (INVISIBLE.has(seg) || seg.endsWith('.tmp')) {
      throw bad(`"${seg}" is a name the filesystem transport skips when listing`);
    }
    if (new TextEncoder().encode(seg).length > MAX_SEGMENT_BYTES) {
      throw bad(`a path segment is longer than ${MAX_SEGMENT_BYTES} bytes`);
    }
  }
  if (WITHHELD.some((p) => path === p || path.startsWith(p))) {
    // A content path under these names is never served (§12.4), so storing
    // there would create something nobody could read back.
    throw bad('that path is under a tree no surface serves (§12.4)');
  }
  return key;
}

function checkLabel(name, value) {
  if (value === undefined || value === null || value === '') return undefined;
  if (typeof value !== 'string') throw bad(`${name} must be a string`);
  if (value.length > MAX_LABEL) throw bad(`${name} is longer than ${MAX_LABEL} characters`);
  return value.trim() || undefined;
}

/**
 * §12.3's rule, for a write: a principal that cannot discover the folder is
 * told "not found", one that can is told "forbidden". The wrong answer here
 * confirms that a folder exists to someone who may not know it does.
 */
function authorize(vault, principal, folder, rights, what) {
  if (vault.can(principal, folder, rights).allowed) return;
  const discoverable = vault.can(principal, folder, ['list']).allowed;
  throw discoverable ? new Fault('forbidden', what) : new Fault('not_found');
}

/**
 * Read-modify-write one folder's entry sidecar (§6.1).
 *
 * Conditional on the etag read, because this file is shared by every asset in
 * the folder and last-write-wins on it silently un-binds somebody else's
 * object (§11.3). Comments and key order in a hand-edited file survive:
 * §3 makes this file YAML precisely because a human may have touched it.
 */
async function addSidecarEntry(vault, folder, name, entry) {
  const key = `${META}folders/${folder}entries.yaml`;
  for (let attempt = 0; attempt < 4; attempt++) {
    // stat, then get: if the file moves in between, the etag is older than the
    // bytes and the conditional put below fails rather than losing the update.
    const stat = await vault.t.stat(key);
    const bytes = stat ? await vault.t.get(key) : null;

    let doc;
    if (bytes === null) {
      doc = new YAML.Document({ entries: {} });
    } else {
      doc = YAML.parseDocument(Buffer.from(bytes).toString('utf8'));
      if (doc.errors.length || (doc.contents !== null && !YAML.isMap(doc.contents))) {
        throw new Fault('internal',
          `${key} is not a valid entries file; fix or remove it before storing here`);
      }
      if (doc.contents === null) doc = new YAML.Document({ entries: {} });
    }
    const entries = doc.get('entries');
    if (!YAML.isMap(entries)) doc.set('entries', doc.createNode({}));
    // A hand-written `entries: {}` is a flow map, and everything added to a
    // flow map prints as one unbroken line. Nothing is lost by opening an
    // empty one up; a map that already has entries keeps the author's style.
    else if (entries.items.length === 0) entries.flow = false;
    // An entry already named here belongs to an object that is gone (the
    // caller checked), and §6.1 says such entries are pruned. Replace it
    // rather than inherit a stale id.
    doc.setIn(['entries', name], doc.createNode(entry));

    try {
      await vault.t.put(key, Buffer.from(String(doc), 'utf8'), {
        ifMatch: stat?.etag ?? null, contentType: 'text/yaml',
      });
    } catch (err) {
      if (err?.code === 'PRECONDITION_FAILED') continue;
      throw err;
    }
    vault.sidecars[folder] = doc.toJS();
    return;
  }
  throw conflict(`${key} kept changing underneath this store; try again`);
}

/**
 * Store one new object.
 *
 * @param {import('./vault.mjs').Vault} vault a loaded vault
 * @param {object} args
 * @param {string|null} [args.principal] who is storing. `null` is the operator
 *   at the command line, who holds the vault's credentials and so is not
 *   subject to §8; anything else is evaluated like any other request.
 * @param {string} args.path vault path, e.g. "Assets/photo.png"
 * @param {Buffer|Uint8Array} args.bytes the content. For a note or a data
 *   file this must be valid UTF-8.
 * @param {string} [args.title] a note's frontmatter title, or an asset's
 *   sidecar title
 * @param {string} [args.alt] an asset's alt text (sidecar only)
 * @param {{agent?: string, account?: string, client?: {name?: string, version?: string}}} [args.provenance]
 *   who is behind `principal`. When given (even empty), the new object is
 *   stamped `created_by` with this, the principal and the time. Left out, no
 *   stamp is written; a note's own supplied `created_by` is then left alone.
 * @param {boolean} [args.reindex] rebuild and persist the indexes afterwards.
 *   Pass false to store several objects and refresh once at the end.
 * @param {number} [args.maxBytes]
 * @returns {Promise<{path, id, kind, media_type, size, content_hash, created}>}
 */
export function storeObject(vault, {
  principal = null, path, bytes, title, alt, provenance, reindex = true, maxBytes = MAX_STORE_BYTES,
}) {
  return serialized(vault, async () => {
    // Reload principals, ACLs and sidecars from the store on every write. A
    // long-lived process (an MCP server) loaded them once at startup; honoring
    // a grant the owner has since revoked, or rebuilding the indexes over
    // sidecars another process has since changed, would both be wrong.
    await vault.load();
    const key = checkPath(path);
    const kind = kindFor(path);
    const folder = parentFolder(path);
    const name = basename(path);
    title = checkLabel('title', title);
    alt = checkLabel('alt', alt);
    // Before anything is written: a bad label refuses the store, it does not
    // leave an object behind with no record of who made it.
    const createdBy = provenance ? buildCreatedBy({ principal, ...provenance }) : undefined;

    if (!(bytes instanceof Uint8Array)) throw bad('content is required');
    if (bytes.length > maxBytes) {
      throw new StoreFault('too_large', 413,
        `${bytes.length} bytes is over the ${maxBytes} byte limit`);
    }
    let content = Buffer.from(bytes);

    // Only notes may sit at the root: everything else takes its identity from
    // a sidecar at meta/folders/<folder>/entries.yaml, and the reader finds
    // those by the slash that precedes the filename — a root-level sidecar
    // would be written and never found, leaving the object unbound forever.
    if (kind !== 'note' && folder === '') {
      throw bad('files other than notes must live in a folder, e.g. "Assets/"');
    }

    // Text kinds are decoded strictly: bytes that are not UTF-8 would be
    // indexed as replacement characters and corrupt silently.
    let text = null;
    if (kind === 'note' || kind === 'data') {
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(content);
      } catch {
        throw bad(`${name} must be valid UTF-8 text; store binary data under another extension`);
      }
    }

    // --- authorization (§8) -------------------------------------------------
    if (principal !== null) {
      authorize(vault, principal, folder, ['create_child'], 'create_child is required');
      if (kind === 'note' && parseNote(text, path).acl !== null) {
        authorize(vault, principal, folder, ['write_acl'],
          'frontmatter sets basalt.acl, which needs write_acl');
      }
    }

    // --- collisions (§2.2) --------------------------------------------------
    const { keys: listed } = await vault.t.list(CONTENT);
    const existing = listed.filter((k) => k.startsWith(CONTENT));
    if (existing.includes(key)) throw conflict(`${path} already exists; stores never overwrite`);
    const clash = findCollisions([...existing, key]).find((g) => g.includes(key));
    if (clash) {
      const other = clash.find((k) => k !== key);
      throw conflict(`${path} collides with ${other.slice(CONTENT.length)} ` +
        `once case and Unicode normalization are folded (§2.2)`);
    }
    const segments = key.split('/');
    for (let i = 2; i < segments.length; i++) {
      const prefix = segments.slice(0, i).join('/');
      if (existing.includes(prefix)) {
        throw conflict(`${prefix.slice(CONTENT.length)} is a file, so it cannot also be a folder`);
      }
    }
    if (existing.some((k) => k.startsWith(key + '/'))) {
      throw conflict(`${path} is a folder`);
    }
    if (JSON.stringify(findFolderCaseDivergence(existing))
        !== JSON.stringify(findFolderCaseDivergence([...existing, key]))) {
      throw conflict(`a folder in ${path} differs only in case from an existing one (§2.2)`);
    }

    // --- identity (§4.3) ----------------------------------------------------
    const id = ulid();
    if (kind === 'note') content = Buffer.from(withId(text, id, { title, createdBy }), 'utf8');

    // --- write --------------------------------------------------------------
    // Content first. A sidecar written first and then orphaned by a failed
    // content put would sit on a name that may belong to nobody, and would be
    // pruned later; content with no sidecar is merely unbound, and `basalt
    // mint` repairs it.
    await vault.t.put(key, content, { ifMatch: null, contentType: mediaFor(path) })
      .catch((err) => {
        if (err?.code === 'PRECONDITION_FAILED') {
          throw conflict(`${path} was created by someone else just now`);
        }
        throw err;
      });

    if (kind !== 'note') {
      try {
        await addSidecarEntry(vault, folder, name, {
          id, ...(title ? { title } : {}), ...(alt ? { alt } : {}),
          ...(createdBy ? { created_by: createdBy } : {}),
        });
      } catch (err) {
        if (err instanceof Fault) {
          const hint = `${path} was stored but is unbound; run \`basalt mint\``;
          err.detail = err.detail ? `${err.detail} (${hint})` : hint;
          err.message = `${err.code}: ${err.detail}`;
        }
        throw err;
      }
    }

    if (reindex) {
      try {
        await vault.reindex({ write: true });
      } catch (err) {
        throw new Fault('internal',
          `${path} was stored, but refreshing the indexes failed: ${err.message}. ` +
          `Run \`basalt index --write\`.`);
      }
    }

    return {
      path,
      id,
      kind,
      media_type: mediaFor(path),
      size: content.length,
      content_hash: 'sha256:' + createHash('sha256').update(content).digest('hex'),
      created: true,
      ...(createdBy ? { created_by: createdBy } : {}),
    };
  });
}
