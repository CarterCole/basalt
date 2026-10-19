// The Vault facade, PROTOCOL §3 — loading, scanning, indexing, reading.

import YAML from 'yaml';
import { createHash } from 'node:crypto';
import {
  CONTENT, META, INDEX, PRINCIPALS, MANIFEST,
  keyToPath, pathToKey, parentFolder, basename, isFolder,
  impliedFolders, sortUtf8, isValidKey,
} from './keys.mjs';
import { canonicalBytes, canonicalJson } from './canonical.mjs';
import { Principals } from './acl.mjs';
import { DescriptorStore, checkAccess, effectiveRights } from './security.mjs';
import { buildIndexes, buildSearchIndex, computeDigest } from './indexer.mjs';
import { parseNote, kindFor } from './frontmatter.mjs';
import { withId } from './frontmatter.mjs';

const INDEX_KEYS = {
  nodes: `${INDEX}nodes.json`,
  links: `${INDEX}links.json`,
  backlinks: `${INDEX}backlinks.json`,
  tags: `${INDEX}tags.json`,
  search: `${INDEX}search.json`,
  digest: `${INDEX}digest.json`,
  integrity: `${INDEX}integrity.json`,
};

export class Vault {
  constructor(transport) {
    this.t = transport;
    this.manifest = null;
    this.principals = null;
    this.descriptors = null;
    this.indexes = null;
    this.loaded = false;
  }

  // ------------------------------------------------------------- loading

  async #text(key) {
    const b = await this.t.get(key);
    return b === null ? null : Buffer.from(b).toString('utf8');
  }

  async #yaml(key, fallback = null) {
    const t = await this.#text(key);
    if (t === null) return fallback;
    try { return YAML.parse(t) ?? fallback; } catch { return fallback; }
  }

  /** Load the manifest, principals, folder records and ACLs. */
  async load() {
    const manifest = await this.#yaml(MANIFEST);
    if (!manifest) throw new Error(`not a Basalt vault: ${MANIFEST} is missing`);
    if (manifest.basalt !== 1) {
      // §3.1: refuse a major version this reader does not implement.
      throw new Error(`unsupported spec version: basalt=${manifest.basalt}`);
    }
    this.manifest = manifest;

    const [users, groups, roles] = await Promise.all([
      this.#yaml(`${PRINCIPALS}users.yaml`, { users: [] }),
      this.#yaml(`${PRINCIPALS}groups.yaml`, { groups: [] }),
      this.#yaml(`${PRINCIPALS}roles.yaml`, { roles: {} }),
    ]);
    this.principals = new Principals({
      users: users.users ?? [],
      groups: groups.groups ?? [],
      roles: roles.roles ?? {},
    });

    await this.#loadMeta();
    this.loaded = true;
    return this;
  }

  async #loadMeta() {
    const { keys } = await this.t.list(META);
    const folderAcls = new Map();
    this.folderRecords = {};
    this.sidecars = {};

    for (const key of keys) {
      if (key.startsWith(`${META}acl/`) && key.endsWith('/acl.yaml')) {
        const folder = key.slice(`${META}acl/`.length, -'acl.yaml'.length);
        folderAcls.set(folder, await this.#yaml(key, {}));
      } else if (key.startsWith(`${META}folders/`)) {
        const rest = key.slice(`${META}folders/`.length);
        if (rest.endsWith('/folder.yaml')) {
          const folder = rest.slice(0, -'folder.yaml'.length);
          this.folderRecords[folder] = await this.#yaml(key, {});
        } else if (rest.endsWith('/entries.yaml')) {
          const folder = rest.slice(0, -'entries.yaml'.length);
          this.sidecars[folder] = await this.#yaml(key, { entries: {} });
        }
      }
    }
    // The root folder's ACL may live at meta/acl/acl.yaml.
    if (!folderAcls.has('')) {
      const root = await this.#yaml(`${META}acl/acl.yaml`, null);
      if (root) folderAcls.set('', root);
    }
    this.folderAcls = folderAcls;
    this.descriptors = new DescriptorStore({ folderAcls, inlineAcls: new Map() });
  }

  // ------------------------------------------------------------- scanning

  /** Read every content object. Returns [{key, path, bytes, stat}]. */
  async scan() {
    const { keys } = await this.t.list(CONTENT);
    const content = keys.filter((k) => k.startsWith(CONTENT) && isValidKey(k));
    const out = [];
    for (const key of sortUtf8(content)) {
      const [bytes, stat] = await Promise.all([this.t.get(key), this.t.stat(key)]);
      if (bytes === null) continue;  // raced with a delete
      out.push({ key, path: keyToPath(key), bytes: Buffer.from(bytes), stat });
    }
    return out;
  }

  /**
   * Rebuild every index from content alone (§0). Returns the index objects;
   * pass {write: true} to persist them.
   */
  async reindex({ write = false, force = false } = {}) {
    if (!this.loaded) await this.load();
    const scanned = await this.scan();

    const built = buildIndexes({
      scanned,
      vaultId: this.manifest.vault.id,
      sidecars: this.sidecars,
      folderRecords: this.folderRecords,
    });

    // Inline frontmatter ACLs replace a node's entry in the folder file (§8.6).
    const inlineAcls = new Map();
    for (const n of built._nodes) if (n.acl) inlineAcls.set(n.path, n.acl);
    this.descriptors = new DescriptorStore({ folderAcls: this.folderAcls, inlineAcls });

    // §8.8: search text comes only from nodes readable by `everyone`.
    const search = buildSearchIndex({
      nodes: built._nodes,
      vaultId: this.manifest.vault.id,
      sourceDigest: built.digest.root,
      isPublic: (n) => this.#readableByEveryone(n.path),
    });

    this.indexes = { ...built, search };

    if (write) {
      // §10.7: refuse to replace a non-empty stored index with an empty one.
      // This cannot lose content — indexes are derived — but a vault whose
      // indexes went empty looks empty to every reader, and the usual cause
      // is a transport pointed at the wrong bucket, prefix or addressing
      // style rather than an emptied vault (§3.1).
      if (!force && built._nodes.length === 0) {
        const prior = await this.#text(INDEX_KEYS.nodes);
        let priorCount = 0;
        if (prior !== null) {
          try { priorCount = JSON.parse(prior).entries?.length ?? 0; } catch { /* corrupt */ }
        }
        if (priorCount > 0) {
          const err = new Error(
            `refusing to write an empty index: 0 nodes found, ${priorCount} ` +
            `previously indexed. Check the transport is pointed at the right ` +
            `bucket and prefix, then pass force to override.`);
          err.code = 'EMPTY_INDEX_REFUSED';
          throw err;
        }
      }
      for (const [name, key] of Object.entries(INDEX_KEYS)) {
        const obj = this.indexes[name];
        if (obj) await this.t.put(key, canonicalBytes(obj), { contentType: 'application/json' });
      }
    }
    return this.indexes;
  }

  #readableByEveryone(path) {
    const r = checkAccess({
      store: this.descriptors, principals: this.principals,
      principalId: 'anonymous', path, rights: ['read'],
      audience: 'public',
      bypassTraverse: this.manifest?.security?.bypass_traverse ?? false,
      denyUnresolved: this.manifest?.security?.deny_unresolved ?? true,
    });
    return r.allowed;
  }

  /** Load indexes from the store without rebuilding. */
  async loadIndexes() {
    const out = {};
    for (const [name, key] of Object.entries(INDEX_KEYS)) {
      const t = await this.#text(key);
      if (t !== null) { try { out[name] = JSON.parse(t); } catch { /* corrupt */ } }
    }
    this.indexes = Object.keys(out).length ? out : null;
    return this.indexes;
  }

  /**
   * Index freshness (§10.6): one `get` of the current digest, compared with
   * the stored index's source_digest. Never timestamps, which §1 forbids
   * relying on.
   */
  async indexState() {
    const scanned = await this.scan();
    const current = computeDigest(scanned.map((s) => ({
      path: s.path,
      contentHash: 'sha256:' + createHash('sha256').update(s.bytes).digest('hex'),
    })));
    const stored = this.indexes?.nodes?.source_digest ?? null;
    return {
      current: current.root,
      stored,
      fresh: stored !== null && stored === current.root,
    };
  }

  // ------------------------------------------------------------- reading

  #opts() {
    return {
      audience: this.manifest?.publish?.audience ?? 'gated',
      bypassTraverse: this.manifest?.security?.bypass_traverse ?? false,
      denyUnresolved: this.manifest?.security?.deny_unresolved ?? true,
    };
  }

  /** Check access for a principal on a path (§8). */
  can(principalId, path, rights) {
    return checkAccess({
      store: this.descriptors, principals: this.principals,
      principalId, path, rights, ...this.#opts(),
    });
  }

  /** Effective rights with the deciding ACE per right (§8.7). */
  effective(principalId, path) {
    return effectiveRights({
      store: this.descriptors, principals: this.principals,
      principalId, path, ...this.#opts(),
    });
  }

  #node(path) {
    return this.indexes?.nodes?.entries?.find((e) => e.path === path) ?? null;
  }

  /**
   * Read a node for a principal.
   *
   * §12.3: the 404/403 split is an information-leak boundary. A 403 on a path
   * the requester was not allowed to discover confirms that path exists, so
   * "cannot know it exists" must be indistinguishable from "does not exist".
   */
  async readNode(principalId, path) {
    const node = this.#node(path);
    const decision = this.can(principalId, path, ['read']);

    if (!node) return { status: 404 };
    if (!decision.allowed) {
      const discoverable = this.can(principalId, parentFolder(path), ['list']).allowed;
      return { status: discoverable ? 403 : 404, decisions: decision.decisions };
    }
    const bytes = await this.t.get(pathToKey(path));
    if (bytes === null) return { status: 404 };
    return {
      status: 200,
      node,
      bytes: Buffer.from(bytes),
      text: node.kind === 'note' || node.kind === 'data'
        ? Buffer.from(bytes).toString('utf8') : null,
    };
  }

  /** Direct entries of a folder, filtered to those the principal may see. */
  listFolder(principalId, folder) {
    if (!this.can(principalId, folder, ['list']).allowed) {
      const parentVisible = folder === ''
        ? false
        : this.can(principalId, parentFolder(folder.replace(/\/$/, '')), ['list']).allowed;
      return { status: parentVisible ? 403 : 404 };
    }
    const entries = [];
    for (const e of this.indexes?.nodes?.entries ?? []) {
      if (parentFolder(e.path) !== folder) continue;
      if (!this.can(principalId, e.path, ['read']).allowed) continue;
      entries.push({ path: e.path, kind: e.kind, title: e.title, id: e.id });
    }
    const subfolders = [];
    for (const f of impliedFolders((this.indexes?.nodes?.entries ?? []).map((e) => e.path))) {
      if (parentFolder(f.replace(/\/$/, '')) !== folder) continue;
      if (!this.can(principalId, f, ['list']).allowed) continue;
      subfolders.push(f);
    }
    return {
      status: 200,
      entries: sortUtf8(entries, (e) => e.path),
      folders: sortUtf8(subfolders),
    };
  }

  /**
   * Out-edges and backlinks for a node, redacted per §9.5.
   *
   * A redacted edge is returned with target `redacted` rather than removed:
   * dropping it would make the graph silently wrong, and a reader could not
   * tell a redacted link from a dangling one.
   */
  links(principalId, path) {
    const node = this.#node(path);
    if (!node) return { status: 404 };
    if (!this.can(principalId, path, ['read']).allowed) return { status: 403 };

    const redactTitles = this.manifest?.security?.redact_titles !== false;
    const byId = new Map((this.indexes?.nodes?.entries ?? []).map((e) => [e.id, e]));
    const visible = (id) => {
      const t = byId.get(id);
      return t ? this.can(principalId, t.path, ['read']).allowed : false;
    };
    const shape = (e, otherId) => {
      const other = otherId ? byId.get(otherId) : null;
      // An external or dangling edge has no target, and says so with an
      // explicit null: a client should not have to tell a missing key from a
      // null one to know whether an edge resolved (INTEROP §1.2).
      if (!other) return { ...e, to: e.to, target: null };
      if (visible(otherId)) {
        return { ...e, target: { id: other.id, path: other.path, title: other.title } };
      }
      return {
        ...e,
        to: 'redacted',
        target: { id: 'redacted', path: null, title: redactTitles ? null : other.title },
      };
    };

    const out = (this.indexes?.links?.entries ?? [])
      .filter((e) => e.from === node.id)
      .map((e) => shape(e, e.to));

    // Every backlink is returned; invisible sources are redacted in place
    // rather than dropped (§9.5), so the graph stays honest.
    const back = (this.indexes?.backlinks?.entries?.[node.id] ?? [])
      .map((srcId) => {
        const src = byId.get(srcId);
        if (!src) return null;
        if (visible(srcId)) return { id: src.id, path: src.path, title: src.title };
        return { id: 'redacted', path: null, title: redactTitles ? null : src.title };
      })
      .filter(Boolean);

    return { status: 200, out, backlinks: back };
  }

  /** Search, filtered to readable nodes (§12.5). */
  search(principalId, query) {
    const terms = this.indexes?.search?.terms ?? {};
    const byId = new Map((this.indexes?.nodes?.entries ?? []).map((e) => [e.id, e]));
    const scores = new Map();
    for (const raw of query.toLowerCase().matchAll(/[\p{L}\p{N}_]+/gu)) {
      for (const p of terms[raw[0]] ?? []) {
        const n = byId.get(p.node);
        if (!n) continue;
        if (!this.can(principalId, n.path, ['read']).allowed) continue;
        scores.set(p.node, (scores.get(p.node) ?? 0) + p.tf);
      }
    }
    const hits = [...scores.entries()]
      .map(([id, score]) => ({ score, ...byId.get(id) }))
      .sort((a, b) => b.score - a.score || (a.path < b.path ? -1 : 1));
    return { status: 200, hits };
  }

  /** The navigable tree, pruned to what the principal may see (§12.3). */
  tree(principalId) {
    const build = (folder) => {
      const l = this.listFolder(principalId, folder);
      if (l.status !== 200) return null;
      return {
        folder,
        title: this.folderRecords[folder]?.title
          ?? (basename(folder.replace(/\/$/, '')) || this.manifest.vault.title),
        entries: l.entries,
        folders: l.folders.map(build).filter(Boolean),
      };
    };
    return { status: 200, tree: build('') };
  }

  // ------------------------------------------------------------- writing

  /**
   * Mint ids for unbound objects and persist them (§4.3) — frontmatter for
   * notes, the folder sidecar otherwise.
   */
  async mintIds() {
    const minted = [];
    const scanned = await this.scan();
    for (const { key, path, bytes } of scanned) {
      const kind = kindFor(path);
      if (kind === 'note') {
        const text = Buffer.from(bytes).toString('utf8');
        if (parseNote(text, path).id) continue;
        const id = ulid();
        await this.t.put(key, Buffer.from(withId(text, id), 'utf8'));
        minted.push({ path, id, where: 'frontmatter' });
      } else {
        const folder = parentFolder(path);
        const name = basename(path);
        const sc = this.sidecars[folder] ?? { entries: {} };
        if (sc.entries?.[name]?.id) continue;
        const id = ulid();
        sc.entries = { ...(sc.entries ?? {}), [name]: { ...(sc.entries?.[name] ?? {}), id } };
        this.sidecars[folder] = sc;
        await this.t.put(
          `${META}folders/${folder}entries.yaml`,
          Buffer.from(YAML.stringify(sc), 'utf8'));
        minted.push({ path, id, where: 'sidecar' });
      }
    }
    return minted;
  }
}

/** ULID (§4.1): 48-bit timestamp + 80 bits of randomness, Crockford base32. */
const B32 = '0123456789abcdefghjkmnpqrstvwxyz';
export function ulid(now = Date.now()) {
  let out = '';
  let t = now;
  for (let i = 9; i >= 0; i--) {
    out = B32[t % 32] + out;
    t = Math.floor(t / 32);
  }
  out = out.slice(-10);
  const rand = new Uint8Array(16);
  crypto.getRandomValues(rand);
  for (let i = 0; i < 16; i++) out += B32[rand[i] % 32];
  return out.slice(0, 26);
}

export { INDEX_KEYS };
