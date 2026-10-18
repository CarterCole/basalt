// The surface core — one principal-scoped view of a vault, shared by every
// interop adapter (INTEROP §1).
//
// Every protocol this repo speaks (REST, GraphQL, MCP, Connect, WebDAV,
// feeds, RDF) is a translation layer over this object and nothing more. That
// is a security property, not tidiness: §8.4 evaluation, the §12.3 404/403
// split, the §12.4 withheld trees and the §12.5 subject-keyed cache are
// implemented once here, so a new adapter cannot forget one. An adapter that
// reaches past this class into the Vault is a bug.

import { createHash } from 'node:crypto';
import { canonicalJson } from '../canonical.mjs';
import { pathToKey, parentFolder, isFolder } from '../keys.mjs';
import { RIGHTS } from '../acl.mjs';

/**
 * §12.4 forbids ever serving these trees to a non-system principal: they are
 * the indexes, the ACLs and the principal list, and §8.8 explains why handing
 * them out leaks the private half of the vault.
 */
export const WITHHELD = ['meta/', 'index/', 'principals/', 'history/', 'basalt.yaml'];

export const MEDIA = {
  '.md': 'text/markdown; charset=utf-8',
  '.json': 'application/json', '.yaml': 'text/yaml', '.yml': 'text/yaml',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf', '.txt': 'text/plain; charset=utf-8',
  '.csv': 'text/csv; charset=utf-8', '.mp4': 'video/mp4', '.mp3': 'audio/mpeg',
};

export const mediaFor = (p) => MEDIA[(p.match(/\.[^.]+$/) ?? [''])[0].toLowerCase()]
  ?? 'application/octet-stream';

/**
 * One fault table for every surface (INTEROP §1.3).
 *
 * A denial has to mean the same thing in all of them, so each adapter looks
 * its idiom up here rather than inventing a mapping: HTTP status for REST and
 * WebDAV, a Connect/gRPC code, a JSON-RPC code for MCP, and a stable string
 * that GraphQL puts in `extensions.code`.
 */
export const FAULTS = {
  not_found:          { status: 404, connect: 'not_found',          rpc: -32004 },
  forbidden:          { status: 403, connect: 'permission_denied',  rpc: -32003 },
  unauthenticated:    { status: 401, connect: 'unauthenticated',    rpc: -32001 },
  bad_request:        { status: 400, connect: 'invalid_argument',   rpc: -32602 },
  method_not_allowed: { status: 405, connect: 'unimplemented',      rpc: -32601 },
  internal:           { status: 500, connect: 'internal',           rpc: -32603 },
};

const BY_STATUS = new Map(Object.entries(FAULTS).map(([code, f]) => [f.status, code]));

/** The fault code for a status returned by the Vault layer. */
export function faultFor(status) {
  return BY_STATUS.get(status) ?? 'internal';
}

/** A denial, carried unchanged across adapters. */
export class Fault extends Error {
  constructor(code, detail) {
    const f = FAULTS[code] ?? FAULTS.internal;
    super(detail ? `${code}: ${detail}` : code);
    this.name = 'Fault';
    this.code = code;
    this.detail = detail ?? null;
    this.status = f.status;
    this.connect = f.connect;
    this.rpc = f.rpc;
  }

  static fromStatus(status, detail) {
    return new Fault(faultFor(status), detail);
  }
}

export class Surface {
  /**
   * @param {import('../vault.mjs').Vault} vault
   * @param {object} [opts]
   * @param {'proxy'|'redirect'} [opts.delivery] §12.4 delivery mode for bytes
   * @param {number} [opts.presignTtl] seconds; §12.4 wants this under 300
   */
  constructor(vault, { delivery = 'proxy', presignTtl = 120 } = {}) {
    this.vault = vault;
    this.delivery = delivery;
    this.presignTtl = presignTtl;
    this.cache = new Map();
    this.state = 'fresh';
  }

  get vaultId() { return this.vault.manifest?.vault?.id ?? ''; }

  // ------------------------------------------------------- caching (§12.5)

  /** The principal's effective subject set (§8.4 step 1), sorted. */
  subjects(principalId) {
    return [principalId, ...[...this.vault.principals.groupsOf(principalId)].sort()];
  }

  /**
   * A cache key for index-derived data.
   *
   * It MUST include the subject set, or the cache serves one principal's
   * visibility to another. Every adapter shares this one cache, so the check
   * is made once for all of them — and the equivalence suite (§14.2) asks the
   * same question over every protocol in both orders to prove it.
   */
  cacheKey(route, principalId, arg = '') {
    const h = createHash('sha256').update(this.subjects(principalId).join(',')).digest('hex');
    return `${route}\u0000${h.slice(0, 16)}\u0000${arg}`;
  }

  #cached(route, principalId, arg, produce) {
    const key = this.cacheKey(route, principalId, arg);
    if (this.cache.has(key)) return this.cache.get(key);
    const value = produce();
    this.cache.set(key, value);
    return value;
  }

  /** Drop cached index-derived responses; call after a reindex. */
  invalidate() { this.cache.clear(); }

  // -------------------------------------------------------- the §12.4 guard

  /** True when a path is one of the trees no surface may ever serve. */
  withheld(path) {
    return WITHHELD.some((p) => path === p || path.startsWith(p));
  }

  /**
   * Reject a withheld path as 404, never 403: a 403 would confirm that
   * `principals/users.yaml` exists, which is half the answer.
   */
  #guard(path) {
    if (this.withheld(path)) throw new Fault('not_found');
  }

  // ------------------------------------------------------------ operations
  //
  // Each returns plain data or throws Fault. Adapters never see a status
  // code, so they cannot soften a 404 into a 403.

  /** The public subset of the manifest (§12.3). */
  manifest() {
    const man = this.vault.manifest;
    return {
      basalt: man.basalt,
      vault: { id: man.vault.id, title: man.vault.title ?? null },
      publish: {
        audience: man.publish?.audience ?? 'gated',
        home: man.publish?.home ?? null,
      },
      index_state: this.state,
    };
  }

  /** Who the request is, and what it carries (§8.4 step 1). */
  me(principalId) {
    const user = this.vault.principals.users.get(principalId) ?? null;
    return {
      principal: principalId,
      display_name: user?.display_name ?? null,
      subjects: this.subjects(principalId),
      anonymous: principalId === 'anonymous',
    };
  }

  /** Content plus metadata and edges, if `read` (§12.3). */
  async node(principalId, path) {
    this.#guard(path);
    const r = await this.vault.readNode(principalId, path);
    if (r.status !== 200) throw Fault.fromStatus(r.status);
    const edges = this.vault.links(principalId, path);
    return {
      node: r.node,
      text: r.text,
      bytes: r.bytes,
      media_type: mediaFor(path),
      links: edges.status === 200
        ? { out: edges.out, backlinks: edges.backlinks }
        : { out: [], backlinks: [] },
    };
  }

  /**
   * Bytes only. In `redirect` mode this returns a presigned location instead
   * of the body: a presigned URL is a bearer token that outlives the ACL
   * check that produced it, so the TTL stays short and §12.4 keeps it out of
   * any shared cache.
   */
  async raw(principalId, path) {
    this.#guard(path);
    const r = await this.vault.readNode(principalId, path);
    if (r.status !== 200) throw Fault.fromStatus(r.status);

    if (this.delivery === 'redirect' && this.vault.t.capabilities?.has('presign')) {
      const location = await this.vault.t.presign(pathToKey(path), {
        ttlSeconds: this.presignTtl,
      });
      return { redirect: location, node: r.node, media_type: mediaFor(path) };
    }
    return {
      bytes: r.bytes, node: r.node, media_type: mediaFor(path),
      etag: r.node?.etag ?? null,
    };
  }

  /** Direct entries of a folder, filtered to what the principal may see. */
  list(principalId, folder = '') {
    const f = folder === '' ? '' : (isFolder(folder) ? folder : folder + '/');
    this.#guard(f);
    return this.#cached('list', principalId, f, () => {
      const r = this.vault.listFolder(principalId, f);
      if (r.status !== 200) throw Fault.fromStatus(r.status);
      return { folder: f, entries: r.entries, folders: r.folders };
    });
  }

  /** Out-edges and backlinks, redacted in place per §9.5. */
  links(principalId, path) {
    this.#guard(path);
    const r = this.vault.links(principalId, path);
    if (r.status !== 200) throw Fault.fromStatus(r.status);
    return { path, out: r.out, backlinks: r.backlinks };
  }

  /** Postings filtered to readable nodes, not merely re-ranked (§12.5). */
  search(principalId, query, { limit = 20, offset = 0 } = {}) {
    if (typeof query !== 'string' || query.trim() === '') {
      throw new Fault('bad_request', 'empty query');
    }
    const all = this.#cached('search', principalId, query, () => {
      const r = this.vault.search(principalId, query);
      if (r.status !== 200) throw Fault.fromStatus(r.status);
      return r.hits;
    });
    const n = clampInt(limit, 1, 200, 20);
    const from = clampInt(offset, 0, 1e6, 0);
    return { query, total: all.length, offset: from, hits: all.slice(from, from + n) };
  }

  /** The navigable tree, pruned to what is visible (§12.3). */
  tree(principalId) {
    return this.#cached('tree', principalId, '', () => {
      const r = this.vault.tree(principalId);
      if (r.status !== 200) throw Fault.fromStatus(r.status);
      return r.tree;
    });
  }

  /** Tag postings, filtered to readable nodes. */
  tags(principalId) {
    return this.#cached('tags', principalId, '', () => {
      const byId = this.#byId();
      const out = [];
      for (const [tag, ids] of Object.entries(this.vault.indexes?.tags?.entries ?? {})) {
        const nodes = ids
          .map((id) => byId.get(id))
          .filter((n) => n && this.vault.can(principalId, n.path, ['read']).allowed)
          .map((n) => ({ id: n.id, path: n.path, title: n.title }));
        if (nodes.length) out.push({ tag, nodes });
      }
      return out;
    });
  }

  /**
   * Effective rights (§8.7). Seeing anyone's rights — including your own, on
   * an object whose ACL you may not read — requires `read_acl` on the object.
   */
  effective(principalId, { path = '', principal } = {}) {
    this.#guard(path);
    const who = principal ?? principalId;
    if (!this.vault.can(principalId, path, ['read_acl']).allowed) {
      throw new Fault('forbidden');
    }
    const e = this.vault.effective(who, path);
    return {
      principal: who,
      path,
      granted: e.granted,
      decisions: Object.fromEntries(RIGHTS.map((r) => [r, e.decisions[r]])),
      failed_at: e.failedAt ?? null,
    };
  }

  /** Index freshness (§10.6), as the header value every surface reports. */
  indexState() { return this.state; }

  #byId() {
    return new Map((this.vault.indexes?.nodes?.entries ?? []).map((e) => [e.id, e]));
  }

  /**
   * Every readable node entry, in §13.3 order.
   *
   * This is the feed/catalogue view — WebDAV, Atom, sitemaps, RDF and MCP
   * resource listings all want it, and none of them should reimplement the
   * filter.
   */
  nodes(principalId, { publishedOnly = false } = {}) {
    return this.#cached('nodes', principalId, publishedOnly ? 'pub' : 'all', () => {
      const out = [];
      for (const e of this.vault.indexes?.nodes?.entries ?? []) {
        if (this.withheld(e.path)) continue;
        if (publishedOnly && e.publish === false) continue;
        if (!this.vault.can(principalId, e.path, ['read']).allowed) continue;
        out.push(e);
      }
      return out;
    });
  }

  /** Readable folders, for surfaces that need collections (WebDAV, trees). */
  folders(principalId) {
    return this.#cached('folders', principalId, '', () => {
      const seen = new Set(['']);
      for (const e of this.nodes(principalId)) {
        let f = parentFolder(e.path);
        while (f !== '' && !seen.has(f)) {
          seen.add(f);
          f = parentFolder(f.replace(/\/$/, ''));
        }
      }
      return [...seen].filter((f) => this.vault.can(principalId, f, ['list']).allowed).sort();
    });
  }

  /**
   * Readable entries with store metadata, newest first.
   *
   * Feeds need a timestamp and the indexes deliberately carry none — §10
   * derives everything from content, and §1 forbids relying on store clocks
   * for correctness. A feed is presentation, not correctness, so mtime is
   * honest enough here and absent when the store will not say.
   */
  async recent(principalId, { limit = 20, publishedOnly = true } = {}) {
    const entries = this.nodes(principalId, { publishedOnly });
    const stats = await Promise.all(entries.map(async (e) => {
      const s = await this.vault.t.stat(pathToKey(e.path)).catch(() => null);
      return { ...e, mtime: s?.mtime ?? null, size: s?.size ?? e.size ?? 0 };
    }));
    stats.sort((a, b) => (b.mtime ?? '').localeCompare(a.mtime ?? '')
      || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
    return stats.slice(0, clampInt(limit, 1, 500, 20));
  }

  /** A single entry plus store metadata, ACL-checked. */
  async stat(principalId, path) {
    this.#guard(path);
    const entry = (this.vault.indexes?.nodes?.entries ?? []).find((e) => e.path === path);
    if (!entry) throw new Fault('not_found');
    if (!this.vault.can(principalId, path, ['read']).allowed) {
      const discoverable = this.vault.can(principalId, parentFolder(path), ['list']).allowed;
      throw new Fault(discoverable ? 'forbidden' : 'not_found');
    }
    const s = await this.vault.t.stat(pathToKey(path)).catch(() => null);
    return { ...entry, mtime: s?.mtime ?? null, size: s?.size ?? entry.size ?? 0 };
  }

  /** A weak ETag over a serialized body, for conditional requests. */
  etag(value) {
    const bytes = Buffer.isBuffer(value) ? value
      : Buffer.from(typeof value === 'string' ? value : canonicalJson(value), 'utf8');
    return `W/"${createHash('sha256').update(bytes).digest('hex').slice(0, 32)}"`;
  }
}

function clampInt(v, lo, hi, fallback) {
  const n = typeof v === 'number' ? v : parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(hi, Math.max(lo, Math.trunc(n)));
}
