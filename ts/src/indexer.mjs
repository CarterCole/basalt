// Index generation, PROTOCOL §10.
//
// Everything here is derived: delete every index and these functions rebuild
// all of them from content alone, byte for byte (§0). That property is what
// makes the conformance suite checkable, so the only inputs allowed are
// content bytes and keys — never listing order, never mtimes.

import { createHash } from 'node:crypto';
import YAML from 'yaml';
import {
  CONTENT, keyToPath, pathToKey, basename, stem, parentFolder,
  impliedFolders, findCollisions, findFolderCaseDivergence,
  sortUtf8, compareUtf8, nfc, foldCase,
} from './keys.mjs';
import { parseNote, kindFor, isUlid } from './frontmatter.mjs';
import {
  extractLinks, extractHeadings, extractBlockIds, buildResolver,
  resolveTarget, anchorResolves, tagClosure,
} from './links.mjs';

export const SPEC = 1;

function sha256(...parts) {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
}

const hex = (buf) => 'sha256:' + buf.toString('hex');

/**
 * The merkle root over content/ (§10.6).
 *
 * Leaf hashes are sorted, not paths, so the root is independent of traversal
 * order — a store whose `list` is unordered (§1) cannot change the result.
 */
export function computeDigest(entries) {
  const leaves = entries.map(({ path, contentHash }) =>
    sha256(Buffer.from(nfc(path), 'utf8'), Buffer.from([0]),
           Buffer.from(contentHash.replace(/^sha256:/, ''), 'hex')));
  leaves.sort(Buffer.compare);
  const root = leaves.length ? sha256(Buffer.concat(leaves)) : sha256(Buffer.alloc(0));

  // Per-folder subtree hashes let an incremental pass skip untouched folders.
  const byFolder = new Map();
  for (const e of entries) {
    for (const f of foldersOf(e.path)) {
      if (!byFolder.has(f)) byFolder.set(f, []);
      byFolder.get(f).push(sha256(
        Buffer.from(nfc(e.path), 'utf8'), Buffer.from([0]),
        Buffer.from(e.contentHash.replace(/^sha256:/, ''), 'hex')));
    }
  }
  const tree = {};
  for (const [folder, hashes] of byFolder) {
    hashes.sort(Buffer.compare);
    tree[folder] = hex(sha256(Buffer.concat(hashes)));
  }
  for (const e of entries) tree[e.path] = e.contentHash;

  return { root: hex(root), count: entries.length, tree };
}

function foldersOf(path) {
  const out = [];
  const segs = path.split('/');
  segs.pop();
  let acc = '';
  for (const s of segs) { acc += s + '/'; out.push(acc); }
  return out;
}

function envelope(kind, vaultId, sourceDigest, extra) {
  return {
    basalt: SPEC,
    kind,
    vault: vaultId,
    generated: new Date().toISOString(),
    source_digest: sourceDigest,
    ...extra,
  };
}

/**
 * Build every index from a scan of content.
 *
 * `scanned` is an array of {key, path, bytes, stat}. Returns the index
 * objects plus the integrity report, ready to be canonically serialized.
 */
export function buildIndexes({ scanned, vaultId, sidecars = {}, folderRecords = {} }) {
  const integrity = [];

  // ---- pass 1: parse every object, collect identities -------------------
  const nodes = [];
  for (const item of sortUtf8(scanned, (s) => s.path)) {
    const { path, bytes, stat } = item;
    const kind = kindFor(path);
    const contentHash = hex(sha256(bytes));
    const folder = parentFolder(path);
    const sidecar = sidecars[folder]?.entries?.[basename(path)] ?? null;

    const node = {
      path, kind, contentHash,
      size: stat?.size ?? bytes.length,
      etag: stat?.etag ?? null,
      id: null, title: null, tags: [], aliases: [], publish: true,
      headings: [], blockIds: [], acl: null, errors: [],
      text: null,
    };

    if (kind === 'note') {
      const text = Buffer.from(bytes).toString('utf8');
      const parsed = parseNote(text, path);
      node.id = parsed.id;
      node.title = parsed.title;
      node.tags = parsed.tags;
      node.aliases = parsed.aliases;
      node.publish = parsed.publish;
      node.acl = parsed.acl;
      node.headings = extractHeadings(parsed.body);
      node.blockIds = extractBlockIds(parsed.body);
      node.text = text;
      node.body = parsed.body;
      node.bodyStartLine = parsed.bodyStartLine;
      node.errors = parsed.errors;
    } else {
      // §4.2: objects that cannot carry frontmatter get their id from the
      // folder's entry sidecar.
      if (sidecar?.id && isUlid(String(sidecar.id))) node.id = String(sidecar.id).toLowerCase();
      node.title = sidecar?.title ?? stem(basename(path));
      if (kind === 'data') node.text = Buffer.from(bytes).toString('utf8');
    }

    for (const e of node.errors) {
      integrity.push({ severity: e.severity, code: e.code, path, detail: e.detail });
    }
    nodes.push(node);
  }

  // ---- integrity: key collisions and duplicate ids ----------------------
  for (const group of findCollisions(scanned.map((s) => s.key))) {
    integrity.push({
      severity: 'error', code: 'KEY_COLLISION',
      path: keyToPath(group[0]) ?? group[0],
      detail: `collides with ${group.slice(1).join(', ')}`,
    });
  }

  for (const group of findFolderCaseDivergence(scanned.map((s) => s.key))) {
    integrity.push({
      severity: 'warning', code: 'FOLDER_CASE_DIVERGENCE',
      path: keyToPath(group[0]) ?? group[0],
      detail: `also spelled ${group.slice(1).join(', ')}`,
    });
  }

  // §4.3: the bytewise-first path keeps a duplicated id; the rest are
  // treated as unbound so a repair is deterministic across implementations.
  const byId = new Map();
  for (const n of nodes) {
    if (!n.id) continue;
    if (!byId.has(n.id)) { byId.set(n.id, n); continue; }
    const keeper = byId.get(n.id);
    const loser = compareUtf8(keeper.path, n.path) <= 0 ? n : keeper;
    if (loser === keeper) byId.set(n.id, n);
    integrity.push({
      severity: 'warning', code: 'DUPLICATE_ID',
      path: loser.path, detail: `id ${loser.id} also claimed by ${byId.get(n.id).path}`,
    });
    loser.id = null;
  }

  const unbound = nodes.filter((n) => !n.id);
  for (const n of unbound) {
    integrity.push({ severity: 'warning', code: 'UNBOUND_NODE', path: n.path });
  }

  // ---- folder nodes ------------------------------------------------------
  const folders = impliedFolders(nodes.map((n) => n.path));
  const folderNodes = folders.map((f) => ({
    path: f,
    kind: 'folder',
    id: folderRecords[f]?.basalt?.id ?? null,
    title: folderRecords[f]?.title ?? (basename(f.replace(/\/$/, '')) || null),
    publish: folderRecords[f]?.publish !== false,
  }));

  // §6.1: a sidecar entry whose object is gone is pruned on the next pass.
  const paths = new Set(nodes.map((n) => n.path));
  for (const [folder, sc] of Object.entries(sidecars)) {
    for (const name of Object.keys(sc?.entries ?? {})) {
      if (!paths.has(folder + name)) {
        integrity.push({
          severity: 'warning', code: 'ORPHAN_SIDECAR',
          path: folder + name, detail: 'sidecar entry has no object',
        });
      }
    }
  }

  // ---- pass 2: resolve links --------------------------------------------
  const resolvable = nodes.filter((n) => n.id);
  const resolver = buildResolver(resolvable);
  const byPath = new Map(nodes.map((n) => [n.path, n]));
  const edges = [];

  for (const n of nodes) {
    if (!n.id) continue;
    if (n.kind !== 'note' && n.kind !== 'data') continue;

    const found = n.kind === 'note'
      ? extractLinks(n.body ?? '')
      : { edges: extractDataLinks(n.text ?? '', n.path), tags: [] };

    // Merge frontmatter tags with inline tags, keeping the closure (§9.6).
    const tagSet = new Map();
    for (const t of [...n.tags, ...found.tags]) {
      for (const c of tagClosure(t)) {
        const f = foldCase(c);
        if (!tagSet.has(f)) tagSet.set(f, c);
      }
    }
    n.tags = [...tagSet.values()];

    for (const e of found.edges) {
      if (e.kind === 'external') {
        edges.push({
          from: n.id, to: null, kind: 'external', raw: e.raw,
          alias: e.alias, anchor: null, anchor_resolved: true,
          ambiguous: false, candidates: [],
          line: e.line + (n.kind === 'note' ? n.bodyStartLine - 1 : 0),
          col: e.col,
        });
        continue;
      }

      const r = resolveTarget(resolver, n.path, e.raw);
      const target = r.node ? byPath.get(r.node.path) : null;
      if (r.ambiguous) {
        integrity.push({
          severity: 'warning', code: 'AMBIGUOUS_LINK', path: n.path,
          detail: `"${e.raw}" matches ${r.candidates.length} nodes`,
        });
      }
      if (!r.node) {
        integrity.push({
          severity: 'warning', code: 'UNRESOLVED_LINK', path: n.path,
          detail: `"${e.raw}"`,
        });
      }

      edges.push({
        from: n.id,
        to: r.node?.id ?? null,
        kind: e.kind,
        raw: e.raw,
        alias: e.alias,
        anchor: e.anchor,
        anchor_resolved: target
          ? anchorResolves(e.anchor, target.headings, target.blockIds)
          : !e.anchor,
        ambiguous: r.ambiguous,
        candidates: r.candidates,
        line: e.line + (n.kind === 'note' ? n.bodyStartLine - 1 : 0),
        col: e.col,
      });
    }
  }

  // ---- assemble ---------------------------------------------------------
  const digest = computeDigest(
    nodes.map((n) => ({ path: n.path, contentHash: n.contentHash })));

  const nodesIndex = envelope('nodes', vaultId, digest.root, {
    entries: nodes.map((n) => ({
      id: n.id, path: n.path, kind: n.kind, title: n.title,
      size: n.size, etag: n.etag, content_hash: n.contentHash,
      tags: sortUtf8(n.tags), aliases: n.aliases,
      headings: n.headings, publish: n.publish,
      errors: n.errors.map((e) => e.code),
    })),
  });

  const linksIndex = envelope('links', vaultId, digest.root, { entries: edges });

  const backlinks = {};
  for (const e of edges) {
    if (!e.to) continue;
    (backlinks[e.to] ??= []).push(e.from);
  }
  for (const k of Object.keys(backlinks)) {
    backlinks[k] = sortUtf8([...new Set(backlinks[k])]);
  }
  const backlinksIndex = envelope('backlinks', vaultId, digest.root, { entries: backlinks });

  const tagMap = {};
  for (const n of nodes) {
    for (const t of n.tags) {
      if (!n.id) continue;
      (tagMap[t] ??= []).push(n.id);
    }
  }
  for (const k of Object.keys(tagMap)) tagMap[k] = sortUtf8([...new Set(tagMap[k])]);
  const tagsIndex = envelope('tags', vaultId, digest.root, { entries: tagMap });

  const digestIndex = envelope('digest', vaultId, digest.root, {
    root: digest.root, count: digest.count, tree: digest.tree,
  });

  const integrityIndex = envelope('integrity', vaultId, digest.root, {
    entries: sortUtf8(integrity, (i) => `${i.path ?? ''}\u0000${i.code}\u0000${i.detail ?? ''}`),
  });

  return {
    nodes: nodesIndex,
    links: linksIndex,
    backlinks: backlinksIndex,
    tags: tagsIndex,
    digest: digestIndex,
    integrity: integrityIndex,
    _nodes: nodes,
    _folders: folderNodes,
    _edges: edges,
  };
}

const LINK_KEYS = new Set(['link', 'links', 'ref', 'refs', 'href', 'url']);

/**
 * Links inside data objects (§9.4): string *values* only, never keys —
 * scanning keys would turn a dataset's column names into edges.
 */
export function extractDataLinks(text, path) {
  let doc;
  try {
    doc = path.endsWith('.json') ? JSON.parse(text) : null;
  } catch { return []; }
  if (doc === null) {
    try { doc = YAML.parse(text); } catch { return []; }
  }
  const out = [];
  const walk = (value, keyName) => {
    if (typeof value === 'string') {
      const wiki = value.match(/^!?\[\[([^\[\]]+)\]\]$/);
      if (wiki) {
        out.push({ kind: 'wiki', raw: nfc(wiki[1].split('|')[0].split('#')[0].trim()),
                   alias: null, anchor: null, line: 1, col: 1 });
      } else if (LINK_KEYS.has(keyName)) {
        const external = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
        out.push({ kind: external ? 'external' : 'md', raw: nfc(value),
                   alias: null, anchor: null, line: 1, col: 1 });
      }
      return;
    }
    if (Array.isArray(value)) { for (const v of value) walk(v, keyName); return; }
    if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value)) walk(v, k);
    }
  };
  walk(doc, null);
  return out;
}

/** Build search postings, honoring the leak rule in §8.8. */
export function buildSearchIndex({ nodes, vaultId, sourceDigest, isPublic }) {
  const terms = {};
  for (const n of nodes) {
    if (!n.id || !n.text) continue;
    // §8.8: text is indexed only from nodes readable by `everyone`.
    if (!isPublic(n)) continue;
    const counts = new Map();
    for (const raw of (n.body ?? n.text).toLowerCase().matchAll(/[\p{L}\p{N}_]+/gu)) {
      const t = nfc(raw[0]);
      if (t.length < 2 || STOPWORDS.has(t)) continue;
      counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    for (const [t, tf] of counts) (terms[t] ??= []).push({ node: n.id, tf });
  }
  for (const t of Object.keys(terms)) {
    terms[t] = sortUtf8(terms[t], (p) => p.node);
  }
  return envelope('search', vaultId, sourceDigest, {
    terms, stopwords: 'basalt-en-v1', stemmer: 'none',
  });
}

/** The `basalt-en-v1` stopword list named in §10.5. */
export const STOPWORDS = new Set([
  'a', 'an', 'and', 'are', 'as', 'at', 'be', 'but', 'by', 'for', 'from',
  'has', 'have', 'he', 'in', 'is', 'it', 'its', 'of', 'on', 'or', 'that',
  'the', 'their', 'then', 'there', 'they', 'this', 'to', 'was', 'were',
  'will', 'with',
]);
