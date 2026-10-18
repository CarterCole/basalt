// Link extraction and resolution, PROTOCOL §9.

import {
  nfc, foldCase, sortUtf8, stem, basename,
  resolveRelative, resolveRooted, parentFolder,
} from './keys.mjs';

const LINK_EXTENSIONS = ['', '.md', '.markdown'];

// ---------------------------------------------------------------- extraction

/**
 * Compute byte-offset ranges that link syntax must be ignored inside (§9.1):
 * fenced code blocks, inline code spans, math, and HTML comments.
 *
 * This is done as a mask over the whole text rather than line by line because
 * three of the four constructs span lines. Getting it wrong is not a corner
 * case: this very protocol's documentation is full of `[[Example]]` inside
 * fences, and indexing those would pollute the graph of any vault that
 * documents itself.
 */
function exclusionRanges(text) {
  const ranges = [];
  const n = text.length;

  // Fenced blocks: a line whose first non-space run is 3+ backticks or tildes,
  // closed by a line opening with at least as many of the same character.
  const lines = [];
  let off = 0;
  for (const line of text.split('\n')) {
    lines.push({ line, start: off });
    off += line.length + 1;
  }
  let fence = null;
  for (const { line, start } of lines) {
    const m = line.match(/^\s{0,3}(`{3,}|~{3,})/);
    if (fence === null) {
      if (m) fence = { char: m[1][0], len: m[1].length, start };
    } else if (m && m[1][0] === fence.char && m[1].length >= fence.len) {
      ranges.push([fence.start, start + line.length]);
      fence = null;
    }
  }
  if (fence !== null) ranges.push([fence.start, n]);  // unterminated fence

  const masked = (i) => ranges.some(([a, b]) => i >= a && i < b);

  // Inline code spans: matched runs of backticks on one line.
  for (let i = 0; i < n; i++) {
    if (text[i] !== '`' || masked(i)) continue;
    let len = 0;
    while (i + len < n && text[i + len] === '`') len++;
    const close = text.indexOf('`'.repeat(len), i + len);
    if (close === -1) { i += len - 1; continue; }
    const nl = text.indexOf('\n', i);
    if (nl !== -1 && nl < close) { i += len - 1; continue; }  // spans a line
    ranges.push([i, close + len]);
    i = close + len - 1;
  }

  // HTML comments and math blocks.
  for (const [open, close] of [['<!--', '-->'], ['$$', '$$']]) {
    let i = 0;
    while ((i = text.indexOf(open, i)) !== -1) {
      if (masked(i)) { i += open.length; continue; }
      const end = text.indexOf(close, i + open.length);
      if (end === -1) { ranges.push([i, n]); break; }
      ranges.push([i, end + close.length]);
      i = end + close.length;
    }
  }

  return ranges.sort((a, b) => a[0] - b[0]);
}

function offsetToLineCol(text, offset) {
  let line = 1, last = 0;
  for (let i = 0; i < offset; i++) {
    if (text[i] === '\n') { line++; last = i + 1; }
  }
  return { line, col: offset - last + 1 };
}

// [[target|alias]] / ![[target]] — the leading ! marks an embed.
const WIKI_RE = /(!?)\[\[([^\[\]]*?)\]\]/g;
// [text](target) — target stops at whitespace or the closing paren.
const MD_RE = /\[([^\]]*)\]\(\s*<?([^()<>\s]+)>?(?:\s+"[^"]*")?\s*\)/g;
// #tag, #nested/tag
const TAG_RE = /(^|[^\p{L}\p{N}_/#])#([\p{L}\p{N}_-]+(?:\/[\p{L}\p{N}_-]+)*)/gu;

/** Split a raw wikilink body into target, alias and anchor. */
function parseWikiBody(body) {
  let rest = body;
  let alias = null;
  const pipe = rest.indexOf('|');
  if (pipe !== -1) {
    alias = nfc(rest.slice(pipe + 1).trim()) || null;
    rest = rest.slice(0, pipe);
  }
  let anchor = null;
  const hash = rest.indexOf('#');
  if (hash !== -1) {
    anchor = nfc(rest.slice(hash + 1).trim()) || null;
    rest = rest.slice(0, hash);
  }
  return { target: nfc(rest.trim()), alias, anchor };
}

const SCHEME_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * Extract every edge and tag from note text. Returns edges in document order,
 * which §10.2 requires.
 */
export function extractLinks(text) {
  const ranges = exclusionRanges(text);
  const excluded = (i) => ranges.some(([a, b]) => i >= a && i < b);
  const edges = [];

  for (const m of text.matchAll(WIKI_RE)) {
    if (excluded(m.index)) continue;
    const { target, alias, anchor } = parseWikiBody(m[2]);
    if (!target) continue;  // §9.1: empty or whitespace target, skip silently
    edges.push({
      kind: m[1] === '!' ? 'embed' : 'wiki',
      raw: target, alias, anchor, offset: m.index,
    });
  }

  for (const m of text.matchAll(MD_RE)) {
    if (excluded(m.index)) continue;
    const href = m[2].trim();
    if (!href || href.startsWith('#')) continue;
    const isExternal = SCHEME_RE.test(href) || href.startsWith('mailto:');
    let target = href, anchor = null;
    if (!isExternal) {
      const hash = href.indexOf('#');
      if (hash !== -1) {
        anchor = nfc(decodeURIComponent(href.slice(hash + 1))) || null;
        target = href.slice(0, hash);
      }
      try { target = decodeURIComponent(target); } catch { /* keep raw */ }
    }
    if (!target) continue;
    edges.push({
      kind: isExternal ? 'external' : 'md',
      raw: nfc(target), alias: nfc(m[1].trim()) || null, anchor, offset: m.index,
    });
  }

  edges.sort((a, b) => a.offset - b.offset);
  for (const e of edges) Object.assign(e, offsetToLineCol(text, e.offset));

  return { edges, tags: extractTags(text, excluded) };
}

/** Inline tags (§9.6), including the implied-parent closure. */
function extractTags(text, excluded) {
  const seen = new Map();  // folded → first-seen display form
  for (const m of text.matchAll(TAG_RE)) {
    const at = m.index + m[1].length;
    if (excluded(at)) continue;
    const tag = nfc(m[2]);
    if (/^[\p{N}]+$/u.test(tag)) continue;  // §9.6: #1 is not a tag
    for (const t of tagClosure(tag)) {
      const f = foldCase(t);
      if (!seen.has(f)) seen.set(f, t);
    }
  }
  return [...seen.values()];
}

/** "a/b/c" → ["a", "a/b", "a/b/c"] (§9.6 implied parents). */
export function tagClosure(tag) {
  const parts = tag.split('/');
  return parts.map((_, i) => parts.slice(0, i + 1).join('/'));
}

/** Slugify a heading for anchor comparison (§9.3). */
export function slugify(text) {
  return nfc(text).toLowerCase().trim()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9\-_]/g, '');
}

/** Headings with slugs, skipping fenced code. */
export function extractHeadings(text) {
  const ranges = exclusionRanges(text);
  const excluded = (i) => ranges.some(([a, b]) => i >= a && i < b);
  const out = [];
  let off = 0;
  for (const line of text.split('\n')) {
    const m = line.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (m && !excluded(off)) {
      const t = nfc(m[2].trim());
      out.push({ level: m[1].length, text: t, slug: slugify(t) });
    }
    off += line.length + 1;
  }
  return out;
}

/** Block ids (`^abc123` at end of a line), for #^ anchors. */
export function extractBlockIds(text) {
  const out = [];
  for (const m of text.matchAll(/(?:^|\s)\^([\p{L}\p{N}-]+)\s*$/gmu)) {
    out.push(m[1]);
  }
  return out;
}

// ---------------------------------------------------------------- resolution

/**
 * Build the lookup tables resolution needs. `nodes` is an array of
 * {id, path, aliases}.
 */
export function buildResolver(nodes) {
  const byPath = new Map();          // exact path → node
  const byAlias = new Map();         // folded alias → node[]
  const byStem = new Map();          // folded stem AND basename → node[]

  for (const n of nodes) {
    byPath.set(nfc(n.path), n);
    for (const a of n.aliases ?? []) {
      const k = foldCase(a);
      if (!byAlias.has(k)) byAlias.set(k, []);
      byAlias.get(k).push(n);
    }
    // §9.2 step 5 matches the stem and the full basename, so that both
    // [[Hexes]] and ![[diagram.png]] resolve. A node whose name has no
    // extension yields the same string twice, hence the dedupe.
    const name = basename(n.path);
    for (const key of new Set([foldCase(stem(name)), foldCase(name)])) {
      if (!byStem.has(key)) byStem.set(key, []);
      byStem.get(key).push(n);
    }
  }
  for (const list of [...byAlias.values(), ...byStem.values()]) {
    list.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  }
  return { byPath, byAlias, byStem, nodes };
}

function tryPath(resolver, candidate) {
  if (!candidate) return null;
  for (const ext of LINK_EXTENSIONS) {
    const hit = resolver.byPath.get(nfc(candidate + ext));
    if (hit) return hit;
  }
  return null;
}

/**
 * Resolve one target (§9.2). Returns
 * {node, by, ambiguous, candidates} — `node` is null when unresolved.
 *
 * The step order is the whole point: rooted paths beat relative ones, relative
 * beat vault-root, and only then do the forgiving name-based steps run. Steps
 * 1-3 are case-sensitive and 4-5 are not, because a path-shaped target means
 * exactly what it says while a name-shaped one is how people type.
 */
export function resolveTarget(resolver, fromPath, rawTarget) {
  const target = nfc(rawTarget);

  // 1. Rooted path.
  if (target.startsWith('/')) {
    const hit = tryPath(resolver, resolveRooted(target));
    return hit
      ? { node: hit, by: 'rooted-path', ambiguous: false, candidates: [] }
      : { node: null, by: 'unresolved', ambiguous: false, candidates: [] };
  }

  // 2. Exact relative path.
  const rel = resolveRelative(fromPath, target);
  const relHit = tryPath(resolver, rel);
  if (relHit) return { node: relHit, by: 'relative-path', ambiguous: false, candidates: [] };

  // 3. Exact vault-root path.
  const rootHit = tryPath(resolver, resolveRooted(target));
  if (rootHit) return { node: rootHit, by: 'vault-root-path', ambiguous: false, candidates: [] };

  // 4. Alias, case-insensitive.
  const aliasHits = resolver.byAlias.get(foldCase(target)) ?? [];
  if (aliasHits.length) return pick(aliasHits, 'alias');

  // 5. Unique basename, case-insensitive.
  const stemHits = resolver.byStem.get(foldCase(target)) ?? [];
  if (stemHits.length) return pick(stemHits, 'unique-basename');

  // 6. Unresolved.
  return { node: null, by: 'unresolved', ambiguous: false, candidates: [] };
}

/**
 * Choose among multiple name matches. §9.2 requires a deterministic tiebreak —
 * bytewise-first path — and requires the ambiguity be reported, not hidden,
 * so the author can fix the real problem.
 */
function pick(hits, by) {
  const ordered = sortUtf8(hits, (n) => n.path);
  return {
    node: ordered[0],
    by,
    ambiguous: ordered.length > 1,
    candidates: ordered.length > 1 ? ordered.map((n) => n.id) : [],
  };
}

/** True when an anchor resolves against a node's headings/block ids (§9.3). */
export function anchorResolves(anchor, headings, blockIds) {
  if (!anchor) return true;
  if (anchor.startsWith('^')) return (blockIds ?? []).includes(anchor.slice(1));
  const want = slugify(anchor);
  return (headings ?? []).some((h) => h.slug === want);
}

export { parentFolder };
