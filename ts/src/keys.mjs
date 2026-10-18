// Key validation and path algebra, PROTOCOL §1.1 and §2.

import { nfc, foldCase, compareUtf8, sortUtf8 } from './order.mjs';

export const MAX_KEY_BYTES = 1024;

export const CONTENT = 'content/';
export const META = 'meta/';
export const INDEX = 'index/';
export const PRINCIPALS = 'principals/';
export const HISTORY = 'history/';
export const MANIFEST = 'basalt.yaml';

/** Prefixes this spec reserves (§2.3). */
export const RESERVED = [CONTENT, META, INDEX, PRINCIPALS, HISTORY];

export class KeyError extends Error {
  constructor(code, key, detail) {
    super(`${code}: ${JSON.stringify(key)}${detail ? ` (${detail})` : ''}`);
    this.name = 'KeyError';
    this.code = code;
    this.key = key;
  }
}

/**
 * Validate a key for writing (§1.1). Returns the key unchanged, or throws
 * KeyError with the code the conformance corpus expects.
 */
export function validateKey(key) {
  if (typeof key !== 'string' || key.length === 0) {
    throw new KeyError('KEY_EMPTY', key);
  }
  const bytes = new TextEncoder().encode(key).length;
  if (bytes > MAX_KEY_BYTES) {
    throw new KeyError('KEY_TOO_LONG', key, `${bytes} > ${MAX_KEY_BYTES}`);
  }
  for (const ch of key) {
    const cp = ch.codePointAt(0);
    // C0 (incl. NUL) and C1 control ranges.
    if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) {
      throw new KeyError('KEY_CONTROL_CHAR', key, `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`);
    }
  }
  if (key.startsWith('/')) throw new KeyError('KEY_LEADING_SLASH', key);
  if (key.endsWith('/')) throw new KeyError('KEY_TRAILING_SLASH', key);

  const segments = key.split('/');
  for (const seg of segments) {
    if (seg === '') throw new KeyError('KEY_EMPTY_SEGMENT', key);
    if (seg === '.' || seg === '..') throw new KeyError('KEY_DOT_SEGMENT', key, seg);
  }
  // NFC last: the checks above give more specific errors for the same input,
  // and the corpus pins which error a given key produces.
  if (nfc(key) !== key) throw new KeyError('KEY_NOT_NFC', key);
  return key;
}

/** True when the key is valid, without throwing. */
export function isValidKey(key) {
  try { validateKey(key); return true; } catch { return false; }
}

/**
 * Detect colliding keys (§2.2) — distinct keys equal under NFC + case-fold.
 * Returns groups of two or more keys, each group ordered by §13.3 so the
 * survivor (the first) is deterministic.
 */
export function findCollisions(keys) {
  const buckets = new Map();
  for (const k of keys) {
    const fold = foldCase(k);
    if (!buckets.has(fold)) buckets.set(fold, []);
    buckets.get(fold).push(k);
  }
  const out = [];
  for (const group of buckets.values()) {
    if (group.length > 1) out.push(sortUtf8(group));
  }
  return sortUtf8(out, (g) => g[0]);
}

/**
 * Folder-case divergence (§2.2): distinct keys whose folder segments fold
 * together. Weaker than a collision — both files survive — but the folders
 * merge on a case-insensitive store, moving one file and breaking every
 * path-shaped link to it.
 *
 * Returns groups of the differently-cased folder spellings found, each
 * ordered by §13.3.
 */
export function findFolderCaseDivergence(keys) {
  const spellings = new Map();  // folded folder → Set<actual spelling>
  for (const k of keys) {
    const segs = k.split('/');
    segs.pop();
    let acc = '';
    for (const seg of segs) {
      acc += seg + '/';
      const f = foldCase(acc);
      if (!spellings.has(f)) spellings.set(f, new Set());
      spellings.get(f).add(acc);
    }
  }
  const out = [];
  for (const set of spellings.values()) {
    if (set.size > 1) out.push(sortUtf8([...set]));
  }
  return sortUtf8(out, (g) => g[0]);
}

/** content/Notes/A.md → Notes/A.md. Returns null for keys outside content/. */
export function keyToPath(key) {
  return key.startsWith(CONTENT) ? key.slice(CONTENT.length) : null;
}

/** Notes/A.md → content/Notes/A.md */
export function pathToKey(path) {
  return CONTENT + path;
}

/** Notes/Ideas/A.md → "Notes/Ideas/"; a root-level path → "" */
export function parentFolder(path) {
  const i = path.lastIndexOf('/');
  return i === -1 ? '' : path.slice(0, i + 1);
}

/** Notes/Ideas/A.md → ["", "Notes/", "Notes/Ideas/"], root-first. */
export function ancestorFolders(path) {
  const out = [''];
  const segs = path.split('/');
  segs.pop();  // drop the entry name
  let acc = '';
  for (const s of segs) { acc += s + '/'; out.push(acc); }
  return out;
}

/** Notes/A.md → "A.md" */
export function basename(path) {
  const i = path.lastIndexOf('/');
  return i === -1 ? path : path.slice(i + 1);
}

/** "A.md" → "A"; "A.tar.gz" → "A.tar" (last extension only) */
export function stem(name) {
  const i = name.lastIndexOf('.');
  return i <= 0 ? name : name.slice(0, i);
}

/** "A.md" → ".md" (lowercased); no extension → "" */
export function extname(name) {
  const i = name.lastIndexOf('.');
  return i <= 0 ? '' : name.slice(i).toLowerCase();
}

/** True when `path` is a folder path (ends in / or is the root ""). */
export function isFolder(path) {
  return path === '' || path.endsWith('/');
}

/**
 * The set of folders implied by a set of content paths (§2.1). Folders are
 * never stored; they exist exactly as long as something lives beneath them.
 */
export function impliedFolders(paths) {
  const set = new Set();
  for (const p of paths) {
    for (const f of ancestorFolders(p)) if (f !== '') set.add(f);
  }
  return sortUtf8([...set]);
}

/**
 * Resolve `target` against the folder of `fromPath`, applying . and ..
 * Returns null if the result escapes the vault root — a link must not be
 * able to address outside the vault.
 */
export function resolveRelative(fromPath, target) {
  const base = parentFolder(fromPath);
  const segs = (base + target).split('/');
  const out = [];
  for (const seg of segs) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { if (out.length === 0) return null; out.pop(); continue; }
    out.push(seg);
  }
  return out.length ? out.join('/') : null;
}

/** Normalize a rooted target ("/a/../b" → "b"), or null if it escapes. */
export function resolveRooted(target) {
  const out = [];
  for (const seg of target.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { if (out.length === 0) return null; out.pop(); continue; }
    out.push(seg);
  }
  return out.length ? out.join('/') : null;
}

export { compareUtf8, sortUtf8, nfc, foldCase };
