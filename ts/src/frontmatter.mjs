// Frontmatter parsing, PROTOCOL §5.2.
//
// The governing rule: one malformed file must never cost the vault its index.
// Every failure here is collected as a per-node error and the body is indexed
// anyway.

import YAML from 'yaml';
import { nfc, stem, extname } from './keys.mjs';

const DELIM = '---';

/** Kind from the key alone (§5.1) — never from sniffing bytes. */
const NOTE_EXT = new Set(['.md', '.markdown']);
const DATA_EXT = new Set(['.yaml', '.yml', '.json']);
const ASSET_EXT = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.svg', '.bmp', '.ico',
  '.pdf', '.mp3', '.wav', '.flac', '.ogg', '.m4a',
  '.mp4', '.webm', '.mov', '.avi', '.mkv',
  '.woff', '.woff2', '.ttf', '.otf',
  '.txt', '.csv', '.tsv',
]);

export function kindFor(path) {
  const ext = extname(path);
  if (NOTE_EXT.has(ext)) return 'note';
  if (DATA_EXT.has(ext)) return 'data';
  if (ASSET_EXT.has(ext)) return 'asset';
  return 'opaque';
}

/**
 * Split a note into its frontmatter block and body.
 *
 * §5.2 is strict about the opening delimiter: it must be the very first line,
 * with no BOM and no leading blank line. Both near-misses are common enough
 * (editors add BOMs, authors add blank lines) that silently accepting them
 * would make two implementations disagree about whether a file has
 * frontmatter at all.
 */
export function splitFrontmatter(text) {
  if (text.startsWith('﻿')) {
    return { raw: null, body: text, bodyStartLine: 1 };
  }
  const lines = text.split('\n');
  if (lines[0].trimEnd() !== DELIM) {
    return { raw: null, body: text, bodyStartLine: 1 };
  }
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trimEnd() === DELIM) {
      return {
        raw: lines.slice(1, i).join('\n'),
        body: lines.slice(i + 1).join('\n'),
        bodyStartLine: i + 2,
      };
    }
  }
  // Unterminated block: no frontmatter, whole file is body.
  return { raw: null, body: text, bodyStartLine: 1 };
}

const ULID_RE = /^[0-9a-hjkmnp-tv-z]{26}$/;

/** True for a well-formed lowercase Crockford base32 ULID (§4.1). */
export function isUlid(s) {
  return typeof s === 'string' && ULID_RE.test(s.toLowerCase());
}

/** Normalize a `tags` value: a list, or a comma-separated scalar (§5.2). */
function normalizeTags(value) {
  if (value == null) return [];
  const raw = Array.isArray(value)
    ? value
    : typeof value === 'string'
      ? value.split(',')
      : [value];
  const out = [];
  for (const t of raw) {
    if (t == null) continue;
    const s = nfc(String(t)).trim().replace(/^#/, '');
    if (s) out.push(s);
  }
  return out;
}

/**
 * Parse a note. Returns metadata plus `errors`, never throwing on bad YAML.
 *
 * `path` is used only for the filename-stem title fallback.
 */
export function parseNote(text, path = '') {
  const errors = [];
  const { raw, body, bodyStartLine } = splitFrontmatter(text);

  let fm = null;
  if (raw !== null) {
    try {
      fm = YAML.parse(raw, { strict: false });
      if (fm !== null && typeof fm !== 'object') fm = null;
      if (Array.isArray(fm)) fm = null;
    } catch (err) {
      errors.push({
        severity: 'warning',
        code: 'FRONTMATTER_PARSE',
        detail: err.message.split('\n')[0],
      });
      fm = null;
    }
  }

  const b = (fm && typeof fm.basalt === 'object' && fm.basalt) || {};

  let id = null;
  if (b.id != null) {
    const candidate = String(b.id).toLowerCase();
    if (isUlid(candidate)) id = candidate;
    else errors.push({ severity: 'error', code: 'INVALID_ID', detail: String(b.id) });
  }

  // Title: frontmatter, then first H1, then the filename stem (§5.2).
  let title = null;
  if (fm && fm.title != null && String(fm.title).trim()) {
    title = nfc(String(fm.title).trim());
  } else {
    const h1 = firstH1(body);
    if (h1) title = h1;
    else if (path) title = nfc(stem(path.split('/').pop()));
  }

  const aliases = (Array.isArray(b.aliases) ? b.aliases : [])
    .filter((a) => a != null)
    .map((a) => nfc(String(a).trim()))
    .filter(Boolean);

  return {
    id,
    title,
    tags: normalizeTags(fm?.tags),
    aliases,
    publish: b.publish === false ? false : true,
    acl: b.acl ?? null,
    created: b.created ?? null,
    updated: b.updated ?? null,
    frontmatter: fm,
    hasFrontmatter: raw !== null,
    body,
    bodyStartLine,
    errors,
  };
}

/** The first ATX H1 outside fenced code, or null. */
function firstH1(body) {
  let fence = null;
  for (const line of body.split('\n')) {
    const t = line.trimStart();
    const f = t.match(/^(`{3,}|~{3,})/);
    if (f) {
      if (fence === null) fence = f[1][0];
      else if (t.startsWith(fence.repeat(3))) fence = null;
      continue;
    }
    if (fence !== null) continue;
    const m = t.match(/^#\s+(.+?)\s*#*\s*$/);
    if (m) return nfc(m[1].trim());
  }
  return null;
}

/**
 * Write a node id into a note's frontmatter, preserving comments and key
 * order (§13.4). Used by the minting pass (§4.3).
 */
export function withId(text, id) {
  const { raw, body } = splitFrontmatter(text);
  if (raw === null) {
    return `---\nbasalt:\n  id: ${id}\n---\n${text}`;
  }
  const doc = YAML.parseDocument(raw);  // parseDocument retains comments
  const basalt = doc.get('basalt');
  if (basalt && typeof basalt === 'object' && typeof basalt.set === 'function') {
    basalt.set('id', id);
  } else {
    doc.set('basalt', doc.createNode({ id }));
  }
  const out = String(doc).replace(/\n$/, '');
  return `---\n${out}\n---\n${body}`;
}
