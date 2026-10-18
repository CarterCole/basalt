// Canonical JSON serialization, PROTOCOL §13.1.
//
// Index objects must be byte-identical across implementations, so this does
// not use JSON.stringify: that sorts nothing, indents inconsistently for
// nested empties, and leaves U+2028/U+2029 unescaped (legal JSON, but they
// break when the bytes are embedded in a <script> tag).

import { compareUtf8 } from './order.mjs';

const ESCAPES = {
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
  '\n': '\\n', '\r': '\\r', '\t': '\\t',
};

function quote(s) {
  let out = '"';
  for (const ch of s) {
    const esc = ESCAPES[ch];
    if (esc) { out += esc; continue; }
    const cp = ch.codePointAt(0);
    // Escape C0 controls (JSON requires it) plus the two line separators
    // that are legal in JSON but illegal in JavaScript string literals.
    if (cp < 0x20 || cp === 0x2028 || cp === 0x2029) {
      out += '\\u' + cp.toString(16).padStart(4, '0');
    } else {
      out += ch;  // §13.1: non-ASCII emitted literally, never \u-escaped.
    }
  }
  return out + '"';
}

function write(value, indent, depth) {
  const pad = indent.repeat(depth);
  const padIn = indent.repeat(depth + 1);

  if (value === null || value === undefined) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('canonical JSON: non-finite number');
    }
    if (!Number.isInteger(value)) {
      // §13.1 bans non-integers from index objects outright, which sidesteps
      // every float-formatting disagreement between languages.
      throw new TypeError(`canonical JSON: non-integer number ${value}`);
    }
    return String(value);
  }
  if (typeof value === 'string') return quote(value);

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    const items = value.map((v) => padIn + write(v, indent, depth + 1));
    return '[\n' + items.join(',\n') + '\n' + pad + ']';
  }

  if (typeof value === 'object') {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined);
    if (keys.length === 0) return '{}';
    keys.sort(compareUtf8);  // §13.1: keys sorted by §13.3
    const items = keys.map(
      (k) => padIn + quote(k) + ': ' + write(value[k], indent, depth + 1),
    );
    return '{\n' + items.join(',\n') + '\n' + pad + '}';
  }

  throw new TypeError(`canonical JSON: unserializable ${typeof value}`);
}

/** Serialize to canonical JSON bytes: 2-space indent, LF, one trailing newline. */
export function canonicalJson(value) {
  return write(value, '  ', 0) + '\n';
}

/** Serialize and encode to UTF-8 bytes, ready for a transport put. */
export function canonicalBytes(value) {
  return new TextEncoder().encode(canonicalJson(value));
}

/**
 * Strip the fields §13.2 excludes from cross-implementation comparison, so
 * two runs at different times over identical content compare equal.
 */
export function comparable(obj) {
  const clone = structuredClone(obj);
  delete clone.generated;
  if (Array.isArray(clone.entries)) {
    for (const e of clone.entries) if (e && typeof e === 'object') delete e.etag;
  }
  return clone;
}
