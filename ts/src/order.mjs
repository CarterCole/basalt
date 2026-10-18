// Canonical ordering and comparison, PROTOCOL §13.3.
//
// All sorting in Basalt is by UTF-8 code unit sequence, bytewise ascending,
// after NFC normalization. This is NOT what JavaScript's `<` does: `<`
// compares UTF-16 code units, which disagrees with UTF-8 byte order for
// characters above the BMP (a surrogate pair sorts below U+E000-U+FFFF in
// UTF-16 but above them in UTF-8). Two implementations that sort differently
// produce different index bytes and fail conformance (§13), so this one
// comparator is the only place ordering is decided.

/** NFC-normalize. Every key, path, id, tag and term passes through here. */
export function nfc(s) {
  return typeof s === 'string' ? s.normalize('NFC') : s;
}

const enc = new TextEncoder();

/** Compare two strings as UTF-8 byte sequences, ascending. */
export function compareUtf8(a, b) {
  const x = enc.encode(nfc(a));
  const y = enc.encode(nfc(b));
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  }
  return x.length === y.length ? 0 : x.length < y.length ? -1 : 1;
}

/** Sort a copy of `arr` by §13.3, optionally through a key function. */
export function sortUtf8(arr, keyFn) {
  const k = keyFn ?? ((v) => v);
  return [...arr].sort((a, b) => compareUtf8(k(a), k(b)));
}

/** Unicode case-fold for the collision rule (§2.2) and name matching (§9.2). */
export function foldCase(s) {
  // toLowerCase after NFC is the practical fold; full Unicode case folding
  // differs for a handful of codepoints (e.g. ﬁ ligature) but no store we
  // target folds those either, and inventing a stricter fold than the
  // filesystems this rule protects against would reject legal keys.
  return nfc(s).toLowerCase();
}
