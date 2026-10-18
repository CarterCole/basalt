//! Canonical ordering and comparison, PROTOCOL §13.3.
//!
//! All sorting in Basalt is by UTF-8 code unit sequence, bytewise ascending,
//! after NFC normalization. Rust's `str` ordering is already UTF-8 bytewise,
//! so this module is thinner than its counterpart in a UTF-16 language — but
//! it still exists, because the *normalization* half of §13.3 is not free and
//! every key, path, id, tag and term has to pass through it.

use std::cmp::Ordering;
use unicode_normalization::{is_nfc_quick, IsNormalized, UnicodeNormalization};

/// NFC-normalize, borrowing when the input is already normalized.
///
/// `is_nfc_quick` answers Yes for pure-ASCII input without allocating, which
/// is the overwhelmingly common case on a key or a path.
pub fn nfc(s: &str) -> std::borrow::Cow<'_, str> {
    match is_nfc_quick(s.chars()) {
        IsNormalized::Yes => std::borrow::Cow::Borrowed(s),
        _ => std::borrow::Cow::Owned(s.nfc().collect()),
    }
}

/// True when `s` is already in Normalization Form C (§1.1).
pub fn is_nfc(s: &str) -> bool {
    match is_nfc_quick(s.chars()) {
        IsNormalized::Yes => true,
        IsNormalized::No => false,
        IsNormalized::Maybe => s.nfc().eq(s.chars()),
    }
}

/// Compare two strings as UTF-8 byte sequences, ascending, after NFC (§13.3).
pub fn compare_utf8(a: &str, b: &str) -> Ordering {
    nfc(a).as_bytes().cmp(nfc(b).as_bytes())
}

/// Sort in place by §13.3.
pub fn sort_utf8(v: &mut [String]) {
    v.sort_by(|a, b| compare_utf8(a, b));
}

/// Sort in place by §13.3 through a key function.
pub fn sort_utf8_by<T, F>(v: &mut [T], key: F)
where
    F: Fn(&T) -> String,
{
    // Stable, so a key function that collides preserves the authored order —
    // which matters for the integrity report, where two entries can share a
    // sort key legitimately.
    v.sort_by(|a, b| compare_utf8(&key(a), &key(b)));
}

/// Unicode case-fold for the collision rule (§2.2) and name matching (§9.2).
///
/// Lowercasing after NFC is the practical fold. Full Unicode case folding
/// differs for a handful of codepoints (the `ﬁ` ligature, for one), but no
/// store this rule protects against folds those either, and inventing a
/// stricter fold than the filesystems in question would reject legal keys.
pub fn fold_case(s: &str) -> String {
    nfc(s).to_lowercase()
}

/// Lowercase hex. `sha2`/`md-5` 0.11 return a `hybrid_array::Array`, which no
/// longer implements `LowerHex`, and a hash rendered differently is a
/// different index byte-for-byte (§13.1).
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}
