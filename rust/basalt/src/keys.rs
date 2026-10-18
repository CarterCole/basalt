//! Key validation and path algebra, PROTOCOL §1.1 and §2.

use crate::order::{compare_utf8, fold_case, is_nfc, nfc, sort_utf8};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const MAX_KEY_BYTES: usize = 1024;

pub const CONTENT: &str = "content/";
pub const META: &str = "meta/";
pub const INDEX: &str = "index/";
pub const PRINCIPALS: &str = "principals/";
pub const HISTORY: &str = "history/";
pub const MANIFEST: &str = "basalt.yaml";

/// Prefixes this spec reserves (§2.3).
pub const RESERVED: [&str; 5] = [CONTENT, META, INDEX, PRINCIPALS, HISTORY];

/// The rejection codes §1.1 defines, named exactly as the conformance corpus
/// spells them so a failure points at the rule rather than at a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyErrorCode {
    Empty,
    TooLong,
    ControlChar,
    LeadingSlash,
    TrailingSlash,
    EmptySegment,
    DotSegment,
    NotNfc,
}

impl KeyErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "KEY_EMPTY",
            Self::TooLong => "KEY_TOO_LONG",
            Self::ControlChar => "KEY_CONTROL_CHAR",
            Self::LeadingSlash => "KEY_LEADING_SLASH",
            Self::TrailingSlash => "KEY_TRAILING_SLASH",
            Self::EmptySegment => "KEY_EMPTY_SEGMENT",
            Self::DotSegment => "KEY_DOT_SEGMENT",
            Self::NotNfc => "KEY_NOT_NFC",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError {
    pub code: KeyErrorCode,
    pub key: String,
    pub detail: Option<String>,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.code.as_str(), self.key)?;
        if let Some(d) = &self.detail {
            write!(f, " ({d})")?;
        }
        Ok(())
    }
}

impl std::error::Error for KeyError {}

/// Validate a key for writing (§1.1).
///
/// The order of the checks is load-bearing: several of these inputs violate
/// more than one rule, and the corpus pins which code a given key produces.
/// NFC is checked last for that reason — the earlier checks give a more
/// specific answer for the same string.
pub fn validate_key(key: &str) -> Result<(), KeyError> {
    let err = |code, detail: Option<String>| KeyError {
        code,
        key: key.to_string(),
        detail,
    };

    if key.is_empty() {
        return Err(err(KeyErrorCode::Empty, None));
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(err(
            KeyErrorCode::TooLong,
            Some(format!("{} > {MAX_KEY_BYTES}", key.len())),
        ));
    }
    for ch in key.chars() {
        let cp = ch as u32;
        // C0 (including NUL), DEL and the C1 range.
        if cp < 0x20 || cp == 0x7f || (0x80..=0x9f).contains(&cp) {
            return Err(err(KeyErrorCode::ControlChar, Some(format!("U+{cp:04X}"))));
        }
    }
    if key.starts_with('/') {
        return Err(err(KeyErrorCode::LeadingSlash, None));
    }
    if key.ends_with('/') {
        return Err(err(KeyErrorCode::TrailingSlash, None));
    }
    for seg in key.split('/') {
        if seg.is_empty() {
            return Err(err(KeyErrorCode::EmptySegment, None));
        }
        if seg == "." || seg == ".." {
            return Err(err(KeyErrorCode::DotSegment, Some(seg.to_string())));
        }
    }
    if !is_nfc(key) {
        return Err(err(KeyErrorCode::NotNfc, None));
    }
    Ok(())
}

/// True when the key is valid, without constructing an error.
pub fn is_valid_key(key: &str) -> bool {
    validate_key(key).is_ok()
}

/// Detect colliding keys (§2.2) — distinct keys equal under NFC + case-fold.
///
/// Returns groups of two or more, each group ordered by §13.3 so the survivor
/// (the first) is the same in every implementation and a repair is
/// reproducible.
pub fn find_collisions<I, S>(keys: I) -> Vec<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut buckets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for k in keys {
        let k = k.as_ref();
        buckets.entry(fold_case(k)).or_default().push(k.to_string());
    }
    let mut out: Vec<Vec<String>> = buckets
        .into_values()
        .filter(|g| g.len() > 1)
        .map(|mut g| {
            sort_utf8(&mut g);
            g
        })
        .collect();
    out.sort_by(|a, b| compare_utf8(&a[0], &b[0]));
    out
}

/// Folder-case divergence (§2.2): distinct keys whose *folder* segments fold
/// together while the keys themselves do not.
///
/// Weaker than a collision — both files survive a round trip — but the two
/// folders merge on a case-insensitive store, which moves one file and breaks
/// every path-shaped link to it (§9.2 steps 1-3). Reported as a warning, and
/// never repaired: picking a winner would move a file the author did not ask
/// to move.
pub fn find_folder_case_divergence<I, S>(keys: I) -> Vec<Vec<String>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut spellings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for k in keys {
        let k = k.as_ref();
        let mut acc = String::new();
        let segs: Vec<&str> = k.split('/').collect();
        for seg in &segs[..segs.len().saturating_sub(1)] {
            acc.push_str(seg);
            acc.push('/');
            spellings
                .entry(fold_case(&acc))
                .or_default()
                .insert(acc.clone());
        }
    }
    let mut out: Vec<Vec<String>> = spellings
        .into_values()
        .filter(|s| s.len() > 1)
        .map(|s| {
            let mut g: Vec<String> = s.into_iter().collect();
            sort_utf8(&mut g);
            g
        })
        .collect();
    out.sort_by(|a, b| compare_utf8(&a[0], &b[0]));
    out
}

/// `content/Notes/A.md` → `Notes/A.md`. None for keys outside `content/`.
pub fn key_to_path(key: &str) -> Option<&str> {
    key.strip_prefix(CONTENT)
}

/// `Notes/A.md` → `content/Notes/A.md`
pub fn path_to_key(path: &str) -> String {
    format!("{CONTENT}{path}")
}

/// `Notes/Ideas/A.md` → `"Notes/Ideas/"`; a root-level path → `""`.
pub fn parent_folder(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i + 1],
        None => "",
    }
}

/// `Notes/Ideas/A.md` → `["", "Notes/", "Notes/Ideas/"]`, root-first.
pub fn ancestor_folders(path: &str) -> Vec<String> {
    let mut out = vec![String::new()];
    let segs: Vec<&str> = path.split('/').collect();
    let mut acc = String::new();
    for seg in &segs[..segs.len().saturating_sub(1)] {
        acc.push_str(seg);
        acc.push('/');
        out.push(acc.clone());
    }
    out
}

/// The ancestor folders of a path that may itself be a folder.
///
/// A folder's own entry is not one of its ancestors, so `Notes/` yields
/// `[""]` and `Notes/Sub/` yields `["", "Notes/"]`.
pub fn ancestors_of(path: &str) -> Vec<String> {
    if is_folder(path) {
        let probe = format!("{}/x", path.trim_end_matches('/'));
        let mut a = ancestor_folders(&probe);
        a.pop();
        a
    } else {
        ancestor_folders(path)
    }
}

/// `Notes/A.md` → `"A.md"`
pub fn basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// `"A.md"` → `"A"`; `"A.tar.gz"` → `"A.tar"` (last extension only).
/// A leading dot is not an extension, so `".gitignore"` is its own stem.
pub fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    }
}

/// `"A.MD"` → `".md"`; no extension → `""`.
pub fn extname(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

/// True when `path` names a folder: it ends in `/`, or it is the vault root.
pub fn is_folder(path: &str) -> bool {
    path.is_empty() || path.ends_with('/')
}

/// The folders implied by a set of content paths (§2.1).
///
/// Folders are never stored; one exists exactly as long as something lives
/// beneath it, which is why this is a function of the paths and nothing else.
pub fn implied_folders<I, S>(paths: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut set: BTreeSet<String> = BTreeSet::new();
    for p in paths {
        for f in ancestor_folders(p.as_ref()) {
            if !f.is_empty() {
                set.insert(f);
            }
        }
    }
    let mut out: Vec<String> = set.into_iter().collect();
    sort_utf8(&mut out);
    out
}

/// The folders between the vault root and a path, nearest last.
///
/// `Notes/Ideas/A.md` → `["Notes/", "Notes/Ideas/"]`. Used for the per-folder
/// subtree hashes in §10.6.
pub fn folders_of(path: &str) -> Vec<String> {
    ancestor_folders(path).into_iter().skip(1).collect()
}

/// Resolve `target` against the folder containing `from_path`, applying `.`
/// and `..` (§9.2 step 2).
///
/// None when the result escapes the vault root: a link must not be able to
/// address outside the vault.
pub fn resolve_relative(from_path: &str, target: &str) -> Option<String> {
    let base = parent_folder(from_path);
    normalize_segments(&format!("{base}{target}"))
}

/// Normalize a rooted target (`"/a/../b"` → `"b"`), or None if it escapes.
pub fn resolve_rooted(target: &str) -> Option<String> {
    normalize_segments(target)
}

fn normalize_segments(s: &str) -> Option<String> {
    let mut out: Vec<&str> = Vec::new();
    for seg in s.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                if out.is_empty() {
                    return None;
                }
                out.pop();
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(nfc(&out.join("/")).into_owned())
    }
}
