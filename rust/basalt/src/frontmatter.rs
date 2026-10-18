//! Content kinds and frontmatter parsing, PROTOCOL §5.
//!
//! The governing rule of §5.2: one malformed file must never cost the vault
//! its index. Nothing in this module returns an error to its caller — every
//! failure is collected as a per-node integrity entry and the body is indexed
//! anyway.

use crate::keys::{basename, extname, stem};
use crate::order::nfc;
use serde_yaml_ng::Value as Yaml;
use std::sync::OnceLock;

const DELIM: &str = "---";

/// Content kind, PROTOCOL §5.1. A function of the key alone — an
/// implementation MUST NOT sniff bytes, so that kind is computable from a
/// `list` result without fetching anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Note,
    Data,
    Asset,
    Opaque,
    /// Not a content object: the virtual folders of §2.1, which carry node
    /// ids and ACLs but no bytes.
    Folder,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Data => "data",
            Self::Asset => "asset",
            Self::Opaque => "opaque",
            Self::Folder => "folder",
        }
    }

    /// Scanned for links (§5.1).
    pub fn linkable(self) -> bool {
        matches!(self, Self::Note | Self::Data)
    }
}

const NOTE_EXT: [&str; 2] = [".md", ".markdown"];
const DATA_EXT: [&str; 3] = [".yaml", ".yml", ".json"];
const ASSET_EXT: [&str; 25] = [
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".bmp", ".ico", ".pdf", ".mp3",
    ".wav", ".flac", ".ogg", ".m4a", ".mp4", ".webm", ".mov", ".avi", ".mkv", ".woff", ".woff2",
    ".ttf", ".otf", ".txt",
];

pub fn kind_for(path: &str) -> Kind {
    let ext = extname(basename(path));
    if NOTE_EXT.contains(&ext.as_str()) {
        Kind::Note
    } else if DATA_EXT.contains(&ext.as_str()) {
        Kind::Data
    } else if ASSET_EXT.contains(&ext.as_str()) || ext == ".csv" || ext == ".tsv" {
        Kind::Asset
    } else {
        Kind::Opaque
    }
}

/// A frontmatter split: the raw YAML block, the body, and the 1-based line the
/// body starts on.
#[derive(Debug, Clone)]
pub struct Split {
    pub raw: Option<String>,
    pub body: String,
    pub body_start_line: usize,
}

/// Split a note into its frontmatter block and body.
///
/// §5.2 is strict about the opening delimiter: it must be the very first line,
/// with no BOM and no leading blank line. Both near-misses are common (editors
/// add BOMs, authors add blank lines) and accepting them silently would make
/// two implementations disagree about whether a file has frontmatter at all.
pub fn split_frontmatter(text: &str) -> Split {
    let whole = || Split {
        raw: None,
        body: text.to_string(),
        body_start_line: 1,
    };
    if text.starts_with('\u{feff}') {
        return whole();
    }
    let lines: Vec<&str> = text.split('\n').collect();
    if lines.first().map(|l| l.trim_end()) != Some(DELIM) {
        return whole();
    }
    for (i, line) in lines.iter().enumerate().skip(1) {
        if line.trim_end() == DELIM {
            return Split {
                raw: Some(lines[1..i].join("\n")),
                body: lines[i + 1..].join("\n"),
                body_start_line: i + 2,
            };
        }
    }
    // Unterminated block: no frontmatter, the whole file is body.
    whole()
}

/// True for a well-formed lowercase Crockford base32 ULID (§4.1).
///
/// Crockford omits `i`, `l`, `o` and `u` to keep the alphabet unambiguous when
/// read aloud or transcribed.
pub fn is_ulid(s: &str) -> bool {
    let s = s.to_lowercase();
    s.len() == 26
        && s.chars().all(|c| {
            c.is_ascii_digit() || (c.is_ascii_lowercase() && !matches!(c, 'i' | 'l' | 'o' | 'u'))
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeError {
    pub severity: Severity,
    pub code: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

/// A parsed note: the reserved keys of §5.2, the conventional user keys read
/// if present, and the errors collected on the way.
#[derive(Debug, Clone)]
pub struct Note {
    pub id: Option<String>,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub aliases: Vec<String>,
    pub publish: bool,
    pub acl: Option<Yaml>,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub has_frontmatter: bool,
    pub body: String,
    pub body_start_line: usize,
    pub errors: Vec<NodeError>,
}

/// Parse a note. Never fails; `path` is used only for the filename-stem title
/// fallback, so passing `""` suppresses that fallback.
pub fn parse_note(text: &str, path: &str) -> Note {
    let mut errors = Vec::new();
    let split = split_frontmatter(text);

    let mut fm: Option<Yaml> = None;
    if let Some(raw) = &split.raw {
        match serde_yaml_ng::from_str::<Yaml>(raw) {
            Ok(v) => {
                // A frontmatter block that parses to a scalar or a sequence is
                // not a mapping of keys, so it carries nothing this protocol
                // can read. Treated as absent rather than as an error: it is
                // legal YAML, just not a frontmatter block.
                fm = if v.is_mapping() { Some(v) } else { None };
            }
            Err(e) => {
                errors.push(NodeError {
                    severity: Severity::Warning,
                    code: "FRONTMATTER_PARSE".into(),
                    detail: Some(e.to_string().lines().next().unwrap_or("").to_string()),
                });
            }
        }
    }

    let basalt = fm
        .as_ref()
        .and_then(|f| f.get("basalt"))
        .filter(|b| b.is_mapping());

    let mut id = None;
    if let Some(raw_id) = basalt.and_then(|b| b.get("id")) {
        let candidate = yaml_text(raw_id).map(|s| s.to_lowercase());
        match candidate {
            Some(c) if is_ulid(&c) => id = Some(c),
            Some(c) => errors.push(NodeError {
                severity: Severity::Error,
                code: "INVALID_ID".into(),
                detail: Some(c),
            }),
            None => errors.push(NodeError {
                severity: Severity::Error,
                code: "INVALID_ID".into(),
                detail: None,
            }),
        }
    }

    // Title: frontmatter, then the first H1, then the filename stem (§5.2).
    let fm_title = fm
        .as_ref()
        .and_then(|f| f.get("title"))
        .and_then(yaml_text)
        .map(|s| nfc(s.trim()).into_owned())
        .filter(|s| !s.is_empty());
    let title = fm_title.or_else(|| first_h1(&split.body)).or_else(|| {
        if path.is_empty() {
            None
        } else {
            Some(nfc(stem(basename(path))).into_owned())
        }
    });

    let aliases = basalt
        .and_then(|b| b.get("aliases"))
        .and_then(|a| a.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(yaml_text)
                .map(|s| nfc(s.trim()).into_owned())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    Note {
        id,
        title,
        tags: normalize_tags(fm.as_ref().and_then(|f| f.get("tags"))),
        aliases,
        publish: basalt
            .and_then(|b| b.get("publish"))
            .and_then(|p| p.as_bool())
            != Some(false),
        acl: basalt.and_then(|b| b.get("acl")).cloned(),
        created: basalt.and_then(|b| b.get("created")).and_then(yaml_text),
        updated: basalt.and_then(|b| b.get("updated")).and_then(yaml_text),
        has_frontmatter: split.raw.is_some(),
        body: split.body,
        body_start_line: split.body_start_line,
        errors,
    }
}

/// A YAML scalar as text. Numbers and booleans are rendered rather than
/// rejected, because `title: 2026` and `id: 01jbq…` both arrive as scalars and
/// a vault should not lose a title to a type guess.
pub fn yaml_scalar(v: &Yaml) -> Option<&str> {
    match v {
        Yaml::String(s) => Some(s),
        _ => None,
    }
}

/// Like [`yaml_scalar`], but renders non-string scalars too.
pub fn yaml_text(v: &Yaml) -> Option<String> {
    match v {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Number(n) => Some(n.to_string()),
        Yaml::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Normalize a `tags` value: a list, or a comma-separated scalar (§5.2).
fn normalize_tags(value: Option<&Yaml>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    let raw: Vec<String> = match value {
        Yaml::Sequence(seq) => seq.iter().filter_map(yaml_text).collect(),
        Yaml::String(s) => s.split(',').map(str::to_string).collect(),
        other => yaml_text(other).into_iter().collect(),
    };
    raw.iter()
        .map(|t| {
            let t = nfc(t.trim()).into_owned();
            t.strip_prefix('#').unwrap_or(&t).to_string()
        })
        .filter(|t| !t.is_empty())
        .collect()
}

fn h1_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^#\s+(.+?)\s*#*\s*$").unwrap())
}

/// The first ATX H1 outside fenced code, or None.
fn first_h1(body: &str) -> Option<String> {
    let mut fence: Option<char> = None;
    for line in body.split('\n') {
        let t = line.trim_start();
        let opener = t
            .strip_prefix("```")
            .map(|_| '`')
            .or_else(|| t.strip_prefix("~~~").map(|_| '~'));
        if let Some(c) = opener {
            match fence {
                None => fence = Some(c),
                Some(open) if open == c => fence = None,
                Some(_) => {}
            }
            continue;
        }
        if fence.is_some() {
            continue;
        }
        if let Some(m) = h1_re().captures(t) {
            return Some(nfc(m.get(1).unwrap().as_str().trim()).into_owned());
        }
    }
    None
}

/// Write a node id into a note's frontmatter, for the minting pass of §4.3.
///
/// §13.4 requires comments to be preserved when an implementation edits YAML
/// it did not author, and an implementation that cannot preserve them MUST
/// refuse to rewrite the file. This one therefore does not reserialize the
/// block: it splices `id:` into the existing `basalt:` mapping textually, or
/// prepends a fresh two-line block, leaving every other byte of the author's
/// YAML — comments, key order, quoting, blank lines — untouched.
pub fn with_id(text: &str, id: &str) -> Result<String, String> {
    let split = split_frontmatter(text);
    let Some(raw) = split.raw else {
        return Ok(format!("---\nbasalt:\n  id: {id}\n---\n{text}"));
    };

    let lines: Vec<&str> = raw.split('\n').collect();
    let basalt_at = lines.iter().position(|l| {
        let t = l.trim_end();
        t == "basalt:" || t.starts_with("basalt:")
    });

    let mut out: Vec<String> = Vec::new();
    match basalt_at {
        None => {
            out.push("basalt:".into());
            out.push(format!("  id: {id}"));
            out.extend(lines.iter().map(|s| s.to_string()));
        }
        Some(i) => {
            let inline = lines[i].trim_end() != "basalt:";
            if inline {
                // `basalt: {…}` on one line. Rewriting a flow mapping safely
                // would mean reserializing it, which §13.4 forbids when we
                // cannot guarantee the author's layout survives.
                return Err(format!(
                    "cannot add an id without rewriting the flow mapping on line {}; \
                     §13.4 forbids silently restyling a human's YAML",
                    i + 1
                ));
            }
            // Match the indentation of the mapping's existing first key, so the
            // spliced line sits where the author's own keys sit.
            let indent = lines[i + 1..]
                .iter()
                .find(|l| !l.trim().is_empty())
                .and_then(|l| {
                    let w = l.len() - l.trim_start().len();
                    (w > 0).then(|| l[..w].to_string())
                })
                .unwrap_or_else(|| "  ".to_string());
            out.extend(lines[..=i].iter().map(|s| s.to_string()));
            out.push(format!("{indent}id: {id}"));
            out.extend(lines[i + 1..].iter().map(|s| s.to_string()));
        }
    }

    Ok(format!(
        "---\n{}\n---\n{}",
        out.join("\n").trim_end_matches('\n'),
        split.body
    ))
}
