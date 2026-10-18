//! Link extraction and resolution, PROTOCOL §9.
//!
//! The link graph is the reason a vault is more than a folder, so §9 specifies
//! extraction and resolution exactly: "which note does `[[Hexes]]` mean" must
//! not be answered differently by two implementations of the same vault.

use crate::keys::{basename, resolve_relative, resolve_rooted, stem};
use crate::order::{compare_utf8, fold_case, nfc};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

const LINK_EXTENSIONS: [&str; 3] = ["", ".md", ".markdown"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    Wiki,
    Embed,
    Md,
    External,
    Tag,
}

impl EdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wiki => "wiki",
            Self::Embed => "embed",
            Self::Md => "md",
            Self::External => "external",
            Self::Tag => "tag",
        }
    }
}

/// One extracted link, before resolution.
#[derive(Debug, Clone)]
pub struct RawEdge {
    pub kind: EdgeKind,
    pub raw: String,
    pub alias: Option<String>,
    pub anchor: Option<String>,
    /// Byte offset into the text the edge was extracted from.
    pub offset: usize,
    pub line: usize,
    /// 1-based column, counted in Unicode scalar values.
    ///
    /// §10.2 records `col` without naming its unit, which is a real ambiguity:
    /// the natural answer differs per language (UTF-16 units in JS, bytes in
    /// Rust, scalars in Python). Scalars are the language-neutral reading and
    /// the one an editor's own column display agrees with, so that is what
    /// this implementation emits.
    pub col: usize,
}

#[derive(Debug, Clone)]
pub struct Heading {
    pub level: usize,
    pub text: String,
    pub slug: String,
}

#[derive(Debug, Clone, Default)]
pub struct Extracted {
    pub edges: Vec<RawEdge>,
    /// Tags in first-seen order, carrying the display casing §9.6 asks for.
    pub tags: Vec<String>,
}

// ------------------------------------------------------------- exclusion

fn fence_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\s{0,3}(`{3,}|~{3,})").unwrap())
}

/// Byte ranges that link syntax must be ignored inside (§9.1): fenced code
/// blocks, inline code spans, math blocks and HTML comments.
///
/// Computed as a mask over the whole text rather than line by line, because
/// three of the four constructs span lines. This is not a corner case: the
/// protocol's own documentation is full of `[[Example]]` inside fences, and
/// indexing those would pollute the graph of any vault that documents itself.
fn exclusion_ranges(text: &str) -> Vec<(usize, usize)> {
    let n = text.len();
    let mut ranges: Vec<(usize, usize)> = Vec::new();

    // Fenced blocks: a line whose first non-space run is three or more
    // backticks or tildes, closed by a line opening with at least as many of
    // the same character.
    let mut offset = 0usize;
    let mut fence: Option<(char, usize, usize)> = None; // (char, len, start)
    for line in text.split('\n') {
        if let Some(m) = fence_re().captures(line) {
            let run = m.get(1).unwrap().as_str();
            let ch = run.chars().next().unwrap();
            match fence {
                None => fence = Some((ch, run.len(), offset)),
                Some((fc, flen, fstart)) if ch == fc && run.len() >= flen => {
                    ranges.push((fstart, offset + line.len()));
                    fence = None;
                }
                Some(_) => {}
            }
        }
        offset += line.len() + 1;
    }
    if let Some((_, _, start)) = fence {
        ranges.push((start, n)); // unterminated fence runs to end of file
    }

    let masked = |ranges: &[(usize, usize)], i: usize| ranges.iter().any(|&(a, b)| i >= a && i < b);

    // Inline code spans: matched runs of backticks on one line.
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i < n {
        if bytes[i] != b'`' || masked(&ranges, i) {
            i += 1;
            continue;
        }
        let mut len = 0usize;
        while i + len < n && bytes[i + len] == b'`' {
            len += 1;
        }
        let needle = "`".repeat(len);
        match text[i + len..].find(&needle) {
            None => {
                i += len;
            }
            Some(rel) => {
                let close = i + len + rel;
                // A span that crosses a line break is not a code span.
                match text[i..close].find('\n') {
                    Some(_) => i += len,
                    None => {
                        ranges.push((i, close + len));
                        i = close + len;
                    }
                }
            }
        }
    }

    // HTML comments and display-math blocks.
    for (open, close) in [("<!--", "-->"), ("$$", "$$")] {
        let mut i = 0usize;
        while let Some(rel) = text[i..].find(open) {
            let at = i + rel;
            if masked(&ranges, at) {
                i = at + open.len();
                continue;
            }
            match text[at + open.len()..].find(close) {
                None => {
                    ranges.push((at, n));
                    break;
                }
                Some(erel) => {
                    let end = at + open.len() + erel;
                    ranges.push((at, end + close.len()));
                    i = end + close.len();
                }
            }
        }
    }

    ranges.sort_unstable();
    ranges
}

fn is_excluded(ranges: &[(usize, usize)], i: usize) -> bool {
    ranges.iter().any(|&(a, b)| i >= a && i < b)
}

/// 1-based line, and 1-based column in Unicode scalars, for a byte offset.
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let before = &text[..offset.min(text.len())];
    let line = before.matches('\n').count() + 1;
    let line_start = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col = text[line_start..offset].chars().count() + 1;
    (line, col)
}

// ------------------------------------------------------------- extraction

fn wiki_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `[[target|alias]]` / `![[target]]` — the leading `!` marks an embed and
    // is part of the match, so `col` points at the `!`.
    RE.get_or_init(|| Regex::new(r"(!?)\[\[([^\[\]]*?)\]\]").unwrap())
}

fn md_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // `[text](target)` — the target stops at whitespace or the closing paren,
    // with an optional angle-bracketed form and an optional title.
    RE.get_or_init(|| {
        Regex::new(r#"\[([^\]]*)\]\(\s*<?([^()<>\s]+)>?(?:\s+"[^"]*")?\s*\)"#).unwrap()
    })
}

fn tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // §9.6: `#` followed by one or more `[\p{L}\p{N}_-]+` segments separated
    // by `/`, and not preceded by a word character — so `C#` and a URL
    // fragment are both safe.
    RE.get_or_init(|| {
        Regex::new(r"(^|[^\p{L}\p{N}_/#])#([\p{L}\p{N}_\-]+(?:/[\p{L}\p{N}_\-]+)*)").unwrap()
    })
}

fn scheme_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^[a-z][a-z0-9+.\-]*://").unwrap())
}

struct WikiBody {
    target: String,
    alias: Option<String>,
    anchor: Option<String>,
}

/// Split a raw wikilink body into target, alias and anchor.
fn parse_wiki_body(body: &str) -> WikiBody {
    let mut rest = body;
    let mut alias = None;
    if let Some(pipe) = rest.find('|') {
        let a = nfc(rest[pipe + 1..].trim()).into_owned();
        alias = (!a.is_empty()).then_some(a);
        rest = &rest[..pipe];
    }
    let mut anchor = None;
    if let Some(hash) = rest.find('#') {
        let a = nfc(rest[hash + 1..].trim()).into_owned();
        anchor = (!a.is_empty()).then_some(a);
        rest = &rest[..hash];
    }
    WikiBody {
        target: nfc(rest.trim()).into_owned(),
        alias,
        anchor,
    }
}

/// Percent-decode, falling back to the raw string when the escapes are broken.
fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                Err(_) => return s.to_string(),
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

/// Extract every edge and tag from note text, edges in document order — which
/// §10.2 requires.
pub fn extract_links(text: &str) -> Extracted {
    let ranges = exclusion_ranges(text);
    let mut edges: Vec<RawEdge> = Vec::new();

    for m in wiki_re().captures_iter(text) {
        let whole = m.get(0).unwrap();
        if is_excluded(&ranges, whole.start()) {
            continue;
        }
        let parsed = parse_wiki_body(m.get(2).unwrap().as_str());
        // §9.1: an empty or whitespace-only target is skipped silently, not
        // recorded as unresolved.
        if parsed.target.is_empty() {
            continue;
        }
        edges.push(RawEdge {
            kind: if m.get(1).unwrap().as_str() == "!" {
                EdgeKind::Embed
            } else {
                EdgeKind::Wiki
            },
            raw: parsed.target,
            alias: parsed.alias,
            anchor: parsed.anchor,
            offset: whole.start(),
            line: 0,
            col: 0,
        });
    }

    for m in md_re().captures_iter(text) {
        let whole = m.get(0).unwrap();
        if is_excluded(&ranges, whole.start()) {
            continue;
        }
        let href = m.get(2).unwrap().as_str().trim();
        // A bare `#fragment` is an intra-document anchor, not an edge.
        if href.is_empty() || href.starts_with('#') {
            continue;
        }
        let external = scheme_re().is_match(href) || href.starts_with("mailto:");
        let (target, anchor) = if external {
            (href.to_string(), None)
        } else {
            match href.find('#') {
                Some(h) => {
                    let a = nfc(&percent_decode(&href[h + 1..])).into_owned();
                    (percent_decode(&href[..h]), (!a.is_empty()).then_some(a))
                }
                None => (percent_decode(href), None),
            }
        };
        if target.is_empty() {
            continue;
        }
        let alias = nfc(m.get(1).unwrap().as_str().trim()).into_owned();
        edges.push(RawEdge {
            kind: if external {
                EdgeKind::External
            } else {
                EdgeKind::Md
            },
            raw: nfc(&target).into_owned(),
            alias: (!alias.is_empty()).then_some(alias),
            anchor,
            offset: whole.start(),
            line: 0,
            col: 0,
        });
    }

    edges.sort_by_key(|e| e.offset);
    for e in &mut edges {
        let (line, col) = line_col(text, e.offset);
        e.line = line;
        e.col = col;
    }

    Extracted {
        tags: extract_tags(text, &ranges),
        edges,
    }
}

/// Inline tags (§9.6), including the implied-parent closure, in first-seen
/// order with first-seen casing as the display form.
fn extract_tags(text: &str, ranges: &[(usize, usize)]) -> Vec<String> {
    let mut seen: Vec<(String, String)> = Vec::new(); // (folded, display)
    for m in tag_re().captures_iter(text) {
        let prefix = m.get(1).unwrap();
        let at = prefix.end();
        if is_excluded(ranges, at) {
            continue;
        }
        let tag = nfc(m.get(2).unwrap().as_str()).into_owned();
        // §9.6: `#1` is not a tag.
        if tag.chars().all(|c| c.is_numeric()) {
            continue;
        }
        for t in tag_closure(&tag) {
            let f = fold_case(&t);
            if !seen.iter().any(|(k, _)| *k == f) {
                seen.push((f, t));
            }
        }
    }
    seen.into_iter().map(|(_, d)| d).collect()
}

/// `"a/b/c"` → `["a", "a/b", "a/b/c"]` — the implied parents of §9.6, so that
/// querying `#nested` finds nodes tagged only `#nested/tag`.
pub fn tag_closure(tag: &str) -> Vec<String> {
    let parts: Vec<&str> = tag.split('/').collect();
    (1..=parts.len()).map(|i| parts[..i].join("/")).collect()
}

/// Slugify a heading for anchor comparison (§9.3): lowercase, NFC, runs of
/// whitespace to `-`, then strip everything outside `[a-z0-9-_]`.
pub fn slugify(text: &str) -> String {
    let lower = nfc(text).to_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut in_ws = false;
    for ch in lower.trim().chars() {
        if ch.is_whitespace() {
            in_ws = true;
            continue;
        }
        if in_ws {
            out.push('-');
            in_ws = false;
        }
        out.push(ch);
    }
    out.chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-' || *c == '_')
        .collect()
}

fn heading_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^(#{1,6})\s+(.+?)\s*#*\s*$").unwrap())
}

/// Headings with slugs, skipping fenced code.
pub fn extract_headings(text: &str) -> Vec<Heading> {
    let ranges = exclusion_ranges(text);
    let mut out = Vec::new();
    let mut offset = 0usize;
    for line in text.split('\n') {
        if let Some(m) = heading_re().captures(line) {
            if !is_excluded(&ranges, offset) {
                let t = nfc(m.get(2).unwrap().as_str().trim()).into_owned();
                out.push(Heading {
                    level: m.get(1).unwrap().as_str().len(),
                    slug: slugify(&t),
                    text: t,
                });
            }
        }
        offset += line.len() + 1;
    }
    out
}

fn block_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:^|\s)\^([\p{L}\p{N}\-]+)\s*$").unwrap())
}

/// Block ids (`^abc123` at the end of a line), for `#^` anchors (§9.1).
pub fn extract_block_ids(text: &str) -> Vec<String> {
    text.split('\n')
        .filter_map(|line| {
            block_id_re()
                .captures(line)
                .map(|m| m.get(1).unwrap().as_str().to_string())
        })
        .collect()
}

// ------------------------------------------------------------- resolution

/// What a resolver needs to know about a node.
#[derive(Debug, Clone)]
pub struct ResolvableNode {
    pub id: String,
    pub path: String,
    pub aliases: Vec<String>,
}

/// Which step of §9.2 produced a match. Named, not numbered, because the
/// conformance corpus asserts the step by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedBy {
    RootedPath,
    RelativePath,
    VaultRootPath,
    Alias,
    UniqueBasename,
    Unresolved,
}

impl ResolvedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RootedPath => "rooted-path",
            Self::RelativePath => "relative-path",
            Self::VaultRootPath => "vault-root-path",
            Self::Alias => "alias",
            Self::UniqueBasename => "unique-basename",
            Self::Unresolved => "unresolved",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Resolution {
    pub path: Option<String>,
    pub id: Option<String>,
    pub by: ResolvedBy,
    pub ambiguous: bool,
    pub candidates: Vec<String>,
}

/// The lookup tables resolution needs.
pub struct Resolver {
    by_path: BTreeMap<String, ResolvableNode>,
    by_alias: BTreeMap<String, Vec<ResolvableNode>>,
    by_name: BTreeMap<String, Vec<ResolvableNode>>,
}

impl Resolver {
    pub fn build<I: IntoIterator<Item = ResolvableNode>>(nodes: I) -> Self {
        let mut by_path = BTreeMap::new();
        let mut by_alias: BTreeMap<String, Vec<ResolvableNode>> = BTreeMap::new();
        let mut by_name: BTreeMap<String, Vec<ResolvableNode>> = BTreeMap::new();

        for n in nodes {
            by_path.insert(nfc(&n.path).into_owned(), n.clone());
            for a in &n.aliases {
                by_alias.entry(fold_case(a)).or_default().push(n.clone());
            }
            // §9.2 step 5 matches the stem *and* the full basename, so that
            // both `[[Hexes]]` and `![[diagram.png]]` resolve. A name with no
            // extension yields the same key twice, hence the dedupe.
            let name = basename(&n.path);
            let keys = {
                let a = fold_case(stem(name));
                let b = fold_case(name);
                if a == b {
                    vec![a]
                } else {
                    vec![a, b]
                }
            };
            for k in keys {
                by_name.entry(k).or_default().push(n.clone());
            }
        }

        for list in by_alias.values_mut().chain(by_name.values_mut()) {
            list.sort_by(|a, b| compare_utf8(&a.path, &b.path));
        }

        Self {
            by_path,
            by_alias,
            by_name,
        }
    }

    fn try_path(&self, candidate: Option<String>) -> Option<&ResolvableNode> {
        let candidate = candidate?;
        for ext in LINK_EXTENSIONS {
            if let Some(hit) = self.by_path.get(&format!("{candidate}{ext}")) {
                return Some(hit);
            }
        }
        None
    }

    /// Resolve one target (§9.2).
    ///
    /// The step order is the whole point: rooted beats relative, relative
    /// beats vault-root, and only then do the forgiving name-based steps run.
    /// Steps 1-3 are case-sensitive and 4-5 are not, because a path-shaped
    /// target means exactly what it says while a name-shaped one is how
    /// people type.
    pub fn resolve(&self, from_path: &str, raw_target: &str) -> Resolution {
        let target = nfc(raw_target).into_owned();

        let unresolved = || Resolution {
            path: None,
            id: None,
            by: ResolvedBy::Unresolved,
            ambiguous: false,
            candidates: Vec::new(),
        };
        let hit = |n: &ResolvableNode, by| Resolution {
            path: Some(n.path.clone()),
            id: Some(n.id.clone()),
            by,
            ambiguous: false,
            candidates: Vec::new(),
        };

        // 1. Rooted path. A rooted target never falls through to the forgiving
        //    steps: `/columns` means that path and nothing else.
        if let Some(rest) = target.strip_prefix('/') {
            return match self.try_path(resolve_rooted(rest)) {
                Some(n) => hit(n, ResolvedBy::RootedPath),
                None => unresolved(),
            };
        }

        // 2. Exact relative path.
        if let Some(n) = self.try_path(resolve_relative(from_path, &target)) {
            return hit(n, ResolvedBy::RelativePath);
        }

        // 3. Exact vault-root path.
        if let Some(n) = self.try_path(resolve_rooted(&target)) {
            return hit(n, ResolvedBy::VaultRootPath);
        }

        // 4. Alias, case-insensitive.
        if let Some(list) = self.by_alias.get(&fold_case(&target)) {
            return pick(list, ResolvedBy::Alias);
        }

        // 5. Unique basename, case-insensitive — stem or full basename.
        if let Some(list) = self.by_name.get(&fold_case(&target)) {
            return pick(list, ResolvedBy::UniqueBasename);
        }

        // 6. Unresolved.
        unresolved()
    }
}

/// Choose among several name matches.
///
/// §9.2 requires a deterministic tiebreak — bytewise-first path — and requires
/// the ambiguity be reported rather than hidden, so the author can fix the
/// real problem instead of wondering which note the link means.
fn pick(hits: &[ResolvableNode], by: ResolvedBy) -> Resolution {
    let first = &hits[0];
    Resolution {
        path: Some(first.path.clone()),
        id: Some(first.id.clone()),
        by,
        ambiguous: hits.len() > 1,
        candidates: if hits.len() > 1 {
            hits.iter().map(|n| n.id.clone()).collect()
        } else {
            Vec::new()
        },
    }
}

/// True when an anchor resolves against a node's headings or block ids (§9.3).
///
/// A heading anchor that matches nothing does NOT make the edge unresolved —
/// the node resolved; only the fragment did not.
pub fn anchor_resolves(anchor: Option<&str>, headings: &[Heading], block_ids: &[String]) -> bool {
    let Some(anchor) = anchor else { return true };
    match anchor.strip_prefix('^') {
        Some(id) => block_ids.iter().any(|b| b == id),
        None => {
            let want = slugify(anchor);
            headings.iter().any(|h| h.slug == want)
        }
    }
}

// --------------------------------------------------------- data objects

const LINK_KEYS: [&str; 6] = ["link", "links", "ref", "refs", "href", "url"];

fn whole_wiki_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^!?\[\[([^\[\]]+)\]\]$").unwrap())
}

/// Links inside data objects (§9.4).
///
/// String *values* only, never keys: scanning keys would turn a dataset's
/// column names into edges. A value that is entirely a wikilink is an edge,
/// and so is any value under a key named `link`, `links`, `ref`, `refs`,
/// `href` or `url`.
pub fn extract_data_links(text: &str, path: &str) -> Vec<RawEdge> {
    let parsed: Option<serde_yaml_ng::Value> = if path.ends_with(".json") {
        // JSON is a subset of YAML 1.2, so one parser serves both, and a
        // `.json` file that is really YAML still yields its links.
        serde_yaml_ng::from_str(text).ok()
    } else {
        serde_yaml_ng::from_str(text).ok()
    };
    let Some(doc) = parsed else {
        return Vec::new();
    };

    let mut out = Vec::new();
    walk_data(&doc, None, &mut out);
    out
}

fn walk_data(value: &serde_yaml_ng::Value, key_name: Option<&str>, out: &mut Vec<RawEdge>) {
    use serde_yaml_ng::Value as Y;
    match value {
        Y::String(s) => {
            if let Some(m) = whole_wiki_re().captures(s) {
                let body = m.get(1).unwrap().as_str();
                let target = body
                    .split('|')
                    .next()
                    .unwrap_or("")
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !target.is_empty() {
                    out.push(RawEdge {
                        kind: EdgeKind::Wiki,
                        raw: nfc(target).into_owned(),
                        alias: None,
                        anchor: None,
                        offset: 0,
                        line: 1,
                        col: 1,
                    });
                }
            } else if key_name.is_some_and(|k| LINK_KEYS.contains(&k)) {
                out.push(RawEdge {
                    kind: if scheme_re().is_match(s) {
                        EdgeKind::External
                    } else {
                        EdgeKind::Md
                    },
                    raw: nfc(s).into_owned(),
                    alias: None,
                    anchor: None,
                    offset: 0,
                    line: 1,
                    col: 1,
                });
            }
        }
        Y::Sequence(seq) => {
            for v in seq {
                walk_data(v, key_name, out);
            }
        }
        Y::Mapping(map) => {
            for (k, v) in map {
                walk_data(v, k.as_str(), out);
            }
        }
        _ => {}
    }
}
