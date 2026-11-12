//! Editing YAML a human may have written, without reserializing it.
//!
//! §13.4 requires comments, key order and quoting to survive when an
//! implementation edits YAML it did not author, and serde does not keep
//! comments. So the two edits a write makes — stamping a note's `basalt:`
//! block (§4.3, §12.7) and adding an entry to a folder's sidecar (§6.1) — are
//! splices on lines of text: the lines this crate owns are replaced or added,
//! and every other byte stays where the author put it. Each result is parsed
//! back before it is returned, so a splice that went wrong is a refusal
//! rather than a corrupted file.

use serde_yaml_ng::{Mapping, Value as Yaml};

/// A value this crate writes: a string or a nested mapping, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    Str(String),
    Map(Vec<(String, Out)>),
}

impl Out {
    pub fn map() -> Vec<(String, Out)> {
        Vec::new()
    }
}

/// A parsed value as one this module can write back: strings (and other
/// scalars, as their text) and mappings. Sequences have no `Out` form.
pub fn from_yaml(v: &Yaml) -> Option<Out> {
    match v {
        Yaml::Mapping(m) => Some(Out::Map(
            m.iter()
                .filter_map(|(k, v)| Some((k.as_str()?.to_string(), from_yaml(v)?)))
                .collect(),
        )),
        Yaml::String(s) => Some(Out::Str(s.clone())),
        Yaml::Bool(b) => Some(Out::Str(b.to_string())),
        Yaml::Number(n) => Some(Out::Str(n.to_string())),
        _ => None,
    }
}

const KEYWORDS: [&str; 13] = [
    "true", "false", "null", "yes", "no", "on", "off", "y", "n", "~", "nan", "inf", "",
];

fn plain_ok(s: &str, extra: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._/-".contains(c) || extra.contains(c))
        && !s.contains("::")
        && !s.ends_with(':')
        && !KEYWORDS.contains(&s.to_ascii_lowercase().as_str())
}

/// A string as a YAML scalar: plain when that cannot be misread, else double
/// quoted (§13.4 prefers double quotes). Control characters and the Unicode
/// line separators are escaped, so no value can start a line of its own.
pub fn scalar(s: &str) -> String {
    // A ULID (§4.1) may start with a digit, but its letters keep any YAML
    // reader from taking it for a number, so ids are written as minting
    // always has written them.
    if plain_ok(s, ":") || crate::frontmatter::is_ulid(s) && s.bytes().any(|b| b.is_ascii_alphabetic()) {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            '\u{2028}' => out.push_str("\\L"),
            '\u{2029}' => out.push_str("\\P"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A mapping key: plain for an ordinary filename, quoted otherwise.
pub fn key(s: &str) -> String {
    let plain = s
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
        && s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !KEYWORDS.contains(&s.to_ascii_lowercase().as_str());
    if plain {
        s.to_string()
    } else {
        scalar_quoted(s)
    }
}

fn scalar_quoted(s: &str) -> String {
    let q = scalar(s);
    if q.starts_with('"') {
        q
    } else {
        format!("\"{q}\"")
    }
}

/// Render `key: value` lines at `indent` spaces.
pub fn render(entries: &[(String, Out)], indent: usize, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    for (k, v) in entries {
        match v {
            Out::Str(s) => out.push(format!("{pad}{}: {}", key(k), scalar(s))),
            Out::Map(m) => {
                out.push(format!("{pad}{}:", key(k)));
                render(m, indent + 2, out);
            }
        }
    }
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn is_blank_or_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.is_empty() || t.starts_with('#')
}

/// The text after `key:` on a top-level line, with any trailing comment
/// removed, or None when the line is not that key.
fn top_level_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(name)?.strip_prefix(':')?;
    if !(rest.is_empty() || rest.starts_with(' ') || rest.starts_with('\t')) {
        return None;
    }
    let rest = rest.trim();
    // A ` #` starts a comment; one inside a quoted scalar would need a real
    // parser, and the values seen here are mappings or nothing.
    let rest = match rest.find(" #") {
        Some(i) => rest[..i].trim_end(),
        None if rest.starts_with('#') => "",
        None => rest,
    };
    Some(rest)
}

/// The end (exclusive) of the block under the top-level key on `start`: the
/// next line at column 0 that is not blank and not a comment.
fn block_end(lines: &[String], start: usize) -> usize {
    lines[start + 1..]
        .iter()
        .position(|l| !is_blank_or_comment(l) && indent_of(l) == 0)
        .map(|p| start + 1 + p)
        .unwrap_or(lines.len())
}

/// The indent of a block's children, from its first one; `fallback` if none.
fn child_indent(lines: &[String], start: usize, end: usize, fallback: usize) -> usize {
    lines[start + 1..end]
        .iter()
        .find(|l| !is_blank_or_comment(l))
        .map(|l| indent_of(l))
        .filter(|&w| w > 0)
        .unwrap_or(fallback)
}

/// Whether a child line at `indent` is the key `name`, written plain or quoted.
fn is_child_key(line: &str, indent: usize, name: &str) -> bool {
    if indent_of(line) != indent {
        return false;
    }
    let t = &line[indent..];
    [name.to_string(), key(name), format!("'{name}'"), format!("\"{name}\"")]
        .iter()
        .any(|k| {
            t.strip_prefix(k.as_str())
                .and_then(|r| r.strip_prefix(':'))
                .is_some_and(|r| r.is_empty() || r.starts_with(' '))
        })
}

/// Remove the children named in `names` (each with its nested lines) from the
/// block `start..end`. Returns the new end.
fn remove_children(lines: &mut Vec<String>, start: usize, end: usize, indent: usize, names: &[&str]) -> usize {
    let mut end = end;
    let mut i = start + 1;
    while i < end {
        if names.iter().any(|n| is_child_key(&lines[i], indent, n)) {
            let mut j = i + 1;
            while j < end && (lines[j].trim().is_empty() || indent_of(&lines[j]) > indent) {
                j += 1;
            }
            // Keep blank lines that separated this child from the next.
            while j > i + 1 && lines[j - 1].trim().is_empty() {
                j -= 1;
            }
            lines.drain(i..j);
            end -= j - i;
        } else {
            i += 1;
        }
    }
    end
}

/// A parsed flow mapping on one line, re-rendered as block lines at `indent`,
/// without the keys in `drop`. serde writes it, so a comment cannot survive
/// — but a one-line flow mapping has nowhere to hold one except its end.
fn flow_to_block(value: &Yaml, indent: usize, drop: &[&str]) -> Result<Vec<String>, String> {
    let Some(m) = value.as_mapping() else {
        return Ok(Vec::new());
    };
    let mut kept = Mapping::new();
    for (k, v) in m {
        if k.as_str().is_some_and(|s| drop.contains(&s)) {
            continue;
        }
        kept.insert(k.clone(), v.clone());
    }
    if kept.is_empty() {
        return Ok(Vec::new());
    }
    let text = serde_yaml_ng::to_string(&Yaml::Mapping(kept)).map_err(|e| e.to_string())?;
    let pad = " ".repeat(indent);
    Ok(text
        .trim_end_matches('\n')
        .split('\n')
        .map(|l| format!("{pad}{l}"))
        .collect())
}

fn parse_mapping(text: &str, what: &str) -> Result<Option<Mapping>, String> {
    match serde_yaml_ng::from_str::<Yaml>(text) {
        Ok(Yaml::Mapping(m)) => Ok(Some(m)),
        Ok(Yaml::Null) => Ok(None),
        Ok(_) => Err(format!("{what} is not a YAML mapping")),
        Err(e) => Err(format!("{what} is not valid YAML: {e}")),
    }
}

/// Set a note's `basalt.id` (and, when given, `basalt.created_by`), and fill
/// in `title` if the author has none — the identity a new note is born with
/// (§4.3, §12.7). An `id` or `created_by` already in the block is replaced,
/// never kept: a supplied one would attach another node's identity, or let a
/// writer name its own author. `title` is the author's key, so it is only ever
/// added.
///
/// `raw` is the frontmatter block without its fences, or None when the note
/// has none. Returns the new block, without fences.
///
/// A one-line `basalt: {…}` can only be edited by rewriting it as a block.
/// `restyle_flow` allows that, for content arriving to be stored; a note
/// already in the vault (the minting pass) is refused instead, because §13.4
/// forbids silently restyling a human's YAML.
pub fn stamp_frontmatter(
    raw: Option<&str>,
    id: &str,
    title: Option<&str>,
    created_by: Option<&Out>,
    restyle_flow: bool,
) -> Result<String, String> {
    let mut ours = vec![("id".to_string(), Out::Str(id.to_string()))];
    if let Some(by) = created_by {
        ours.push(("created_by".to_string(), by.clone()));
    }

    let Some(raw) = raw else {
        let mut lines = vec!["basalt:".to_string()];
        render(&ours, 2, &mut lines);
        if let Some(t) = title {
            lines.push(format!("title: {}", scalar(t)));
        }
        return Ok(lines.join("\n"));
    };

    let parsed = parse_mapping(raw, "the frontmatter")?;
    let has_title = parsed
        .as_ref()
        .is_some_and(|m| m.contains_key(Yaml::String("title".into())));
    let mut lines: Vec<String> = raw.split('\n').map(str::to_string).collect();

    match lines.iter().position(|l| top_level_value(l, "basalt").is_some()) {
        None => {
            let mut head = vec!["basalt:".to_string()];
            render(&ours, 2, &mut head);
            lines.splice(0..0, head);
        }
        Some(at) => {
            let inline = top_level_value(&lines[at], "basalt").unwrap_or_default();
            if inline.is_empty() {
                let end = block_end(&lines, at);
                let ci = child_indent(&lines, at, end, 2);
                remove_children(&mut lines, at, end, ci, &["id", "created_by"]);
                let mut add = Vec::new();
                render(&ours, ci, &mut add);
                lines.splice(at + 1..at + 1, add);
            } else {
                // `basalt: {acl: …}` or `basalt: null`, on one line.
                if !restyle_flow {
                    return Err(format!(
                        "cannot add an id without rewriting the flow mapping on line {}; \
                         §13.4 forbids silently restyling a human's YAML",
                        at + 1
                    ));
                }
                if block_end(&lines, at) != at + 1 {
                    return Err("the basalt: block mixes a flow value with indented lines".into());
                }
                let value = parsed
                    .as_ref()
                    .and_then(|m| m.get(Yaml::String("basalt".into())))
                    .cloned()
                    .unwrap_or(Yaml::Null);
                if !(value.is_null() || value.is_mapping()) {
                    return Err("basalt: in the frontmatter is not a mapping".into());
                }
                let mut block = vec!["basalt:".to_string()];
                render(&ours, 2, &mut block);
                block.extend(flow_to_block(&value, 2, &["id", "created_by"])?);
                lines.splice(at..at + 1, block);
            }
        }
    }

    if let (Some(t), false) = (title, has_title) {
        while lines.last().is_some_and(|l| l.trim().is_empty()) {
            lines.pop();
        }
        lines.push(format!("title: {}", scalar(t)));
    }

    let out = lines.join("\n");
    // Checked, not assumed: the splice must parse and say what it was told to.
    let back = parse_mapping(&out, "the stamped frontmatter")?.unwrap_or_default();
    let got = back
        .get(Yaml::String("basalt".into()))
        .and_then(|b| b.get("id"))
        .and_then(|v| v.as_str());
    if got != Some(id) {
        return Err("could not set basalt.id without rewriting the author's YAML".into());
    }
    Ok(out)
}

/// Add (or replace) one entry in a folder's sidecar (§6.1), keeping every
/// other entry, comment and key order as it was. `existing` is the file's
/// text, or None when there is no sidecar yet.
pub fn add_sidecar_entry(existing: Option<&str>, name: &str, entry: &[(String, Out)]) -> Result<String, String> {
    let mut block = vec![format!("{}:", key(name))];
    render(entry, 2, &mut block);

    let text = existing.unwrap_or("");
    let parsed = parse_mapping(text, "the entries file")?;
    let mut lines: Vec<String> = text.trim_end_matches('\n').split('\n').map(str::to_string).collect();
    if text.trim().is_empty() {
        lines.clear();
    }

    match lines.iter().position(|l| top_level_value(l, "entries").is_some()) {
        None => {
            lines.push("entries:".into());
            lines.extend(block.iter().map(|l| format!("  {l}")));
        }
        Some(at) => {
            let inline = top_level_value(&lines[at], "entries").unwrap_or_default().to_string();
            if inline.is_empty() {
                let end = block_end(&lines, at);
                let ci = child_indent(&lines, at, end, 2);
                let end = remove_children(&mut lines, at, end, ci, &[name]);
                // After the block's last indented line, before any comments or
                // blank lines that lead into the next key.
                let mut insert = end;
                while insert > at + 1 && (is_blank_or_comment(&lines[insert - 1]) && indent_of(&lines[insert - 1]) == 0) {
                    insert -= 1;
                }
                let pad = " ".repeat(ci);
                let step = if ci == 0 { 2 } else { ci };
                let mut add: Vec<String> = Vec::new();
                add.push(format!("{pad}{}", block[0]));
                let mut nested = Vec::new();
                render(entry, ci + step, &mut nested);
                add.extend(nested);
                lines.splice(insert..insert, add);
            } else {
                if block_end(&lines, at) != at + 1 {
                    return Err("entries: mixes a flow value with indented lines".into());
                }
                let value = parsed
                    .as_ref()
                    .and_then(|m| m.get(Yaml::String("entries".into())))
                    .cloned()
                    .unwrap_or(Yaml::Null);
                if !(value.is_null() || value.is_mapping()) {
                    return Err("entries: is not a mapping".into());
                }
                let mut replaced = vec!["entries:".to_string()];
                replaced.extend(flow_to_block(&value, 2, &[name])?);
                replaced.extend(block.iter().map(|l| format!("  {l}")));
                lines.splice(at..at + 1, replaced);
            }
        }
    }

    let out = format!("{}\n", lines.join("\n"));
    let back = parse_mapping(&out, "the updated entries file")?.unwrap_or_default();
    let id = entry.iter().find(|(k, _)| k == "id").map(|(_, v)| v);
    let got = back
        .get(Yaml::String("entries".into()))
        .and_then(|e| e.get(name))
        .and_then(|e| e.get("id"))
        .and_then(|v| v.as_str());
    if let Some(Out::Str(want)) = id {
        if got != Some(want.as_str()) {
            return Err("could not add the entry without rewriting the author's YAML".into());
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str) -> Vec<(String, Out)> {
        vec![("id".into(), Out::Str(id.into()))]
    }

    #[test]
    fn sidecar_keeps_comments_and_neighbours() {
        let before = "# hand-written\nentries:\n  # the diagram\n  diagram.png:\n    id: a\n    alt: x  # keep me\n";
        let out = add_sidecar_entry(Some(before), "photo.png", &entry("b")).unwrap();
        assert!(out.starts_with(before), "{out}");
        assert!(out.ends_with("  photo.png:\n    id: b\n"), "{out}");
    }

    #[test]
    fn sidecar_replaces_a_stale_entry_and_opens_a_flow_map() {
        let out = add_sidecar_entry(Some("entries:\n  a.png:\n    id: old\n  b.png:\n    id: keep\n"), "a.png", &entry("new")).unwrap();
        assert_eq!(out, "entries:\n  b.png:\n    id: keep\n  a.png:\n    id: new\n");
        let out = add_sidecar_entry(Some("entries: {}\n"), "a b.png", &entry("x")).unwrap();
        assert_eq!(out, "entries:\n  \"a b.png\":\n    id: x\n");
        let out = add_sidecar_entry(None, "a.png", &entry("x")).unwrap();
        assert_eq!(out, "entries:\n  a.png:\n    id: x\n");
    }

    #[test]
    fn frontmatter_replaces_supplied_identity_and_keeps_the_rest() {
        let raw = "# mine\nbasalt:\n  id: 01jbq100000000000000000002\n  aliases: [x]  # keep\n  created_by: {principal: u:carter}\ntitle: Mine";
        let by = Out::Map(vec![("agent".into(), Out::Str("claude-code".into()))]);
        let out = stamp_frontmatter(Some(raw), "01aaaaaaaaaaaaaaaaaaaaaaaa", Some("Theirs"), Some(&by), true).unwrap();
        assert_eq!(
            out,
            "# mine\nbasalt:\n  id: 01aaaaaaaaaaaaaaaaaaaaaaaa\n  created_by:\n    agent: claude-code\n  aliases: [x]  # keep\ntitle: Mine"
        );
    }

    #[test]
    fn frontmatter_from_nothing_and_from_flow() {
        let out = stamp_frontmatter(None, "01aaaaaaaaaaaaaaaaaaaaaaaa", Some("A: b"), None, true).unwrap();
        assert_eq!(out, "basalt:\n  id: 01aaaaaaaaaaaaaaaaaaaaaaaa\ntitle: \"A: b\"");
        let out = stamp_frontmatter(Some("basalt: {id: x, aliases: [y]}\ntags: [z]"), "01aaaaaaaaaaaaaaaaaaaaaaaa", None, None, true).unwrap();
        assert!(out.starts_with("basalt:\n  id: 01aaaaaaaaaaaaaaaaaaaaaaaa\n  aliases:"), "{out}");
        assert!(out.ends_with("tags: [z]"));
    }

    #[test]
    fn scalars_cannot_break_out_of_their_line() {
        assert_eq!(scalar("u:editor"), "u:editor");
        assert_eq!(scalar("0.1.0"), "\"0.1.0\"");
        assert_eq!(scalar("true"), "\"true\"");
        assert_eq!(scalar("a\nb: c"), "\"a\\nb: c\"");
        assert_eq!(scalar("arn:aws:iam::1:user/x"), "\"arn:aws:iam::1:user/x\"");
    }
}
