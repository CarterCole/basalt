//! Canonical JSON serialization, PROTOCOL §13.1.
//!
//! Index objects must be byte-identical across implementations, which rules
//! out every general-purpose JSON writer: they disagree about key order, about
//! how an empty container is indented, and about whether U+2028/U+2029 are
//! escaped (legal JSON unescaped, but they break the moment the bytes are
//! embedded in a `<script>` tag).
//!
//! The value type here is deliberately small. §13.1 bans non-integer numbers
//! from index objects outright, so there is no float variant to format and no
//! float-formatting disagreement to have.

use crate::order::nfc;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    /// `BTreeMap<String, _>` is not an implementation detail: Rust orders
    /// `String` by UTF-8 bytes, which is exactly §13.3, so the map *is* the
    /// key-sorting rule. Keys are NFC-normalized on the way in.
    Object(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> JsonObject {
        JsonObject(BTreeMap::new())
    }

    pub fn str(s: impl AsRef<str>) -> Json {
        Json::Str(nfc(s.as_ref()).into_owned())
    }

    pub fn arr<I: IntoIterator<Item = Json>>(items: I) -> Json {
        Json::Array(items.into_iter().collect())
    }

    pub fn strings<I, S>(items: I) -> Json
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Json::Array(items.into_iter().map(Json::str).collect())
    }

    /// A string, or `null` for None — the shape §10.1 and §10.2 use for
    /// `id`, `to`, `alias` and `anchor`.
    pub fn opt_str(s: Option<impl AsRef<str>>) -> Json {
        match s {
            Some(v) => Json::str(v),
            None => Json::Null,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut BTreeMap<String, Json>> {
        match self {
            Json::Object(m) => Some(m),
            _ => None,
        }
    }

    /// Serialize to canonical JSON text: two-space indent, LF endings,
    /// exactly one trailing newline.
    pub fn to_canonical_string(&self) -> String {
        let mut out = String::new();
        write_value(self, 0, &mut out);
        out.push('\n');
        out
    }

    /// Canonical JSON as UTF-8 bytes, ready for a transport `put`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        self.to_canonical_string().into_bytes()
    }

    /// Strip the fields §13.2 excludes from cross-implementation comparison:
    /// `generated`, which legitimately differs between two runs, and the
    /// per-entry `etag`, which legitimately differs between two stores.
    pub fn comparable(&self) -> Json {
        let mut c = self.clone();
        if let Json::Object(m) = &mut c {
            m.remove("generated");
            if let Some(Json::Array(entries)) = m.get_mut("entries") {
                for e in entries {
                    if let Json::Object(eo) = e {
                        eo.remove("etag");
                    }
                }
            }
        }
        c
    }
}

/// A small builder, so index construction reads as a list of fields rather
/// than as map insertions.
pub struct JsonObject(BTreeMap<String, Json>);

impl JsonObject {
    pub fn set(mut self, key: &str, value: Json) -> Self {
        self.0.insert(nfc(key).into_owned(), value);
        self
    }
    pub fn build(self) -> Json {
        Json::Object(self.0)
    }
}

fn write_value(value: &Json, depth: usize, out: &mut String) {
    match value {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Int(i) => out.push_str(&i.to_string()),
        Json::Str(s) => quote(s, out),
        Json::Array(items) => {
            if items.is_empty() {
                out.push_str("[]"); // §13.1: empty arrays as `[]`, not `[\n]`.
                return;
            }
            out.push_str("[\n");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                indent(depth + 1, out);
                write_value(item, depth + 1, out);
            }
            out.push('\n');
            indent(depth, out);
            out.push(']');
        }
        Json::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push_str(",\n");
                }
                indent(depth + 1, out);
                quote(k, out);
                out.push_str(": ");
                write_value(v, depth + 1, out);
            }
            out.push('\n');
            indent(depth, out);
            out.push('}');
        }
    }
}

fn indent(depth: usize, out: &mut String) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

/// Quote a string per §13.1: escape only what JSON requires, plus U+2028 and
/// U+2029. Every other non-ASCII character is emitted literally.
fn quote(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{2028}' || c == '\u{2029}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse canonical (or any) JSON back into [`Json`].
///
/// Needed because the self-check in §14.3 has to compare a stored index
/// against a freshly built one, and the stored bytes are the only input it
/// gets. Rejects non-integer numbers, which §13.1 bans from index objects, so
/// a float in a stored index is a loud failure rather than a silent rounding.
pub fn parse_json(text: &str) -> Result<Json, String> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(format!("trailing input at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        if self.i < self.b.len() && self.b[self.i] == c {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.b.get(self.i) {
            None => Err("unexpected end of input".into()),
            Some(b'n') => self.lit("null", Json::Null),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(_) => self.number(),
        }
    }

    fn lit(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad literal at byte {}", self.i))
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.eat(b'[')?;
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Array(out));
        }
        loop {
            self.ws();
            out.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Array(out));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.eat(b'{')?;
        let mut map = BTreeMap::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            map.insert(k, self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Object(map));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.eat(b'"')?;
        let mut out = String::new();
        loop {
            let c = *self
                .b
                .get(self.i)
                .ok_or_else(|| "unterminated string".to_string())?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = *self
                        .b
                        .get(self.i)
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        other => return Err(format!("bad escape \\{}", other as char)),
                    }
                }
                _ => {
                    // Copy the whole UTF-8 sequence this byte starts.
                    let len = utf8_len(c);
                    let end = self.i - 1 + len;
                    let s = std::str::from_utf8(&self.b[self.i - 1..end])
                        .map_err(|e| format!("invalid UTF-8: {e}"))?;
                    out.push_str(s);
                    self.i = end;
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.hex4()?;
        if (0xd800..0xdc00).contains(&hi) {
            // A surrogate pair, which is how a JSON writer that escapes
            // everything spells an astral character. Accept it on read even
            // though §13.1 forbids writing it.
            if self.b.get(self.i) == Some(&b'\\') && self.b.get(self.i + 1) == Some(&b'u') {
                self.i += 2;
                let lo = self.hex4()?;
                let cp = 0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00);
                return char::from_u32(cp).ok_or_else(|| "bad surrogate pair".into());
            }
            return Err("lone high surrogate".into());
        }
        char::from_u32(hi).ok_or_else(|| "bad \\u escape".into())
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let s = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| "short \\u escape".to_string())?;
        let s = std::str::from_utf8(s).map_err(|_| "bad \\u escape".to_string())?;
        self.i += 4;
        u32::from_str_radix(s, 16).map_err(|_| "bad \\u escape".into())
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while self
            .b
            .get(self.i)
            .is_some_and(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
        {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number")?;
        s.parse::<i64>()
            .map(Json::Int)
            .map_err(|_| format!("§13.1 forbids non-integer numbers in index objects: {s}"))
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}
