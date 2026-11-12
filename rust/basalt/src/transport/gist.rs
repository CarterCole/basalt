//! GitHub gist transport, PROTOCOL §1, plus the small GitHub client the gist
//! commands share.
//!
//! A gist is a flat set of non-empty text files, and a vault is a tree of
//! arbitrary blobs. The five operations still fit, as long as the mapping is
//! honest about what a gist cannot hold:
//!
//! - **Names are flat.** A key becomes one file name by escaping `%` as `%25`
//!   and `/` as `%2F` (`conformance/cases/gist/mapping.yaml`), so
//!   `content/Notes/A.md` is the file `content%2FNotes%2FA.md`. Reversible, and
//!   a gist someone made by hand with plain names reads back as it looks.
//! - **Content is text.** The API carries it as a JSON string, so a put of
//!   bytes that are not UTF-8, or an empty file, is refused rather than
//!   mangled.
//! - **It is small.** The API returns at most 300 files per gist, so a vault in
//!   a gist is for notes, not for a library.
//! - **Writes are not atomic.** A PATCH carries no precondition, so `if_match`
//!   is checked against a fresh read and two writers can still pass the check
//!   together. The `ConditionalPut` capability is therefore not claimed.
//!
//! Writes made inside a batch ([`crate::vault::Vault::batch`]) are held back
//! and sent as ONE PATCH, so `basalt add` is one gist revision, not one per
//! file. That is the place the git store makes its commit. A batch is for one
//! writer at a time per transport, as it is for the git store.
//!
//! The HTTP client is [`ureq`] with rustls: in-process, blocking, no curl and
//! no async runtime. The token is read from the environment and sent only to
//! the API host, over https (or to a loopback address, for tests). It is never
//! accepted on the command line, where it would land in shell history and
//! `ps`. The one subprocess anywhere in this module is the last-resort token
//! lookup, `gh auth token`, because a keyring login has no other way in.

use super::{
    BatchEnd, BatchInfo, Capability, ListOpts, Listing, PutMeta, Result, Stat, Transport,
    TransportError,
};
use crate::keys::validate_key;
use md5::{Digest as _, Md5};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_API: &str = "https://api.github.com";
/// The API shows no more than this many files of one gist.
pub const MAX_GIST_FILES: usize = 300;
const MAX_NAME_BYTES: usize = 255;
/// The largest response body read, API or raw file. A bound, not a promise.
const MAX_BODY: u64 = 128 * 1024 * 1024;

// ------------------------------------------------------------------- names

/// A vault path (or key) as a gist file name.
pub fn encode_name(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        match c {
            '%' => out.push_str("%25"),
            '/' => out.push_str("%2F"),
            c => out.push(c),
        }
    }
    out
}

/// A gist file name as a vault path. Only `%2F` and `%25` (either case of the
/// hex digit) mean anything, decoded in one left-to-right pass; every other
/// `%` is left alone.
pub fn decode_name(name: &str) -> String {
    let b = name.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            match (b[i + 1], b[i + 2]) {
                (b'2', b'F' | b'f') => {
                    out.push(b'/');
                    i += 3;
                    continue;
                }
                (b'2', b'5') => {
                    out.push(b'%');
                    i += 3;
                    continue;
                }
                _ => {}
            }
        }
        out.push(b[i]);
        i += 1;
    }
    // Only ASCII sequences were replaced by ASCII, so the bytes are still UTF-8.
    String::from_utf8(out).expect("decoding replaces ASCII with ASCII")
}

/// The gist id in whatever a person pasted: the id, the page URL, a clone URL.
/// `None` when there is none. A raw-file URL ends in a file name, which is not
/// an id, so it is refused rather than guessed at.
pub fn parse_gist_id(input: &str) -> Option<String> {
    let mut s = input.trim().to_string();
    if s.is_empty() {
        return None;
    }
    if let Some(i) = s.find(['#', '?']) {
        s.truncate(i);
    }
    if let Some(i) = s.find("://") {
        // A URL: its path. No path at all is no id.
        let rest = &s[i + 3..];
        s = match rest.find('/') {
            Some(p) => rest[p..].to_string(),
            None => String::new(),
        };
    } else if let Some(a) = s.find('@') {
        // scp-like clone address: user@host:ID.git
        if a > 0 && !s[..a].contains('/') {
            let rest = &s[a + 1..];
            if let Some(c) = rest.find(':') {
                if c > 0 && !rest[..c].contains('/') && c + 1 < rest.len() {
                    s = rest[c + 1..].to_string();
                }
            }
        }
    }
    let trimmed = s.trim_end_matches('/');
    let last = trimmed.rsplit('/').next().unwrap_or("");
    let last = last.strip_suffix(".git").unwrap_or(last);
    let ok = (5..=64).contains(&last.len()) && last.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then(|| last.to_ascii_lowercase())
}

/// Whether these bytes can be a gist file: non-blank UTF-8 with no NUL.
/// `None` when they can, otherwise why not (`empty` or `not_text`).
pub fn why_not_text(bytes: &[u8]) -> Option<&'static str> {
    if bytes.contains(&0) {
        return Some("not_text");
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Some("not_text");
    };
    // JavaScript's trim() is the other implementation's definition of blank:
    // it takes the byte-order mark and leaves U+0085 alone.
    let blank = text
        .chars()
        .all(|c| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}');
    blank.then_some("empty")
}

// --------------------------------------------------------------------- API

/// A failure talking to GitHub, with a stable `code`: `no_token`,
/// `unauthorized`, `not_found`, `rate_limited`, `forbidden`, `insecure_api`,
/// `network`, `http`, `too_big`, `bad_id`.
#[derive(Debug, Clone)]
pub struct GistError {
    pub code: &'static str,
    pub message: String,
    pub status: Option<u16>,
}

impl GistError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), status: None }
    }

    fn with_status(code: &'static str, message: impl Into<String>, status: u16) -> Self {
        Self { code, message: message.into(), status: Some(status) }
    }
}

impl fmt::Display for GistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for GistError {}

impl From<GistError> for TransportError {
    fn from(e: GistError) -> Self {
        TransportError::Backend(e.message)
    }
}

fn is_loopback(host: &str) -> bool {
    host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host.ends_with(".localhost")
}

/// `(scheme, host)` of an http(s) URL; the host keeps its brackets if IPv6.
fn scheme_and_host(url: &str) -> Option<(String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = if hostport.starts_with('[') {
        hostport.split_inclusive(']').next().unwrap_or(hostport)
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    (!host.is_empty()).then(|| (scheme.to_ascii_lowercase(), host.to_ascii_lowercase()))
}

/// The token to authenticate with: `GITHUB_TOKEN`, then `GH_TOKEN`, then
/// whatever the GitHub CLI has signed in (`gh auth token`), which is where a
/// keyring login lives. `None` when there is none: reading a gist works
/// without one, writing does not.
pub fn find_token() -> Option<String> {
    for name in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(v) = std::env::var(name) {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    gh_auth_token()
}

/// `gh auth token`, with five seconds to answer. `None` if `gh` is not
/// installed, not signed in, or too slow.
fn gh_auth_token() -> Option<String> {
    let mut child = Command::new("gh")
        .args(["auth", "token"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    if !status.success() {
        return None;
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    let t = out.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// One file of a gist, as the listing shows it.
#[derive(Debug, Clone)]
pub struct GistFile {
    pub size: u64,
    /// The listing cut the content short (over about 1 MB); fetch `raw_url`.
    pub truncated: bool,
    pub raw_url: Option<String>,
    /// The bytes, when the listing had them whole.
    pub content: Option<Vec<u8>>,
}

/// A gist as the rest of this code sees it.
#[derive(Debug, Clone)]
pub struct Gist {
    pub id: String,
    pub url: Option<String>,
    pub public: bool,
    pub description: String,
    pub updated_at: Option<String>,
    /// More files than the API will list.
    pub truncated: bool,
    pub files: BTreeMap<String, GistFile>,
}

fn shape(g: &Value) -> Gist {
    let mut files = BTreeMap::new();
    if let Some(obj) = g.get("files").and_then(Value::as_object) {
        for (name, f) in obj {
            if f.is_null() {
                continue;
            }
            let truncated = f.get("truncated").and_then(Value::as_bool).unwrap_or(false);
            let inline = f.get("content").and_then(Value::as_str);
            let size = f
                .get("size")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| inline.map_or(0, |c| c.len() as u64));
            files.insert(
                name.clone(),
                GistFile {
                    size,
                    truncated,
                    raw_url: f.get("raw_url").and_then(Value::as_str).map(str::to_string),
                    content: if truncated { None } else { inline.map(|c| c.as_bytes().to_vec()) },
                },
            );
        }
    }
    let text = |k: &str| g.get(k).and_then(Value::as_str).map(str::to_string);
    Gist {
        id: text("id").unwrap_or_default(),
        url: text("html_url"),
        public: g.get("public").and_then(Value::as_bool).unwrap_or(false),
        description: text("description").unwrap_or_default(),
        updated_at: text("updated_at"),
        truncated: g.get("truncated").and_then(Value::as_bool).unwrap_or(false),
        files,
    }
}

fn valid_id(id: &str) -> bool {
    (5..=64).contains(&id.len()) && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Clone, Copy)]
enum Method {
    Get,
    Post,
    Patch,
}

fn headers<B>(rb: ureq::RequestBuilder<B>, auth: Option<&str>) -> ureq::RequestBuilder<B> {
    let rb = rb
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", "2022-11-28");
    match auth {
        Some(a) => rb.header("authorization", a),
        None => rb,
    }
}

/// The GitHub client: one gist at a time, over the REST API.
pub struct GistApi {
    api_url: String,
    /// https, or a loopback host: the only places a token may be sent.
    secure_enough: bool,
    /// `None` until looked up; `Some(None)` is "looked, found none".
    token: Mutex<Option<Option<String>>>,
    agent: ureq::Agent,
    raw_agent: ureq::Agent,
}

impl GistApi {
    /// A client for `api_url` (else `GITHUB_API_URL`, else api.github.com).
    /// The token is looked up the first time it is needed ([`find_token`]).
    pub fn new(api_url: Option<&str>) -> std::result::Result<Self, GistError> {
        Self::build(api_url, None)
    }

    /// As [`GistApi::new`] with the token given: `None` means "no token", and
    /// the environment is not consulted.
    pub fn with_token(api_url: Option<&str>, token: Option<&str>) -> std::result::Result<Self, GistError> {
        Self::build(api_url, Some(token.map(str::to_string)))
    }

    fn build(api_url: Option<&str>, token: Option<Option<String>>) -> std::result::Result<Self, GistError> {
        let from_env = std::env::var("GITHUB_API_URL").ok().filter(|v| !v.is_empty());
        let url = api_url
            .map(str::to_string)
            .or(from_env)
            .unwrap_or_else(|| DEFAULT_API.to_string());
        let url = url.trim_end_matches('/').to_string();
        let (scheme, host) = scheme_and_host(&url)
            .filter(|(s, _)| s == "http" || s == "https")
            .ok_or_else(|| GistError::new("bad_url", format!("not an http(s) URL: {url}")))?;
        let loopback = is_loopback(&host);
        let agent_for = |secs: u64| {
            let mut cfg = ureq::Agent::config_builder()
                .http_status_as_error(false)
                .user_agent("basalt-vault")
                .timeout_global(Some(Duration::from_secs(secs)));
            // Never send a loopback request through a proxy from the environment.
            if loopback {
                cfg = cfg.proxy(None);
            }
            ureq::Agent::new_with_config(cfg.build())
        };
        Ok(Self {
            api_url: url,
            secure_enough: scheme == "https" || loopback,
            token: Mutex::new(token),
            agent: agent_for(30),
            raw_agent: agent_for(60),
        })
    }

    pub fn api_url(&self) -> &str {
        &self.api_url
    }

    fn token(&self) -> Option<String> {
        let mut t = self.token.lock().unwrap();
        t.get_or_insert_with(find_token).clone()
    }

    /// Whether a write could be signed. Cheap after the first call.
    pub fn can_write(&self) -> bool {
        self.token().is_some() && self.secure_enough
    }

    fn call(&self, method: Method, path: &str, body: Option<Value>, write: bool) -> std::result::Result<Value, GistError> {
        let token = self.token();
        if write && token.is_none() {
            return Err(GistError::new(
                "no_token",
                "writing a gist needs a GitHub token with the gist scope: set GITHUB_TOKEN \
                 (or GH_TOKEN), or sign in with `gh auth login`",
            ));
        }
        let mut auth = None;
        if let Some(t) = &token {
            if self.secure_enough {
                auth = Some(format!("Bearer {t}"));
            } else if write {
                return Err(GistError::new(
                    "insecure_api",
                    format!("{} is not https, so the token will not be sent to it", self.api_url),
                ));
            }
            // A read of a public or secret gist needs no token; leave it off.
        }

        let url = format!("{}{path}", self.api_url);
        let payload = body.map(|b| b.to_string());
        let sent = match method {
            Method::Get => headers(self.agent.get(&url), auth.as_deref()).call(),
            Method::Post => headers(self.agent.post(&url), auth.as_deref())
                .header("content-type", "application/json")
                .send(payload.unwrap_or_default()),
            Method::Patch => headers(self.agent.patch(&url), auth.as_deref())
                .header("content-type", "application/json")
                .send(payload.unwrap_or_default()),
        };
        let mut res = sent.map_err(|e| GistError::new("network", format!("could not reach {}: {e}", self.api_url)))?;
        let status = res.status().as_u16();
        let header = |name: &str| {
            res.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_string)
        };
        let limited = header("x-ratelimit-remaining").as_deref() == Some("0");
        let reset = header("x-ratelimit-reset").and_then(|v| v.parse::<u64>().ok()).filter(|&r| r > 0);
        let bytes = res
            .body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| GistError::new("network", format!("could not read the answer from {}: {e}", self.api_url)))?;
        let json: Option<Value> = serde_json::from_slice(&bytes).ok();

        if (200..300).contains(&status) {
            if status == 204 {
                return Ok(Value::Null);
            }
            return json.ok_or_else(|| GistError::with_status("http", "GitHub sent an answer that is not JSON", status));
        }

        let detail = json
            .as_ref()
            .and_then(|j| j.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let with_detail = |d: &str| if d.is_empty() { String::new() } else { format!(": {d}") };
        Err(match status {
            404 => GistError::with_status(
                "not_found",
                if token.is_some() {
                    "gist not found (or this token has no access to it)"
                } else {
                    "gist not found (or it is private to an account: set GITHUB_TOKEN)"
                },
                404,
            ),
            401 => GistError::with_status(
                "unauthorized",
                format!("GitHub rejected the token{}", with_detail(&detail)),
                401,
            ),
            429 | 403 if status == 429 || limited => {
                let mut m = String::from("GitHub rate limit reached");
                if let Some(r) = reset {
                    m.push_str(&format!("; resets {}", super::fs::rfc3339(r)));
                }
                if token.is_none() {
                    m.push_str(" (unauthenticated requests get far fewer: set GITHUB_TOKEN)");
                }
                GistError::with_status("rate_limited", m, status)
            }
            403 => GistError::with_status(
                "forbidden",
                format!(
                    "GitHub refused: {}{}",
                    if detail.is_empty() { "forbidden" } else { &detail },
                    if write { " (the token needs the gist scope)" } else { "" }
                ),
                403,
            ),
            _ => GistError::with_status(
                "http",
                format!("GitHub answered {status}{}", with_detail(&detail)),
                status,
            ),
        })
    }

    /// One gist, with the files it shows inline.
    pub fn get(&self, id: &str) -> std::result::Result<Gist, GistError> {
        if !valid_id(id) {
            return Err(GistError::new("bad_id", format!("not a gist id: {id}")));
        }
        Ok(shape(&self.call(Method::Get, &format!("/gists/{id}"), None, false)?))
    }

    /// Create a gist. `files` maps a file name to its text. Secret unless `public`.
    pub fn create(
        &self,
        files: &BTreeMap<String, String>,
        description: &str,
        public: bool,
    ) -> std::result::Result<Gist, GistError> {
        let mut f = Map::new();
        for (name, content) in files {
            f.insert(name.clone(), json!({ "content": content }));
        }
        let body = json!({ "description": description, "public": public, "files": f });
        Ok(shape(&self.call(Method::Post, "/gists", Some(body), true)?))
    }

    /// Change a gist: a file name mapped to text sets it, mapped to `None`
    /// removes it. One request, so one revision.
    pub fn update(
        &self,
        id: &str,
        files: &BTreeMap<String, Option<String>>,
        description: Option<&str>,
    ) -> std::result::Result<Gist, GistError> {
        if !valid_id(id) {
            return Err(GistError::new("bad_id", format!("not a gist id: {id}")));
        }
        let mut body = Map::new();
        if let Some(d) = description {
            body.insert("description".into(), json!(d));
        }
        let mut f = Map::new();
        for (name, content) in files {
            f.insert(
                name.clone(),
                match content {
                    Some(c) => json!({ "content": c }),
                    None => Value::Null,
                },
            );
        }
        body.insert("files".into(), Value::Object(f));
        Ok(shape(&self.call(Method::Patch, &format!("/gists/{id}"), Some(Value::Object(body)), true)?))
    }

    /// A file the listing cut short (over about 1 MB). The raw host is not the
    /// API host, so the token is not sent there: a secret gist is readable by
    /// anyone holding its URL, and a token has no business on another origin.
    pub fn raw(&self, url: &str) -> std::result::Result<Vec<u8>, GistError> {
        let mut res = self
            .raw_agent
            .get(url)
            .call()
            .map_err(|e| GistError::new("network", format!("could not fetch {url}: {e}")))?;
        let status = res.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(GistError::with_status("http", format!("fetching {url} answered {status}"), status));
        }
        res.body_mut()
            .with_config()
            .limit(MAX_BODY)
            .read_to_vec()
            .map_err(|e| GistError::new("network", format!("could not fetch {url}: {e}")))
    }

    /// A file's full bytes: inline when the listing had them, else fetched.
    pub fn content(&self, file: &GistFile) -> std::result::Result<Vec<u8>, GistError> {
        if let Some(c) = &file.content {
            return Ok(c.clone());
        }
        match &file.raw_url {
            Some(u) => self.raw(u),
            None => Err(GistError::new("http", "the gist did not say where to fetch a truncated file")),
        }
    }
}

// --------------------------------------------------------------- transport

fn md5_etag(bytes: &[u8]) -> String {
    format!("\"{}\"", crate::order::hex(&Md5::digest(bytes)))
}

/// A held-back write: bytes to set, or `None` to remove.
type Held = BTreeMap<String, Option<Vec<u8>>>;

#[derive(Default)]
struct State {
    gist: Option<Gist>,
    fetched: Option<Instant>,
    /// Writes held back by a batch; `None` outside one.
    pending: Option<Held>,
    depth: usize,
}

/// Every key of a gist, by the name a vault knows it under, with the name the
/// gist has for it (a file written by hand may spell it oddly).
fn keyed(g: &Gist) -> BTreeMap<String, (&String, &GistFile)> {
    g.files.iter().map(|(name, f)| (decode_name(name), (name, f))).collect()
}

pub struct GistTransport {
    id: String,
    api: GistApi,
    ttl: Duration,
    caps: BTreeSet<Capability>,
    state: Mutex<State>,
}

impl GistTransport {
    /// `id` is a gist id or URL. Reads are reused for 30 seconds, since they
    /// cost API calls (60 an hour without a token); a batch always reads fresh.
    pub fn new(id: &str, api: GistApi) -> std::result::Result<Self, GistError> {
        let parsed = parse_gist_id(id)
            .ok_or_else(|| GistError::new("bad_id", format!("not a gist id or URL: {id}")))?;
        Ok(Self {
            id: parsed,
            api,
            ttl: Duration::from_secs(30),
            // Nothing a gist offers maps to a capability of §3.1: no presign,
            // no conditional put (see the module docs), no ranges, no batch
            // delete.
            caps: BTreeSet::new(),
            state: Mutex::new(State::default()),
        })
    }

    /// How long a read of the gist is reused. Zero reads on every operation.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// The gist's page, once read; the canonical address before that.
    pub fn url(&self) -> String {
        let st = self.state.lock().unwrap();
        st.gist
            .as_ref()
            .and_then(|g| g.url.clone())
            .unwrap_or_else(|| format!("https://gist.github.com/{}", self.id))
    }

    /// Read the gist now, and refuse one too big for the API to show whole.
    pub fn ready(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        self.refresh(&mut st)
    }

    fn refresh(&self, st: &mut State) -> Result<()> {
        let g = self.api.get(&self.id)?;
        if g.truncated {
            return Err(GistError::new(
                "too_big",
                format!(
                    "gist {} has more than {MAX_GIST_FILES} files, which the API will not list; \
                     clone it with git instead, or split it",
                    self.id
                ),
            )
            .into());
        }
        st.gist = Some(g);
        st.fetched = Some(Instant::now());
        Ok(())
    }

    /// Make sure there is a read of the gist, and that it is not stale.
    fn view(&self, st: &mut State) -> Result<()> {
        let fresh = matches!(st.fetched, Some(t) if t.elapsed() <= self.ttl);
        if st.gist.is_none() || !fresh {
            self.refresh(st)?;
        }
        Ok(())
    }

    /// The bytes and stat of one key as it will be once the held-back writes
    /// land, or `None`.
    fn lookup(&self, st: &mut State, key: &str) -> Result<Option<(Vec<u8>, Option<String>)>> {
        self.view(st)?;
        if let Some(held) = &st.pending {
            if let Some(v) = held.get(key) {
                return Ok(v.clone().map(|b| (b, st.gist.as_ref().and_then(|g| g.updated_at.clone()))));
            }
        }
        let g = st.gist.as_ref().expect("view reads the gist");
        match keyed(g).get(key) {
            Some((_, f)) => Ok(Some((self.api.content(f)?, g.updated_at.clone()))),
            None => Ok(None),
        }
    }

    /// Send held writes as one PATCH, leaving out what would change nothing.
    /// Returns whether a request went out.
    fn send(&self, st: &mut State, writes: Held) -> Result<bool> {
        if writes.is_empty() {
            return Ok(false);
        }
        if st.gist.is_none() {
            self.refresh(st)?;
        }
        let g = st.gist.as_ref().expect("just read");
        let by_key = keyed(g);
        let mut files: BTreeMap<String, Option<String>> = BTreeMap::new();
        for (key, v) in &writes {
            let had = by_key.get(key);
            match v {
                None => {
                    if let Some((name, _)) = had {
                        files.insert((*name).clone(), None);
                    }
                }
                Some(bytes) => {
                    if let Some((_, f)) = had {
                        if f.content.as_deref() == Some(bytes.as_slice()) {
                            continue;
                        }
                    }
                    // Reuse the name the gist already has, so a file written
                    // by hand under an odd spelling is updated and not
                    // duplicated beside it.
                    let name = had.map(|(n, _)| (*n).clone()).unwrap_or_else(|| encode_name(key));
                    // put() checked it is UTF-8 before holding it.
                    let text = String::from_utf8(bytes.clone())
                        .map_err(|_| TransportError::Backend(format!("{key} is not UTF-8 text")))?;
                    files.insert(name, Some(text));
                }
            }
        }
        if files.is_empty() {
            return Ok(false);
        }
        let added = files
            .iter()
            .filter(|(n, c)| c.is_some() && !g.files.contains_key(*n))
            .count();
        let removed = files.values().filter(|c| c.is_none()).count();
        let after = g.files.len() + added - removed;
        if after > MAX_GIST_FILES {
            return Err(GistError::new(
                "too_big",
                format!("that would make {after} files in the gist; the API shows {MAX_GIST_FILES}"),
            )
            .into());
        }
        let updated = self.api.update(&self.id, &files, None)?;
        st.gist = Some(updated);
        st.fetched = Some(Instant::now());
        Ok(true)
    }
}

impl Transport for GistTransport {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut st = self.state.lock().unwrap();
        Ok(self.lookup(&mut st, key)?.map(|(b, _)| b))
    }

    fn stat(&self, key: &str) -> Result<Option<Stat>> {
        let mut st = self.state.lock().unwrap();
        Ok(self.lookup(&mut st, key)?.map(|(b, mtime)| Stat {
            size: b.len() as u64,
            etag: Some(md5_etag(&b)),
            mtime,
        }))
    }

    fn list(&self, prefix: &str, opts: &ListOpts) -> Result<Listing> {
        let mut st = self.state.lock().unwrap();
        self.view(&mut st)?;
        let g = st.gist.as_ref().expect("view reads the gist");
        let mut names: BTreeSet<String> = g.files.keys().map(|n| decode_name(n)).collect();
        if let Some(held) = &st.pending {
            for (key, v) in held {
                if v.is_some() {
                    names.insert(key.clone());
                } else {
                    names.remove(key);
                }
            }
        }
        let mut keys = Vec::new();
        let mut prefixes = BTreeSet::new();
        for key in names {
            if !key.starts_with(prefix) {
                continue;
            }
            if let Some(d) = opts.delimiter {
                if let Some(i) = key[prefix.len()..].find(d) {
                    prefixes.insert(format!("{prefix}{}", &key[prefix.len()..prefix.len() + i + d.len_utf8()]));
                    continue;
                }
            }
            keys.push(key);
        }
        Ok(Listing { keys, prefixes: prefixes.into_iter().collect(), cursor: None })
    }

    fn put(&self, key: &str, bytes: &[u8], meta: &PutMeta) -> Result<Stat> {
        validate_key(key)?;
        if let Some(why) = why_not_text(bytes) {
            return Err(TransportError::Backend(format!(
                "a gist holds non-empty text files only; {key} is {}. Keep it in a folder or git store.",
                if why == "empty" { "empty" } else { "not UTF-8 text" }
            )));
        }
        let name = encode_name(key);
        if name.len() > MAX_NAME_BYTES {
            return Err(TransportError::Backend(format!(
                "{key} makes a gist file name longer than {MAX_NAME_BYTES} bytes"
            )));
        }

        let mut st = self.state.lock().unwrap();
        if let Some(want) = &meta.if_match {
            // Fresh outside a batch (a batch read fresh when it began): the
            // check is only as good as that read, and a gist has no way to
            // make it atomic.
            if st.pending.is_none() {
                self.refresh(&mut st)?;
            }
            let have = self.lookup(&mut st, key)?.map(|(b, _)| md5_etag(&b));
            if &have != want {
                return Err(TransportError::PreconditionFailed(key.to_string()));
            }
        }

        if let Some(held) = st.pending.as_mut() {
            held.insert(key.to_string(), Some(bytes.to_vec()));
            return Ok(Stat {
                size: bytes.len() as u64,
                etag: Some(md5_etag(bytes)),
                mtime: Some(super::fs::now_rfc3339()),
            });
        }
        let mut one = Held::new();
        one.insert(key.to_string(), Some(bytes.to_vec()));
        self.send(&mut st, one)?;
        drop(st);
        Ok(self.stat(key)?.unwrap_or(Stat { size: bytes.len() as u64, etag: Some(md5_etag(bytes)), mtime: None }))
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if let Some(held) = st.pending.as_mut() {
            held.insert(key.to_string(), None);
            return Ok(());
        }
        let mut one = Held::new();
        one.insert(key.to_string(), None);
        self.send(&mut st, one)?;
        Ok(())
    }

    fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.caps
    }

    /// Group writes into one PATCH, one revision of the gist. Nested batches
    /// join the outer one, and the writes go out when the outermost ends.
    fn begin_batch(&self) -> Result<()> {
        let mut st = self.state.lock().unwrap();
        if st.depth > 0 {
            st.depth += 1;
            return Ok(());
        }
        // A fresh read to write against; if it fails, no batch has begun.
        self.refresh(&mut st)?;
        st.pending = Some(Held::new());
        st.depth = 1;
        Ok(())
    }

    /// Finish the innermost batch. The outermost sends what was held, even if
    /// the work in it failed part-way, because what was written is still wanted.
    fn end_batch(&self, _info: &BatchInfo) -> Result<BatchEnd> {
        let mut st = self.state.lock().unwrap();
        if st.depth == 0 {
            return Ok(BatchEnd::default());
        }
        st.depth -= 1;
        if st.depth > 0 {
            return Ok(BatchEnd::default());
        }
        let held = st.pending.take().unwrap_or_default();
        let committed = self.send(&mut st, held)?;
        Ok(BatchEnd { committed, rederive: false })
    }
}
