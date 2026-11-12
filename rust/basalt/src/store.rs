//! Creating objects, PROTOCOL §12.7 — storing a note, an image or any other
//! file in a vault.
//!
//! Create-only on purpose. Replacing or deleting an object destroys work, and
//! §11 (history) is what makes that recoverable; until a vault has history,
//! the only write that cannot lose anything is one that refuses to touch an
//! object that already exists.
//!
//! What a store has to get right, in the order it happens:
//!
//! 1. The path must be one a reader can address: a valid key (§1.1), not a
//!    name the filesystem transport skips, not under a withheld tree (§12.4),
//!    and not colliding with anything already there (§2.2).
//! 2. The principal needs `create_child` on the folder (§8.1). A note that
//!    carries its own inline ACL also needs `write_acl`, because an inline ACL
//!    replaces the folder file's entry (§8.6).
//! 3. The object gets an identity at birth (§4.3): a frontmatter id for a
//!    note, an entry sidecar (§6.1) for anything else. The same place records
//!    who stored it (`created_by`).
//! 4. The indexes are rebuilt and persisted, so the vault is exactly as fresh
//!    after a store as before it.
//!
//! The conformance corpus holds the cases (`cases/store/creation.yaml`) and
//! every implementation that stores runs them.

use crate::frontmatter::{kind_for, parse_note, split_frontmatter, Kind};
use crate::keys::{
    basename, find_collisions, find_folder_case_divergence, parent_folder, path_to_key,
    validate_key, CONTENT, META,
};
use crate::serve::surface::{media_for, Surface};
use crate::transport::{BatchInfo, PutMeta, TransportError};
use crate::vault::{Vault, VaultError};
use crate::yamltext::{self, Out};
use sha2::{Digest, Sha256};
use std::fmt;

/// The largest object a store accepts. A bound, not a recommendation: over
/// MCP the same call arrives base64-encoded inside one JSON-RPC line.
pub const MAX_STORE_BYTES: usize = 25 * 1024 * 1024;

const MAX_LABEL: usize = 1000;
const MAX_SEGMENT_BYTES: usize = 255;
const MAX_CLIENT_FIELD: usize = 100;
const MAX_CALLER_IN: usize = 2048;
const MAX_CALLER: usize = 512;

/// A refusal, with the fault code and HTTP status the other surfaces use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError {
    pub code: &'static str,
    pub status: u16,
    pub detail: String,
}

impl StoreError {
    pub fn bad(detail: impl Into<String>) -> Self {
        Self { code: "bad_request", status: 400, detail: detail.into() }
    }
    pub fn conflict(detail: impl Into<String>) -> Self {
        Self { code: "conflict", status: 409, detail: detail.into() }
    }
    fn forbidden(detail: impl Into<String>) -> Self {
        Self { code: "forbidden", status: 403, detail: detail.into() }
    }
    fn not_found() -> Self {
        Self { code: "not_found", status: 404, detail: String::new() }
    }
    fn too_large(detail: impl Into<String>) -> Self {
        Self { code: "too_large", status: 413, detail: detail.into() }
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self { code: "internal", status: 500, detail: detail.into() }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "{}", self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

impl std::error::Error for StoreError {}

impl From<VaultError> for StoreError {
    fn from(e: VaultError) -> Self {
        Self::internal(e.to_string())
    }
}

impl From<TransportError> for StoreError {
    fn from(e: TransportError) -> Self {
        Self::internal(e.to_string())
    }
}

/// What a connecting program called itself in its handshake. Nothing checks
/// it, so it is recorded as a claim, apart from what the operator declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Client {
    pub name: Option<String>,
    pub version: Option<String>,
}

/// Who is behind a write (§12.7 item 5). `agent` and `account` are the
/// operator's labels; `caller` is what the store named for the credentials;
/// `client` is the connection's own claim. None of them comes from the
/// request's arguments or content.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Provenance {
    pub agent: Option<String>,
    pub account: Option<String>,
    pub caller: Option<String>,
    pub client: Option<Client>,
}

/// An operator's name for an agent or an account: `claude-code`, `work`,
/// `copilot:acme`. No `@`, so an email address cannot be pasted in by mistake
/// into a file that may be shared.
pub fn check_provenance_label(name: &str, value: Option<&str>) -> Result<Option<String>, StoreError> {
    let Some(v) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let ok = v.len() <= 64
        && v.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && v.chars().all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c));
    if !ok {
        return Err(StoreError::bad(format!(
            "{name} must be a short label such as \"work\" or \"claude-code\" \
             (letters, digits and . _ : / -, at most 64), not an email address or a token"
        )));
    }
    Ok(Some(v.to_string()))
}

/// The store's name for the credentials behind a write, made fit to keep in
/// a file that may be shared. Any `/`- or `:`-separated segment holding an
/// `@` is written as `sha256:` and the first 16 hex digits of the hash of the
/// lowercased segment; anything left outside the ARN alphabet is refused.
pub fn normalize_caller(value: Option<&str>) -> Result<Option<String>, StoreError> {
    let Some(v) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let refuse = || {
        StoreError::bad(
            "caller must be a store identity such as an AWS ARN \
             (letters, digits and + = , . _ / : -, at most 512)",
        )
    };
    if v.chars().count() > MAX_CALLER_IN {
        return Err(refuse());
    }
    let mut out = String::with_capacity(v.len());
    let mut seg = String::new();
    let flush = |seg: &mut String, out: &mut String| {
        if seg.contains('@') {
            let h = Sha256::digest(seg.to_lowercase().as_bytes());
            out.push_str("sha256:");
            out.push_str(&crate::order::hex(&h)[..16]);
        } else {
            out.push_str(seg);
        }
        seg.clear();
    };
    for c in v.chars() {
        if c == '/' || c == ':' {
            flush(&mut seg, &mut out);
            out.push(c);
        } else {
            seg.push(c);
        }
    }
    flush(&mut seg, &mut out);
    let ok = out.len() <= MAX_CALLER
        && out.chars().all(|c| c.is_ascii_alphanumeric() || "+=,._/:-".contains(c));
    if !ok {
        return Err(refuse());
    }
    Ok(Some(out))
}

/// A client-reported string, made safe to keep: printable, one line, bounded.
pub fn clean_client_field(value: Option<&str>) -> Option<String> {
    let v = value?;
    let replaced: String = v
        .chars()
        .map(|c| {
            let n = c as u32;
            if n < 0x20 || (0x7f..=0x9f).contains(&n) || c == '\u{2028}' || c == '\u{2029}' {
                ' '
            } else {
                c
            }
        })
        .collect();
    let collapsed = replaced.split_whitespace().collect::<Vec<_>>().join(" ");
    let bounded: String = collapsed.chars().take(MAX_CLIENT_FIELD).collect();
    let bounded = bounded.trim().to_string();
    (!bounded.is_empty()).then_some(bounded)
}

/// The `created_by` record (§12.7), as the ordered mapping that is written.
pub fn build_created_by(principal: Option<&str>, p: &Provenance, at: &str) -> Result<Out, StoreError> {
    let mut m = Out::map();
    if let Some(pr) = principal.filter(|s| !s.is_empty()) {
        m.push(("principal".into(), Out::Str(pr.into())));
    }
    if let Some(a) = check_provenance_label("agent", p.agent.as_deref())? {
        m.push(("agent".into(), Out::Str(a)));
    }
    if let Some(a) = check_provenance_label("account", p.account.as_deref())? {
        m.push(("account".into(), Out::Str(a)));
    }
    if let Some(c) = normalize_caller(p.caller.as_deref())? {
        m.push(("caller".into(), Out::Str(c)));
    }
    if let Some(client) = &p.client {
        if let Some(name) = clean_client_field(client.name.as_deref()) {
            let mut c = vec![("name".to_string(), Out::Str(name))];
            if let Some(v) = clean_client_field(client.version.as_deref()) {
                c.push(("version".into(), Out::Str(v)));
            }
            m.push(("client".into(), Out::Map(c)));
        }
    }
    m.push(("at".into(), Out::Str(at.into())));
    Ok(Out::Map(m))
}

/// Git trailers naming who stored an object, from the same declared labels.
pub fn commit_trailers(principal: Option<&str>, p: Option<&Provenance>) -> Vec<(String, String)> {
    let mut t = Vec::new();
    if let Some(pr) = principal.filter(|s| !s.is_empty()) {
        t.push(("Basalt-Principal".into(), pr.to_string()));
    }
    let Some(p) = p else { return t };
    if let Ok(Some(a)) = check_provenance_label("agent", p.agent.as_deref()) {
        t.push(("Basalt-Agent".into(), a));
    }
    if let Ok(Some(a)) = check_provenance_label("account", p.account.as_deref()) {
        t.push(("Basalt-Account".into(), a));
    }
    if let Some(client) = &p.client {
        if let Some(name) = clean_client_field(client.name.as_deref()) {
            let v = clean_client_field(client.version.as_deref());
            t.push((
                "Basalt-Client".into(),
                match v {
                    Some(v) => format!("{name} {v}"),
                    None => name,
                },
            ));
        }
    }
    t
}

/// One object to store.
#[derive(Debug, Clone, Default)]
pub struct StoreRequest<'a> {
    /// `None` is the operator, who holds the vault's credentials and is not
    /// subject to §8; anything else is evaluated like any other request.
    pub principal: Option<&'a str>,
    pub path: &'a str,
    pub bytes: &'a [u8],
    pub title: Option<&'a str>,
    pub alt: Option<&'a str>,
    /// Given (even empty), the object is stamped `created_by`.
    pub provenance: Option<&'a Provenance>,
    /// Rebuild and persist the indexes afterwards. Pass false to store
    /// several objects and refresh once at the end.
    pub reindex: bool,
    /// Defaults to [`MAX_STORE_BYTES`].
    pub max_bytes: Option<usize>,
}

/// What was stored.
#[derive(Debug, Clone)]
pub struct Stored {
    pub path: String,
    pub id: String,
    pub kind: Kind,
    pub media_type: &'static str,
    pub size: usize,
    pub content_hash: String,
    pub created_by: Option<Out>,
}

fn check_path(path: &str) -> Result<String, StoreError> {
    if path.is_empty() {
        return Err(StoreError::bad("path is required"));
    }
    let key = path_to_key(path);
    validate_key(&key).map_err(|e| StoreError::bad(format!("not a valid path: {}", e.code.as_str())))?;
    for seg in path.split('/') {
        if seg == ".git" || seg == ".DS_Store" || seg.ends_with(".tmp") {
            return Err(StoreError::bad(format!(
                "\"{seg}\" is a name the filesystem transport skips when listing"
            )));
        }
        if seg.len() > MAX_SEGMENT_BYTES {
            return Err(StoreError::bad(format!(
                "a path segment is longer than {MAX_SEGMENT_BYTES} bytes"
            )));
        }
    }
    if Surface::withheld(path) {
        return Err(StoreError::bad("that path is under a tree no surface serves (§12.4)"));
    }
    Ok(key)
}

fn check_label(name: &str, value: Option<&str>) -> Result<Option<String>, StoreError> {
    let Some(v) = value.filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if v.chars().count() > MAX_LABEL {
        return Err(StoreError::bad(format!("{name} is longer than {MAX_LABEL} characters")));
    }
    let t = v.trim();
    Ok((!t.is_empty()).then(|| t.to_string()))
}

/// §12.3's rule for a write: a principal that cannot discover the folder is
/// told "not found", one that can is told "forbidden".
fn authorize(v: &Vault, principal: &str, folder: &str, rights: &[&str], what: &str) -> Result<(), StoreError> {
    if v.can(principal, folder, rights).allowed {
        return Ok(());
    }
    if v.can(principal, folder, &["list"]).allowed {
        Err(StoreError::forbidden(what))
    } else {
        Err(StoreError::not_found())
    }
}

/// Read-modify-write one folder's entry sidecar, conditional on its etag.
fn add_sidecar_entry(v: &mut Vault, folder: &str, name: &str, entry: &[(String, Out)]) -> Result<(), StoreError> {
    let key = format!("{META}folders/{folder}entries.yaml");
    for _ in 0..4 {
        let stat = v.transport.stat(&key)?;
        let bytes = match &stat {
            Some(_) => v.transport.get(&key)?,
            None => None,
        };
        let text = match &bytes {
            Some(b) => Some(String::from_utf8(b.clone()).map_err(|_| {
                StoreError::internal(format!("{key} is not UTF-8; fix or remove it before storing here"))
            })?),
            None => None,
        };
        let updated = yamltext::add_sidecar_entry(text.as_deref(), name, entry).map_err(|why| {
            StoreError::internal(format!("{key}: {why}; fix or remove it before storing here"))
        })?;
        let meta = PutMeta {
            content_type: Some("text/yaml".into()),
            if_match: Some(stat.and_then(|s| s.etag)),
        };
        match v.transport.put(&key, updated.as_bytes(), &meta) {
            Ok(_) => return Ok(()),
            Err(TransportError::PreconditionFailed(_)) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(StoreError::conflict(format!("{key} kept changing underneath this store; try again")))
}

/// Store one new object. On a store that keeps history (git) the object, its
/// sidecar and the refreshed indexes are one commit that says who stored it.
pub fn store_object(v: &mut Vault, req: &StoreRequest<'_>) -> Result<Stored, StoreError> {
    let info = BatchInfo {
        message: Some(format!("Add {}", req.path)),
        trailers: commit_trailers(req.principal, req.provenance),
    };
    v.batch(info, |v| store_inner(v, req))
}

fn store_inner(v: &mut Vault, req: &StoreRequest<'_>) -> Result<Stored, StoreError> {
    // Principals, ACLs and sidecars are re-read on every write: a long-lived
    // process must not honour a grant revoked since it started (§12.7 item 3).
    v.reload()?;
    let path = req.path;
    let key = check_path(path)?;
    let kind = kind_for(path);
    let folder = parent_folder(path).to_string();
    let name = basename(path).to_string();
    let title = check_label("title", req.title)?;
    let alt = check_label("alt", req.alt)?;
    // Before anything is written: a bad label refuses the store rather than
    // leaving an object behind with no record of who made it.
    let created_by = match req.provenance {
        Some(p) => Some(build_created_by(req.principal, p, &now_seconds())?),
        None => None,
    };

    let max = req.max_bytes.unwrap_or(MAX_STORE_BYTES);
    if req.bytes.len() > max {
        return Err(StoreError::too_large(format!(
            "{} bytes is over the {max} byte limit",
            req.bytes.len()
        )));
    }
    if kind != Kind::Note && folder.is_empty() {
        return Err(StoreError::bad("files other than notes must live in a folder, e.g. \"Assets/\""));
    }
    let text = if matches!(kind, Kind::Note | Kind::Data) {
        Some(std::str::from_utf8(req.bytes).map_err(|_| {
            StoreError::bad(format!("{name} must be valid UTF-8 text; store binary data under another extension"))
        })?)
    } else {
        None
    };

    // --- authorization (§8)
    if let Some(p) = req.principal {
        authorize(v, p, &folder, &["create_child"], "create_child is required")?;
        if kind == Kind::Note && parse_note(text.unwrap_or(""), path).acl.is_some() {
            authorize(v, p, &folder, &["write_acl"], "frontmatter sets basalt.acl, which needs write_acl")?;
        }
    }

    // --- collisions (§2.2)
    let existing: Vec<String> = v
        .transport
        .list_all(CONTENT)?
        .into_iter()
        .filter(|k| k.starts_with(CONTENT))
        .collect();
    if existing.contains(&key) {
        return Err(StoreError::conflict(format!("{path} already exists; stores never overwrite")));
    }
    let mut with: Vec<String> = existing.clone();
    with.push(key.clone());
    if let Some(group) = find_collisions(&with).into_iter().find(|g| g.contains(&key)) {
        let other = group.iter().find(|k| **k != key).cloned().unwrap_or_default();
        return Err(StoreError::conflict(format!(
            "{path} collides with {} once case and Unicode normalization are folded (§2.2)",
            &other[CONTENT.len()..]
        )));
    }
    let segments: Vec<&str> = key.split('/').collect();
    for i in 2..segments.len() {
        let prefix = segments[..i].join("/");
        if existing.contains(&prefix) {
            return Err(StoreError::conflict(format!(
                "{} is a file, so it cannot also be a folder",
                &prefix[CONTENT.len()..]
            )));
        }
    }
    let as_folder = format!("{key}/");
    if existing.iter().any(|k| k.starts_with(&as_folder)) {
        return Err(StoreError::conflict(format!("{path} is a folder")));
    }
    if find_folder_case_divergence(&existing) != find_folder_case_divergence(&with) {
        return Err(StoreError::conflict(format!(
            "a folder in {path} differs only in case from an existing one (§2.2)"
        )));
    }

    // --- identity (§4.3)
    let id = crate::ulid();
    let content: Vec<u8> = match (kind, text) {
        (Kind::Note, Some(t)) => {
            let split = split_frontmatter(t);
            let raw = split.raw.as_deref();
            let block = yamltext::stamp_frontmatter(raw, &id, title.as_deref(), created_by.as_ref(), true)
                .map_err(StoreError::bad)?;
            let body = if raw.is_some() { split.body.as_str() } else { t };
            format!("---\n{block}\n---\n{body}").into_bytes()
        }
        _ => req.bytes.to_vec(),
    };

    // --- write: content first, then the sidecar, then the indexes (item 7)
    let meta = PutMeta {
        content_type: Some(media_for(path).to_string()),
        if_match: Some(None),
    };
    match v.transport.put(&key, &content, &meta) {
        Ok(_) => {}
        Err(TransportError::PreconditionFailed(_)) => {
            return Err(StoreError::conflict(format!("{path} was created by someone else just now")))
        }
        Err(e) => return Err(e.into()),
    }

    if kind != Kind::Note {
        let mut entry = vec![("id".to_string(), Out::Str(id.clone()))];
        if let Some(t) = &title {
            entry.push(("title".into(), Out::Str(t.clone())));
        }
        if let Some(a) = &alt {
            entry.push(("alt".into(), Out::Str(a.clone())));
        }
        if let Some(by) = &created_by {
            entry.push(("created_by".into(), by.clone()));
        }
        if let Err(mut e) = add_sidecar_entry(v, &folder, &name, &entry) {
            e.detail = format!("{} ({path} was stored but is unbound; run `basalt mint`)", e.detail);
            return Err(e);
        }
        v.reload()?;
    }

    if req.reindex {
        v.reindex(true).map_err(|e| {
            StoreError::internal(format!(
                "{path} was stored, but refreshing the indexes failed: {e}. Run `basalt index --write`."
            ))
        })?;
    }

    Ok(Stored {
        path: path.to_string(),
        id,
        kind,
        media_type: media_for(path),
        size: content.len(),
        content_hash: format!("sha256:{}", crate::order::hex(&Sha256::digest(&content))),
        created_by,
    })
}

/// RFC 3339 UTC to the second, the form `created_by.at` takes.
pub fn now_seconds() -> String {
    crate::transport::fs::now_rfc3339()
}
