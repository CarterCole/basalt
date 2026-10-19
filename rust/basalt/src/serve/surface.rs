//! The surface core — one principal-scoped view of a vault, INTEROP §1.1.
//!
//! Every protocol this crate speaks (the §12.3 REST routes, the OpenAPI
//! document, MCP over HTTP and stdio) is a translation layer over this type
//! and nothing more. That is a security property rather than tidiness: §8.4
//! evaluation, the §12.3 404/403 split, the §12.4 withheld trees and the
//! §12.5 subject-keyed cache are implemented once here, so a surface added
//! later cannot forget one of them.
//!
//! A surface that reaches past this type into [`Vault`] is a defect even when
//! its output happens to be correct, because the next surface written by
//! copying it will not be.

use crate::canonical::Json;
use crate::keys::{basename, parent_folder, path_to_key};
use crate::order::{hex, sort_utf8_by};
use crate::transport::Capability;
use crate::vault::{IndexState, Vault};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

/// §12.4 forbids ever serving these trees to a non-`system` principal: they
/// are the indexes, the ACLs and the principal list, and §8.8 explains why
/// handing them out leaks the private half of the vault.
pub const WITHHELD: [&str; 5] = ["meta/", "index/", "principals/", "history/", "basalt.yaml"];

/// How `raw` delivers bytes (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The gatekeeper streams the bytes. Always correct, costs bandwidth.
    Proxy,
    /// Mint a short-lived presigned URL and redirect. Needs `presign`.
    Redirect,
}

/// One fault table for every surface, INTEROP §1.3.
///
/// A denial has to mean the same thing in all of them, so each surface looks
/// its own idiom up here rather than inventing a mapping. `NotFound` MUST
/// stay ambiguous between "no such object" and "you may not discover it"
/// (§12.3) in every one of those idioms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    NotFound,
    Forbidden,
    Unauthenticated,
    BadRequest,
    MethodNotAllowed,
    Internal,
}

impl Fault {
    pub fn code(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::Unauthenticated => "unauthenticated",
            Self::BadRequest => "bad_request",
            Self::MethodNotAllowed => "method_not_allowed",
            Self::Internal => "internal",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Forbidden => 403,
            Self::Unauthenticated => 401,
            Self::BadRequest => 400,
            Self::MethodNotAllowed => 405,
            Self::Internal => 500,
        }
    }

    /// The JSON-RPC error code MCP and `/rpc` report (INTEROP §1.3).
    pub fn rpc(self) -> i64 {
        match self {
            Self::NotFound => -32004,
            Self::Forbidden => -32003,
            Self::Unauthenticated => -32001,
            Self::BadRequest | Self::MethodNotAllowed => match self {
                Self::MethodNotAllowed => -32601,
                _ => -32602,
            },
            Self::Internal => -32603,
        }
    }

    /// The Connect/gRPC code, for a surface that speaks it.
    pub fn connect(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Forbidden => "permission_denied",
            Self::Unauthenticated => "unauthenticated",
            Self::BadRequest => "invalid_argument",
            Self::MethodNotAllowed => "unimplemented",
            Self::Internal => "internal",
        }
    }

    pub fn from_status(status: u16) -> Self {
        match status {
            403 => Self::Forbidden,
            404 => Self::NotFound,
            401 => Self::Unauthenticated,
            400 => Self::BadRequest,
            405 => Self::MethodNotAllowed,
            _ => Self::Internal,
        }
    }

    pub fn all() -> [Fault; 6] {
        [
            Self::NotFound,
            Self::Forbidden,
            Self::Unauthenticated,
            Self::BadRequest,
            Self::MethodNotAllowed,
            Self::Internal,
        ]
    }
}

pub type Answer = Result<Json, Fault>;

/// The bytes of one node, or the redirect that stands in for them (§12.4).
pub enum RawBody {
    Bytes {
        bytes: Vec<u8>,
        media_type: &'static str,
        etag: Option<String>,
    },
    Redirect(String),
}

pub struct Surface {
    vault: Mutex<Vault>,
    delivery: Delivery,
    /// Index-derived responses, keyed per §12.5.
    cache: Mutex<BTreeMap<String, Json>>,
    index_state: Mutex<IndexState>,
}

impl Surface {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Mutex::new(vault),
            delivery: Delivery::Proxy,
            cache: Mutex::new(BTreeMap::new()),
            index_state: Mutex::new(IndexState::Fresh),
        }
    }

    pub fn with_delivery(mut self, delivery: Delivery) -> Self {
        self.delivery = delivery;
        self
    }

    pub fn set_delivery(&mut self, delivery: Delivery) {
        self.delivery = delivery;
    }

    /// Read the vault directly. For plumbing that needs the manifest or the
    /// stale policy — never for answering a request, which goes through the
    /// operations below so that §8 is applied exactly once.
    pub fn with_vault<R>(&self, f: impl FnOnce(&Vault) -> R) -> R {
        f(&self.vault.lock().expect("vault lock"))
    }

    pub fn vault_id(&self) -> String {
        self.with_vault(|v| v.manifest.vault_id.clone())
    }

    pub fn index_state(&self) -> IndexState {
        *self.index_state.lock().expect("state lock")
    }

    pub fn set_index_state(&self, state: IndexState) {
        *self.index_state.lock().expect("state lock") = state;
    }

    /// Drop cached index-derived responses; call after a reindex.
    pub fn invalidate(&self) {
        self.cache.lock().expect("cache lock").clear();
    }

    /// True when a path is one of the trees no surface may ever serve.
    pub fn withheld(path: &str) -> bool {
        WITHHELD.iter().any(|p| path == *p || path.starts_with(p))
    }

    /// Reject a withheld path as not-found, never forbidden: a 403 would
    /// confirm that `principals/users.yaml` is there, which is half the answer.
    fn guard(path: &str) -> Result<(), Fault> {
        if Self::withheld(path) {
            return Err(Fault::NotFound);
        }
        Ok(())
    }

    // ----------------------------------------------------- caching (§12.5)

    /// A cache key for index-derived data.
    ///
    /// It MUST include the principal's effective subject set, or the cache
    /// serves one principal's visibility to another. Every surface shares this
    /// one cache, so the rule is applied once for all of them — and the
    /// equivalence suite asks the same question over every surface in both
    /// orders to prove it.
    fn cache_key(v: &Vault, route: &str, principal: &str, arg: &str) -> String {
        let mut subjects = vec![principal.to_string()];
        subjects.extend(v.principals.groups_of(principal));
        subjects.sort();
        let h = Sha256::digest(subjects.join(",").as_bytes());
        format!("{route}\u{0}{}\u{0}{arg}", &hex(&h)[..16])
    }

    fn cached(&self, v: &Vault, route: &str, principal: &str, arg: &str, make: impl FnOnce(&Vault) -> Answer) -> Answer {
        let key = Self::cache_key(v, route, principal, arg);
        if let Some(hit) = self.cache.lock().expect("cache lock").get(&key) {
            return Ok(hit.clone());
        }
        let value = make(v)?;
        self.cache
            .lock()
            .expect("cache lock")
            .insert(key, value.clone());
        Ok(value)
    }

    // ------------------------------------------------------------ operations

    /// The public subset of the manifest (§12.3).
    ///
    /// The *public* subset only: §15 notes that whoever can read `security.*`
    /// learns the vault's enforcement posture.
    pub fn manifest(&self) -> Json {
        let state = self.index_state();
        self.with_vault(|v| {
            Json::obj()
                .set("basalt", Json::Int(v.manifest.basalt))
                .set(
                    "vault",
                    Json::obj()
                        .set("id", Json::str(&v.manifest.vault_id))
                        .set("title", Json::opt_str(v.manifest.vault_title.as_deref()))
                        .build(),
                )
                .set(
                    "publish",
                    Json::obj()
                        .set("audience", Json::str(v.manifest.audience.as_str()))
                        .set("home", Json::opt_str(v.manifest.home.as_deref()))
                        .build(),
                )
                .set("index_state", Json::str(state.as_str()))
                .build()
        })
    }

    /// Who the request is, and what it carries (§8.4 step 1).
    pub fn me(&self, principal: &str) -> Json {
        self.with_vault(|v| {
            let mut subjects = vec![principal.to_string()];
            subjects.extend(v.principals.groups_of(principal));
            subjects.sort();
            Json::obj()
                .set("principal", Json::str(principal))
                .set(
                    "display_name",
                    Json::opt_str(
                        v.principals
                            .users
                            .get(principal)
                            .and_then(|u| u.display.as_deref()),
                    ),
                )
                .set("subjects", Json::strings(&subjects))
                .set(
                    "anonymous",
                    Json::Bool(principal == v.manifest.anonymous_principal),
                )
                .build()
        })
    }

    /// Content plus metadata and edges, if `read` (§12.3).
    pub fn node(&self, principal: &str, path: &str) -> Answer {
        Self::guard(path)?;
        self.with_vault(|v| {
            let r = v.read_node(principal, path).map_err(|_| Fault::NotFound)?;
            if r.status != 200 {
                return Err(Fault::from_status(r.status));
            }
            let entry = Self::entry_of(v, path).ok_or(Fault::NotFound)?;
            Ok(Json::obj()
                .set("node", entry)
                .set("text", Json::opt_str(r.text.as_deref()))
                .set("media_type", Json::str(media_for(path)))
                .set("links", Self::links_of(v, principal, path)?)
                .build())
        })
    }

    /// Bytes only.
    ///
    /// In `redirect` mode this answers with a presigned location instead of a
    /// body: a presigned URL is a bearer token that outlives the ACL check
    /// that produced it, so the TTL stays short and §12.4 keeps it out of any
    /// shared cache — and out of every JSON body on every other surface.
    pub fn raw(&self, principal: &str, path: &str) -> Result<RawBody, Fault> {
        Self::guard(path)?;
        let delivery = self.delivery;
        self.with_vault(|v| {
            let r = v.read_node(principal, path).map_err(|_| Fault::NotFound)?;
            if r.status != 200 {
                return Err(Fault::from_status(r.status));
            }
            if delivery == Delivery::Redirect && v.transport.has(Capability::Presign) {
                if let Ok(url) = v.transport.presign(&path_to_key(path), 120) {
                    return Ok(RawBody::Redirect(url));
                }
            }
            let etag = Self::entry_of(v, path)
                .and_then(|e| e.get("etag").and_then(|t| t.as_str().map(String::from)));
            Ok(RawBody::Bytes {
                bytes: r.bytes.unwrap_or_default(),
                media_type: media_for(path),
                etag,
            })
        })
    }

    /// Direct entries of a folder, filtered to what the principal may see.
    pub fn list(&self, principal: &str, folder: &str) -> Answer {
        let folder = if folder.is_empty() || folder.ends_with('/') {
            folder.to_string()
        } else {
            format!("{folder}/")
        };
        Self::guard(&folder)?;
        self.with_vault(|v| {
            self.cached(v, "list", principal, &folder, |v| {
                let r = v.list_folder(principal, &folder);
                if r.status != 200 {
                    return Err(Fault::from_status(r.status));
                }
                Ok(Json::obj()
                    .set("folder", Json::str(&folder))
                    .set(
                        "entries",
                        Json::arr(r.entries.iter().map(|e| {
                            Json::obj()
                                .set("path", Json::str(&e.path))
                                .set("kind", Json::str(&e.kind))
                                .set("title", Json::opt_str(e.title.as_deref()))
                                .set("id", Json::opt_str(e.id.as_deref()))
                                .build()
                        })),
                    )
                    .set("folders", Json::strings(&r.folders))
                    .build())
            })
        })
    }

    /// A page of readable node entries, in §13.3 order.
    pub fn nodes(&self, principal: &str, limit: i64, offset: i64, published_only: bool) -> Json {
        let all = self.readable(principal, published_only);
        let limit = limit.clamp(1, 1000) as usize;
        let offset = offset.max(0) as usize;
        let page: Vec<Json> = all.iter().skip(offset).take(limit).cloned().collect();
        Json::obj()
            .set("total", Json::Int(all.len() as i64))
            .set("offset", Json::Int(offset as i64))
            .set("limit", Json::Int(limit as i64))
            .set("entries", Json::Array(page))
            .build()
    }

    /// Every readable node entry, exactly as `index/nodes.json` carries it.
    ///
    /// Reading the index rather than rebuilding the shape is what keeps this
    /// identical to the other implementations: the entries are the bytes §13
    /// already pins.
    pub fn readable(&self, principal: &str, published_only: bool) -> Vec<Json> {
        self.with_vault(|v| Self::readable_in(v, principal, published_only))
    }

    fn readable_in(v: &Vault, principal: &str, published_only: bool) -> Vec<Json> {
        let mut out = Vec::new();
        for entry in Self::entries(v) {
            let Some(path) = entry.get("path").and_then(|p| p.as_str()) else {
                continue;
            };
            if Self::withheld(path) {
                continue;
            }
            if published_only && entry.get("publish") == Some(&Json::Bool(false)) {
                continue;
            }
            if !v.can(principal, path, &["read"]).allowed {
                continue;
            }
            out.push(entry.clone());
        }
        out
    }

    fn entries(v: &Vault) -> &[Json] {
        v.indexes
            .as_ref()
            .and_then(|i| i.nodes.get("entries"))
            .and_then(|e| e.as_array())
            .unwrap_or(&[])
    }

    fn entry_of(v: &Vault, path: &str) -> Option<Json> {
        Self::entries(v)
            .iter()
            .find(|e| e.get("path").and_then(|p| p.as_str()) == Some(path))
            .cloned()
    }

    /// Out-edges and backlinks, redacted in place per §9.5.
    pub fn links(&self, principal: &str, path: &str) -> Answer {
        Self::guard(path)?;
        self.with_vault(|v| Self::links_of(v, principal, path))
    }

    /// The shaping §9.5 requires: a redacted edge is kept with its target
    /// withheld, never dropped. Dropping it would make the graph silently
    /// wrong, and a reader could not tell a redacted link from a dangling one.
    fn links_of(v: &Vault, principal: &str, path: &str) -> Answer {
        let entry = Self::entry_of(v, path).ok_or(Fault::NotFound)?;
        if !v.can(principal, path, &["read"]).allowed {
            let discoverable = v.can(principal, parent_folder(path), &["list"]).allowed;
            return Err(if discoverable {
                Fault::Forbidden
            } else {
                Fault::NotFound
            });
        }
        let id = entry
            .get("id")
            .and_then(|i| i.as_str())
            .unwrap_or_default()
            .to_string();
        let redact_titles = v.manifest.redact_titles;

        let by_id: BTreeMap<&str, &Json> = Self::entries(v)
            .iter()
            .filter_map(|e| e.get("id").and_then(|i| i.as_str()).map(|i| (i, e)))
            .collect();
        let visible = |target: &Json| -> bool {
            target
                .get("path")
                .and_then(|p| p.as_str())
                .map(|p| v.can(principal, p, &["read"]).allowed)
                .unwrap_or(false)
        };
        let reference = |target: &Json, redacted: bool| -> Json {
            if redacted {
                Json::obj()
                    .set("id", Json::str("redacted"))
                    .set("path", Json::Null)
                    .set(
                        "title",
                        if redact_titles {
                            Json::Null
                        } else {
                            Json::opt_str(target.get("title").and_then(|t| t.as_str()))
                        },
                    )
                    .build()
            } else {
                Json::obj()
                    .set("id", Json::opt_str(target.get("id").and_then(|i| i.as_str())))
                    .set("path", Json::opt_str(target.get("path").and_then(|p| p.as_str())))
                    .set("title", Json::opt_str(target.get("title").and_then(|t| t.as_str())))
                    .build()
            }
        };

        let edges = v
            .indexes
            .as_ref()
            .and_then(|i| i.links.get("entries"))
            .and_then(|e| e.as_array())
            .unwrap_or(&[]);

        let mut out = Vec::new();
        for edge in edges {
            if edge.get("from").and_then(|f| f.as_str()) != Some(id.as_str()) {
                continue;
            }
            let mut shaped = edge.clone();
            let to = edge.get("to").and_then(|t| t.as_str()).map(String::from);
            match to.as_deref().and_then(|t| by_id.get(t).copied()) {
                None => {
                    // External or dangling: there is no target to redact.
                    shaped
                        .as_object_mut()
                        .expect("edge is an object")
                        .insert("target".into(), Json::Null);
                }
                Some(target) => {
                    let hidden = !visible(target);
                    let obj = shaped.as_object_mut().expect("edge is an object");
                    if hidden {
                        obj.insert("to".into(), Json::str("redacted"));
                    }
                    obj.insert("target".into(), reference(target, hidden));
                }
            }
            out.push(shaped);
        }

        let backlinks = v
            .indexes
            .as_ref()
            .and_then(|i| i.backlinks.get("entries"))
            .and_then(|e| e.get(&id))
            .and_then(|e| e.as_array())
            .unwrap_or(&[])
            .iter()
            .filter_map(|src| src.as_str())
            .filter_map(|src| by_id.get(src).copied())
            // Every backlink is returned; an invisible source is redacted in
            // place rather than dropped, so the graph stays honest.
            .map(|src| reference(src, !visible(src)))
            .collect::<Vec<_>>();

        Ok(Json::obj()
            .set("path", Json::str(path))
            .set("out", Json::Array(out))
            .set("backlinks", Json::Array(backlinks))
            .build())
    }

    /// Postings filtered to readable nodes, not merely re-ranked (§12.5).
    pub fn search(&self, principal: &str, query: &str, limit: i64, offset: i64) -> Answer {
        if query.trim().is_empty() {
            return Err(Fault::BadRequest);
        }
        let limit = limit.clamp(1, 200) as usize;
        let offset = offset.max(0) as usize;
        self.with_vault(|v| {
            let all = self.cached(v, "search", principal, query, |v| {
                let hits = v.search(principal, query);
                Ok(Json::arr(hits.iter().map(|h| {
                    // A hit is a node entry with a score inlined, which is the
                    // shape every surface returns.
                    let mut entry = Self::entry_of(v, &h.path).unwrap_or_else(|| {
                        Json::obj()
                            .set("path", Json::str(&h.path))
                            .set("id", Json::str(&h.id))
                            .set("title", Json::opt_str(h.title.as_deref()))
                            .build()
                    });
                    entry
                        .as_object_mut()
                        .expect("entry is an object")
                        .insert("score".into(), Json::Int(h.score));
                    entry
                })))
            })?;
            let hits = all.as_array().unwrap_or(&[]);
            Ok(Json::obj()
                .set("query", Json::str(query))
                .set("total", Json::Int(hits.len() as i64))
                .set("offset", Json::Int(offset as i64))
                .set(
                    "hits",
                    Json::Array(hits.iter().skip(offset).take(limit).cloned().collect()),
                )
                .build())
        })
    }

    /// The navigable tree, pruned to what is visible (§12.3).
    pub fn tree(&self, principal: &str) -> Answer {
        self.with_vault(|v| {
            self.cached(v, "tree", principal, "", |v| match v.tree(principal) {
                None => Err(Fault::NotFound),
                Some(t) => Ok(Json::obj().set("tree", tree_json(&t)).build()),
            })
        })
    }

    /// Tags and the readable nodes carrying them (§9.6).
    pub fn tags(&self, principal: &str) -> Answer {
        self.with_vault(|v| {
            self.cached(v, "tags", principal, "", |v| {
                let by_id: BTreeMap<&str, &Json> = Self::entries(v)
                    .iter()
                    .filter_map(|e| e.get("id").and_then(|i| i.as_str()).map(|i| (i, e)))
                    .collect();
                let postings = v
                    .indexes
                    .as_ref()
                    .and_then(|i| i.tags.get("entries"))
                    .and_then(|e| e.as_object())
                    .cloned()
                    .unwrap_or_default();
                let mut out = Vec::new();
                for (tag, ids) in postings {
                    let nodes: Vec<Json> = ids
                        .as_array()
                        .unwrap_or(&[])
                        .iter()
                        .filter_map(|i| i.as_str())
                        .filter_map(|i| by_id.get(i).copied())
                        .filter(|e| {
                            e.get("path")
                                .and_then(|p| p.as_str())
                                .map(|p| v.can(principal, p, &["read"]).allowed)
                                .unwrap_or(false)
                        })
                        .map(|e| {
                            Json::obj()
                                .set("id", Json::opt_str(e.get("id").and_then(|i| i.as_str())))
                                .set("path", Json::opt_str(e.get("path").and_then(|p| p.as_str())))
                                .set("title", Json::opt_str(e.get("title").and_then(|t| t.as_str())))
                                .build()
                        })
                        .collect();
                    if !nodes.is_empty() {
                        out.push(
                            Json::obj()
                                .set("tag", Json::str(&tag))
                                .set("nodes", Json::Array(nodes))
                                .build(),
                        );
                    }
                }
                Ok(Json::obj().set("tags", Json::Array(out)).build())
            })
        })
    }

    /// Readable entries with store metadata, newest first.
    ///
    /// The indexes deliberately carry no timestamp — §10 derives everything
    /// from content and §1 forbids relying on store clocks for correctness —
    /// so mtime appears only here, where it is presentation rather than
    /// correctness, and is null when the store will not say.
    pub fn recent(&self, principal: &str, limit: i64, published_only: bool) -> Json {
        let limit = limit.clamp(1, 500) as usize;
        self.with_vault(|v| {
            let mut rows: Vec<(Option<String>, String, Json)> =
                Self::readable_in(v, principal, published_only)
                    .into_iter()
                    .map(|entry| {
                        let path = entry
                            .get("path")
                            .and_then(|p| p.as_str())
                            .unwrap_or_default()
                            .to_string();
                        let stat = v.transport.stat(&path_to_key(&path)).ok().flatten();
                        let mtime = stat.as_ref().and_then(|s| s.mtime.clone());
                        let mut entry = entry;
                        entry
                            .as_object_mut()
                            .expect("entry is an object")
                            .insert("mtime".into(), Json::opt_str(mtime.as_deref()));
                        (mtime, path, entry)
                    })
                    .collect();
            // Newest first, ties broken by §13.3 path order so the answer is
            // stable across two stores with the same second resolution.
            rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
            Json::obj()
                .set(
                    "entries",
                    Json::Array(rows.into_iter().take(limit).map(|r| r.2).collect()),
                )
                .build()
        })
    }

    /// Effective rights with the deciding ACE per right (§8.7).
    ///
    /// Seeing anyone's rights — including your own, on an object whose ACL you
    /// may not read — requires `read_acl` on the object.
    pub fn effective(&self, principal: &str, path: &str, who: Option<&str>) -> Answer {
        Self::guard(path)?;
        let who = who.filter(|w| !w.is_empty()).unwrap_or(principal);
        self.with_vault(|v| {
            if !v.can(principal, path, &["read_acl"]).allowed {
                return Err(Fault::Forbidden);
            }
            let e = v.effective(who, path);
            Ok(Json::obj()
                .set("principal", Json::str(who))
                .set("path", Json::str(path))
                .set("granted", Json::strings(e.granted()))
                .set(
                    "decisions",
                    Json::Object(
                        e.decisions
                            .iter()
                            .map(|(r, d)| {
                                (
                                    r.clone(),
                                    Json::obj()
                                        .set("decision", Json::str(d.decision.as_str()))
                                        .set("by", Json::str(&d.by))
                                        .set("failed_at", Json::opt_str(d.failed_at.as_deref()))
                                        .build(),
                                )
                            })
                            .collect(),
                    ),
                )
                .set("failed_at", Json::opt_str(e.failed_at.as_deref()))
                .build())
        })
    }

    /// Readable folders, for surfaces that need collections.
    pub fn folders(&self, principal: &str) -> Vec<String> {
        self.with_vault(|v| {
            let mut seen: BTreeSet<String> = BTreeSet::new();
            seen.insert(String::new());
            for entry in Self::readable_in(v, principal, false) {
                let path = entry
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or_default()
                    .to_string();
                let mut folder = parent_folder(&path).to_string();
                while !folder.is_empty() && !seen.contains(&folder) {
                    seen.insert(folder.clone());
                    folder = parent_folder(folder.trim_end_matches('/')).to_string();
                }
            }
            let mut out: Vec<String> = seen
                .into_iter()
                .filter(|f| v.can(principal, f, &["list"]).allowed)
                .collect();
            sort_utf8_by(&mut out, |f| f.clone());
            out
        })
    }
}

fn tree_json(t: &crate::vault::TreeNode) -> Json {
    Json::obj()
        .set("folder", Json::str(&t.folder))
        .set(
            "title",
            Json::opt_str(
                t.title
                    .as_deref()
                    .or_else(|| Some(basename(t.folder.trim_end_matches('/')))),
            ),
        )
        .set(
            "entries",
            Json::arr(t.entries.iter().map(|e| {
                Json::obj()
                    .set("path", Json::str(&e.path))
                    .set("kind", Json::str(&e.kind))
                    .set("title", Json::opt_str(e.title.as_deref()))
                    .set("id", Json::opt_str(e.id.as_deref()))
                    .build()
            })),
        )
        .set("folders", Json::arr(t.folders.iter().map(tree_json)))
        .build()
}

pub fn media_for(path: &str) -> &'static str {
    match crate::keys::extname(crate::keys::basename(path)).as_str() {
        ".md" | ".markdown" => "text/markdown; charset=utf-8",
        ".json" => "application/json",
        ".yaml" | ".yml" => "text/yaml",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".svg" => "image/svg+xml",
        ".pdf" => "application/pdf",
        ".txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Base64, for the surfaces that carry bytes inside a JSON string.
///
/// Hand-rolled for the same reason the canonical JSON writer is: this crate
/// has no serialization dependency, and the encoder is twenty lines.
pub fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
