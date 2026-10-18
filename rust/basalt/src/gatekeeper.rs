//! The gatekeeper HTTP service, PROTOCOL §12.
//!
//! This process holds the only credentials to the store. The bucket stays
//! private and never faces the reader, which is what makes §8's inherited
//! permissions real rather than advisory — no S3-like store can express an
//! inherited deny, so something has to stand in front of it.
//!
//! The server is hand-rolled over `TcpListener` rather than built on an async
//! HTTP stack. §12.3 is eight read-only routes over a synchronous transport;
//! an executor would add a dependency tree larger than this entire crate
//! without changing what any route returns.

use crate::canonical::Json;
use crate::keys::path_to_key;
use crate::transport::Capability;
use crate::vault::{IndexState, Vault};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// §12.4 forbids ever serving these trees to a non-`system` principal: they
/// are the indexes, the ACLs and the principal list, and §8.8 explains why
/// handing them out leaks the private half of the vault.
const NEVER_SERVE: [&str; 5] = ["meta/", "index/", "principals/", "history/", "basalt.yaml"];

/// How `raw` delivers bytes (§12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The gatekeeper streams the bytes. Always correct, costs bandwidth.
    Proxy,
    /// Mint a short-lived presigned URL and redirect. Needs `presign`.
    Redirect,
}

/// Reduces a request to exactly one principal id (§12.1).
///
/// How that happens is out of scope — session cookie, OIDC, signed token,
/// mTLS, a reverse-proxy header. The one hard rule is that a client MUST NOT
/// be able to assert its own principal id, so this takes the raw headers and
/// the implementor decides which of them, if any, is trustworthy.
pub type Identify = Arc<dyn Fn(&Request) -> String + Send + Sync>;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: Json) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_canonical_bytes(),
        }
    }
    fn error(status: u16) -> Self {
        let msg = match status {
            404 => "not_found",
            403 => "forbidden",
            400 => "bad_request",
            405 => "method_not_allowed",
            503 => "index_stale",
            _ => "error",
        };
        Self::json(status, Json::obj().set("error", Json::str(msg)).build())
    }
}

pub struct Gatekeeper {
    vault: Mutex<Vault>,
    identify: Identify,
    delivery: Delivery,
    /// Index-derived responses, keyed per §12.5.
    cache: Mutex<BTreeMap<String, Vec<u8>>>,
    index_state: Mutex<IndexState>,
}

impl Gatekeeper {
    pub fn new(vault: Vault) -> Self {
        Self {
            vault: Mutex::new(vault),
            // The default returns `anonymous` for everything: authentication
            // is deliberately out of scope (§12.1).
            identify: Arc::new(|_| "anonymous".to_string()),
            delivery: Delivery::Proxy,
            cache: Mutex::new(BTreeMap::new()),
            index_state: Mutex::new(IndexState::Fresh),
        }
    }

    pub fn with_identify(mut self, f: Identify) -> Self {
        self.identify = f;
        self
    }

    pub fn with_delivery(mut self, d: Delivery) -> Self {
        self.delivery = d;
        self
    }

    /// Force one principal for every request — for local testing only.
    pub fn with_fixed_principal(self, who: &str) -> Self {
        let who = who.to_string();
        self.with_identify(Arc::new(move |_| who.clone()))
    }

    pub fn set_index_state(&self, state: IndexState) {
        *self.index_state.lock().unwrap() = state;
    }

    /// Drop cached index-derived responses; call after a reindex.
    pub fn invalidate(&self) {
        self.cache.lock().unwrap().clear();
    }

    /// A cache key for index-derived responses (§12.5).
    ///
    /// It MUST include the principal's effective subject set, or the cache
    /// serves one user's visibility to another. §12.5 calls this the single
    /// most likely place for a conforming-looking implementation to leak, so
    /// the subject set is hashed in rather than the principal id alone — two
    /// principals with identical group membership may legitimately share an
    /// entry, and one whose groups changed must not.
    fn cache_key(&self, route: &str, principal: &str, arg: &str) -> String {
        let vault = self.vault.lock().unwrap();
        let mut subjects = vec![principal.to_string()];
        subjects.extend(vault.principals.groups_of(principal));
        subjects.sort();
        drop(vault);
        let h = Sha256::digest(subjects.join(",").as_bytes());
        format!("{route}\u{0}{}\u{0}{arg}", crate::order::hex(&h))
    }

    pub fn handle(&self, req: &Request) -> Response {
        let principal = (self.identify)(req);

        if req.method != "GET" && req.method != "HEAD" {
            return Response::error(405);
        }

        let Some(rest) = req.path.strip_prefix("/api/v1/") else {
            return Response::error(404);
        };
        let (route, target) = match rest.split_once('/') {
            Some((r, t)) => (r, percent_decode(t)),
            None => (rest, String::new()),
        };

        // §12.4: refuse the protocol's own trees outright, before any ACL work
        // — a 403 here would itself confirm the tree is there.
        if NEVER_SERVE
            .iter()
            .any(|p| target == *p || target.starts_with(p))
        {
            return Response::error(404);
        }

        // §10.6: a gatekeeper MUST signal staleness under every policy, so a
        // client is never silently served old data. `refuse` is the one policy
        // that answers with an error rather than a header.
        let state = *self.index_state.lock().unwrap();
        if state == IndexState::Stale
            && self.vault.lock().unwrap().manifest.stale_policy
                == crate::manifest::StalePolicy::Refuse
        {
            return self.finish(Response::error(503), state);
        }

        let resp = match route {
            "manifest" => {
                let v = self.vault.lock().unwrap();
                // The *public subset* only: §15 notes that whoever can read
                // `security.*` learns the vault's enforcement posture.
                Response::json(
                    200,
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
                        .build(),
                )
            }

            "node" => {
                let v = self.vault.lock().unwrap();
                match v.read_node(&principal, &target) {
                    Err(_) => Response::error(404),
                    Ok(r) if r.status != 200 => Response::error(r.status),
                    Ok(r) => {
                        let links = v.links(&principal, &target);
                        Response::json(
                            200,
                            Json::obj()
                                .set("path", Json::opt_str(r.path.as_deref()))
                                .set("id", Json::opt_str(r.id.as_deref()))
                                .set("kind", Json::opt_str(r.kind.map(|k| k.as_str())))
                                .set("title", Json::opt_str(r.title.as_deref()))
                                .set("text", Json::opt_str(r.text.as_deref()))
                                .set("links", links_json(&links))
                                .build(),
                        )
                    }
                }
            }

            "raw" => {
                let v = self.vault.lock().unwrap();
                match v.read_node(&principal, &target) {
                    Err(_) => Response::error(404),
                    Ok(r) if r.status != 200 => Response::error(r.status),
                    Ok(r) => {
                        if self.delivery == Delivery::Redirect
                            && v.transport.has(Capability::Presign)
                        {
                            // §12.4: a presigned URL is a bearer token that
                            // outlives the ACL check that produced it, so the
                            // TTL is short and it never enters a shared cache.
                            match v.transport.presign(&path_to_key(&target), 120) {
                                Ok(url) => Response {
                                    status: 302,
                                    headers: vec![("location".into(), url)],
                                    body: Vec::new(),
                                },
                                Err(_) => Response::error(404),
                            }
                        } else {
                            Response {
                                status: 200,
                                headers: vec![("content-type".into(), media_for(&target).into())],
                                body: r.bytes.unwrap_or_default(),
                            }
                        }
                    }
                }
            }

            "list" => {
                let folder = if target.is_empty() || target.ends_with('/') {
                    target.clone()
                } else {
                    format!("{target}/")
                };
                let key = self.cache_key("list", &principal, &folder);
                if let Some(hit) = self.cache.lock().unwrap().get(&key) {
                    return self.finish(
                        Response {
                            status: 200,
                            headers: vec![("content-type".into(), "application/json".into())],
                            body: hit.clone(),
                        },
                        state,
                    );
                }
                let v = self.vault.lock().unwrap();
                let r = v.list_folder(&principal, &folder);
                if r.status != 200 {
                    Response::error(r.status)
                } else {
                    let body = Json::obj()
                        .set("folder", Json::str(&folder))
                        .set("entries", Json::arr(r.entries.iter().map(entry_json)))
                        .set("folders", Json::strings(&r.folders))
                        .build();
                    let resp = Response::json(200, body);
                    self.cache.lock().unwrap().insert(key, resp.body.clone());
                    resp
                }
            }

            "links" => {
                let v = self.vault.lock().unwrap();
                let r = v.links(&principal, &target);
                if r.status != 200 {
                    Response::error(r.status)
                } else {
                    Response::json(200, links_json(&r))
                }
            }

            "search" => {
                let Some(q) = req.query.get("q").filter(|q| !q.is_empty()) else {
                    return self.finish(Response::error(400), state);
                };
                let v = self.vault.lock().unwrap();
                let hits = v.search(&principal, q);
                Response::json(
                    200,
                    Json::obj()
                        .set(
                            "hits",
                            Json::arr(hits.iter().map(|h| {
                                Json::obj()
                                    .set("id", Json::str(&h.id))
                                    .set("path", Json::str(&h.path))
                                    .set("title", Json::opt_str(h.title.as_deref()))
                                    .set("score", Json::Int(h.score))
                                    .build()
                            })),
                        )
                        .build(),
                )
            }

            "tree" => {
                let key = self.cache_key("tree", &principal, "");
                if let Some(hit) = self.cache.lock().unwrap().get(&key) {
                    return self.finish(
                        Response {
                            status: 200,
                            headers: vec![("content-type".into(), "application/json".into())],
                            body: hit.clone(),
                        },
                        state,
                    );
                }
                let v = self.vault.lock().unwrap();
                match v.tree(&principal) {
                    None => Response::error(404),
                    Some(t) => {
                        let resp = Response::json(200, tree_json(&t));
                        self.cache.lock().unwrap().insert(key, resp.body.clone());
                        resp
                    }
                }
            }

            "effective" => {
                let path = req.query.get("path").cloned().unwrap_or_default();
                let who = req
                    .query
                    .get("principal")
                    .cloned()
                    .unwrap_or_else(|| principal.clone());
                let v = self.vault.lock().unwrap();
                // §8.7 is a privileged view: seeing someone else's effective
                // rights requires `read_acl` on the object.
                if !v.can(&principal, &path, &["read_acl"]).allowed {
                    Response::error(403)
                } else {
                    let e = v.effective(&who, &path);
                    Response::json(
                        200,
                        Json::obj()
                            .set("principal", Json::str(&who))
                            .set("path", Json::str(&path))
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
                                                    .set(
                                                        "failed_at",
                                                        Json::opt_str(d.failed_at.as_deref()),
                                                    )
                                                    .build(),
                                            )
                                        })
                                        .collect(),
                                ),
                            )
                            .set("failed_at", Json::opt_str(e.failed_at.as_deref()))
                            .build(),
                    )
                }
            }

            _ => Response::error(404),
        };

        self.finish(resp, state)
    }

    /// Add the headers §12.3 requires of every response.
    fn finish(&self, mut resp: Response, state: IndexState) -> Response {
        let vault_id = self.vault.lock().unwrap().manifest.vault_id.clone();
        resp.headers.push(("x-basalt-vault".into(), vault_id));
        resp.headers
            .push(("x-basalt-index-state".into(), state.as_str().into()));
        // §12.4: an index-derived or ACL-filtered response must never enter a
        // shared cache, because its contents depend on who asked.
        resp.headers
            .push(("cache-control".into(), "private, no-store".into()));
        resp
    }

    /// Serve until the process ends.
    pub fn listen(self: Arc<Self>, addr: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.serve_one(stream);
            });
        }
        Ok(())
    }

    /// Bind without serving, so a caller can report the real port.
    pub fn bind(addr: &str) -> std::io::Result<TcpListener> {
        TcpListener::bind(addr)
    }

    pub fn serve(self: Arc<Self>, listener: TcpListener) {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let me = Arc::clone(&self);
            std::thread::spawn(move || {
                let _ = me.serve_one(stream);
            });
        }
    }

    fn serve_one(&self, mut stream: TcpStream) -> std::io::Result<()> {
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut start = String::new();
        if reader.read_line(&mut start)? == 0 {
            return Ok(());
        }
        let mut parts = start.split_whitespace();
        let method = parts.next().unwrap_or("GET").to_string();
        let raw_target = parts.next().unwrap_or("/").to_string();

        let mut headers = BTreeMap::new();
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line)? == 0 {
                break;
            }
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }
        // Drain any body so the connection closes cleanly.
        if let Some(len) = headers.get("content-length").and_then(|l| l.parse().ok()) {
            let mut sink = vec![0u8; len];
            let _ = reader.read_exact(&mut sink);
        }

        let (path, query) = match raw_target.split_once('?') {
            Some((p, q)) => (p.to_string(), parse_query(q)),
            None => (raw_target.clone(), BTreeMap::new()),
        };

        let resp = self.handle(&Request {
            method: method.clone(),
            path,
            query,
            headers,
        });

        let reason = match resp.status {
            200 => "OK",
            302 => "Found",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            503 => "Service Unavailable",
            _ => "Error",
        };
        let mut head = format!("HTTP/1.1 {} {reason}\r\n", resp.status);
        for (k, v) in &resp.headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str(&format!("content-length: {}\r\n", resp.body.len()));
        head.push_str("connection: close\r\n\r\n");
        stream.write_all(head.as_bytes())?;
        if method != "HEAD" {
            stream.write_all(&resp.body)?;
        }
        stream.flush()
    }
}

fn entry_json(e: &crate::vault::ListEntry) -> Json {
    Json::obj()
        .set("path", Json::str(&e.path))
        .set("kind", Json::str(&e.kind))
        .set("title", Json::opt_str(e.title.as_deref()))
        .set("id", Json::opt_str(e.id.as_deref()))
        .build()
}

fn links_json(r: &crate::vault::LinksResponse) -> Json {
    Json::obj()
        .set(
            "out",
            Json::arr(r.out.iter().map(|l| {
                Json::obj()
                    .set("kind", Json::str(&l.kind))
                    .set("raw", Json::str(&l.raw))
                    .set("alias", Json::opt_str(l.alias.as_deref()))
                    .set("anchor", Json::opt_str(l.anchor.as_deref()))
                    .set("to", Json::opt_str(l.to.as_deref()))
                    .set("target_path", Json::opt_str(l.target_path.as_deref()))
                    .set("target_title", Json::opt_str(l.target_title.as_deref()))
                    .set("redacted", Json::Bool(l.redacted))
                    .set("line", Json::Int(l.line as i64))
                    .set("col", Json::Int(l.col as i64))
                    .build()
            })),
        )
        .set(
            "backlinks",
            Json::arr(r.backlinks.iter().map(|b| {
                Json::obj()
                    .set("id", Json::str(&b.id))
                    .set("path", Json::opt_str(b.path.as_deref()))
                    .set("title", Json::opt_str(b.title.as_deref()))
                    .build()
            })),
        )
        .build()
}

fn tree_json(t: &crate::vault::TreeNode) -> Json {
    Json::obj()
        .set("folder", Json::str(&t.folder))
        .set("title", Json::opt_str(t.title.as_deref()))
        .set("entries", Json::arr(t.entries.iter().map(entry_json)))
        .set("folders", Json::arr(t.folders.iter().map(tree_json)))
        .build()
}

fn media_for(path: &str) -> &'static str {
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

fn parse_query(q: &str) -> BTreeMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(&v.replace('+', " "))),
            None => (percent_decode(p), String::new()),
        })
        .collect()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}
