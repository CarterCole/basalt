//! The router, INTEROP §1.4.
//!
//! One listener, one identity step, one surface object, several protocols. The
//! identity step happens here and exactly once (§12.1): no surface may read a
//! principal off the request, so none can be talked into accepting a
//! client-asserted one.

use super::mcp::{self, MCP_LATEST, MCP_VERSIONS};
use super::ops::OPERATIONS;
use super::rest::{self, openapi_document, problem, Outcome};
use super::surface::{Fault, RawBody, Surface};
use crate::canonical::Json;
use crate::manifest::StalePolicy;
use crate::vault::IndexState;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Request bodies here are queries, never uploads.
pub const MAX_BODY: usize = 1 << 20;

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
    pub fn json(status: u16, body: &Json) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.to_canonical_bytes(),
        }
    }

    pub fn problem(fault: Fault, detail: Option<&str>) -> Self {
        Self {
            status: fault.status(),
            headers: vec![(
                "content-type".into(),
                "application/problem+json".into(),
            )],
            body: problem(fault, detail).to_canonical_bytes(),
        }
    }

    fn text(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body: body.into(),
        }
    }

    fn with(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// The interop surfaces this implementation can mount (INTEROP §10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SurfaceKind {
    Rest,
    Mcp,
}

impl SurfaceKind {
    pub const ALL: [SurfaceKind; 2] = [SurfaceKind::Rest, SurfaceKind::Mcp];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::Mcp => "mcp",
        }
    }

    pub fn profile(self) -> &'static str {
        match self {
            Self::Rest => "P-REST",
            Self::Mcp => "P-MCP",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "rest" => Some(Self::Rest),
            "mcp" => Some(Self::Mcp),
            _ => None,
        }
    }

    /// The profile name to the surface it mounts. Profiles this
    /// implementation does not serve — `P-GRAPHQL`, `P-WEBDAV` and the rest —
    /// map to nothing here, so a vault may declare them for another
    /// implementation without this one pretending to answer.
    pub fn from_profile(profile: &str) -> Option<Self> {
        match profile {
            "P-REST" => Some(Self::Rest),
            "P-MCP" => Some(Self::Mcp),
            _ => None,
        }
    }
}

/// The surfaces a vault's manifest allows (§3.1, INTEROP §10).
///
/// A manifest that lists `publish.interop` bounds what may be mounted, so a
/// vault owner can take a surface off for every deployment of that vault in
/// one edit — the same shape as the §12.2 audience ceiling. A manifest that
/// says nothing predates the annex and claims nothing, so everything this
/// implementation has mounts and the operator decides.
/// The surfaces mounted when a manifest declares nothing: the §12 read API,
/// and nothing else.
///
/// Profiles are opt-in (§14.1). Silence means deny everywhere else in this
/// protocol — an unmatched right (§8.4), an unresolvable subject (§8.4), an
/// undeclared audience (§12.2) — and a vault written before a profile existed
/// cannot have consented to serving it.
pub const DEFAULT_SURFACES: [SurfaceKind; 1] = [SurfaceKind::Rest];

pub fn declared_surfaces(manifest: &crate::Manifest) -> BTreeSet<SurfaceKind> {
    match &manifest.interop {
        None => DEFAULT_SURFACES.into_iter().collect(),
        Some(profiles) => profiles
            .iter()
            .filter_map(|p| SurfaceKind::from_profile(p))
            .collect(),
    }
}

pub struct Router {
    pub surface: Surface,
    enabled: BTreeSet<SurfaceKind>,
    server_version: String,
}

impl Router {
    pub fn new(surface: Surface) -> Self {
        let enabled = surface.with_vault(|v| declared_surfaces(&v.manifest));
        Self {
            surface,
            enabled,
            server_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Override what the manifest declared — the operator's choice, for a
    /// deployment that serves less than the vault allows.
    pub fn with_surfaces(mut self, surfaces: BTreeSet<SurfaceKind>) -> Self {
        self.enabled = surfaces;
        self
    }

    pub fn enabled(&self) -> &BTreeSet<SurfaceKind> {
        &self.enabled
    }

    pub fn has(&self, kind: SurfaceKind) -> bool {
        self.enabled.contains(&kind)
    }

    /// The absolute base URL for this request, honouring a reverse proxy.
    fn base(&self, req: &Request) -> String {
        let proto = req
            .header("x-forwarded-proto")
            .unwrap_or("http")
            .split(',')
            .next()
            .unwrap_or("http")
            .trim()
            .to_string();
        let host = req
            .header("x-forwarded-host")
            .or_else(|| req.header("host"))
            .unwrap_or("localhost")
            .split(',')
            .next()
            .unwrap_or("localhost")
            .trim()
            .to_string();
        format!("{proto}://{host}")
    }

    pub fn handle(&self, principal: &str, req: &Request, body: &[u8]) -> Response {
        let state = self.surface.index_state();

        // §10.6: a gatekeeper MUST signal staleness under every policy, so a
        // client is never silently served old data. `refuse` is the one policy
        // that answers with an error rather than a header.
        if state == IndexState::Stale
            && self.surface.with_vault(|v| v.manifest.stale_policy) == StalePolicy::Refuse
        {
            return self.finish(
                req,
                Response::json(
                    503,
                    &Json::obj().set("error", Json::str("index_stale")).build(),
                ),
                state,
            );
        }

        // ------------------------------------------------- discovery (§1.4)
        if req.path == "/.well-known/basalt" || req.path == "/.well-known/basalt.json" {
            let base = self.base(req);
            // The one response that is identical for everyone: it describes
            // the surfaces, never the content.
            let resp = Response::json(200, &self.discovery(&base))
                .with("cache-control", "public, max-age=60")
                .with("x-basalt-surface", "discovery");
            return self.finish(req, resp, state);
        }

        // ------------------------------------------------------- REST (§2)
        if self.has(SurfaceKind::Rest) && req.path.starts_with(rest::API) {
            if let Some((route, target)) = rest::route_for(&req.path) {
                if req.method != "GET" && req.method != "HEAD" {
                    let resp = Response::problem(Fault::MethodNotAllowed, None)
                        .with("allow", "GET, HEAD");
                    return self.finish(req, resp, state);
                }
                let base = self.base(req);
                let ask = rest::Ask {
                    target,
                    query: &req.query,
                    base: &base,
                };
                let resp = match (route.handler)(&self.surface, principal, &ask) {
                    Err(fault) => Response::problem(fault, None),
                    Ok(Outcome::Raw(RawBody::Redirect(url))) => {
                        // §12.4: a presigned URL is a bearer token that
                        // outlives the ACL check that produced it, so it never
                        // enters a shared cache.
                        Response {
                            status: 302,
                            headers: vec![
                                ("location".into(), url),
                                ("cache-control".into(), "private, no-store".into()),
                            ],
                            body: Vec::new(),
                        }
                    }
                    Ok(Outcome::Raw(RawBody::Bytes {
                        bytes,
                        media_type,
                        etag,
                    })) => {
                        let tag = etag.unwrap_or_else(|| weak_etag(&bytes));
                        self.conditional(req, Response::text(200, media_type, bytes), tag)
                    }
                    Ok(Outcome::Json(value)) => {
                        let body = value.to_canonical_bytes();
                        let tag = weak_etag(&body);
                        self.conditional(
                            req,
                            Response::text(200, "application/json", body),
                            tag,
                        )
                    }
                };
                return self.finish(req, resp.with("x-basalt-surface", "rest"), state);
            }
            return self.finish(
                req,
                Response::problem(Fault::NotFound, None).with("x-basalt-surface", "rest"),
                state,
            );
        }

        // -------------------------------------------------------- MCP (§4.2)
        if self.has(SurfaceKind::Mcp) && req.path == "/mcp" {
            if req.method != "POST" {
                // No SSE stream: this server has no server-initiated messages
                // to send, so the GET half of Streamable HTTP would stay silent.
                let resp = Response::json(
                    405,
                    &super::jsonrpc::error(
                        Json::Null,
                        super::jsonrpc::INVALID_REQUEST,
                        "POST a JSON-RPC request; this server opens no SSE stream",
                    ),
                )
                .with("allow", "POST");
                return self.finish(req, resp.with("x-basalt-surface", "mcp"), state);
            }
            if body.len() > MAX_BODY {
                return self.finish(
                    req,
                    Response::problem(Fault::BadRequest, Some("request body too large")),
                    state,
                );
            }
            let text = String::from_utf8_lossy(body).to_string();
            let methods = mcp::methods(&self.surface, principal, &self.server_version);
            let answered = methods.handle_text(&text).unwrap_or_default();
            let asked = req.header("mcp-protocol-version").unwrap_or("");
            let version = if MCP_VERSIONS.contains(&asked) {
                asked.to_string()
            } else {
                MCP_LATEST.to_string()
            };
            let resp = Response::text(200, "application/json", answered)
                .with("mcp-protocol-version", version)
                .with("x-basalt-surface", "mcp");
            return self.finish(req, resp, state);
        }

        self.finish(
            req,
            Response::problem(
                Fault::NotFound,
                Some(&format!("no surface serves {}", req.path)),
            ),
            state,
        )
    }

    /// Answer 304 when the client already has this exact body.
    ///
    /// The validator of a derived response depends on the principal's
    /// visibility, so the response stays `private`: a shared cache keyed on
    /// the URL alone would serve one subject set's etag to another (§12.5).
    fn conditional(&self, req: &Request, resp: Response, etag: String) -> Response {
        let matched = req
            .header("if-none-match")
            .map(|v| v.split(',').any(|t| t.trim() == etag))
            .unwrap_or(false);
        if matched {
            return Response {
                status: 304,
                headers: resp.headers,
                body: Vec::new(),
            }
            .with("etag", etag);
        }
        resp.with("etag", etag)
    }

    /// Add the headers §12.3 requires of every response.
    fn finish(&self, _req: &Request, mut resp: Response, state: IndexState) -> Response {
        resp.headers
            .push(("x-basalt-vault".into(), self.surface.vault_id()));
        resp.headers
            .push(("x-basalt-index-state".into(), state.as_str().into()));
        // Content is author-supplied on these surfaces; never let a browser
        // sniff a note into something executable.
        resp.headers
            .push(("x-content-type-options".into(), "nosniff".into()));
        if !resp
            .headers
            .iter()
            .any(|(k, _)| k == "cache-control")
        {
            // §12.4: an index-derived or ACL-filtered response must never
            // enter a shared cache, because its contents depend on who asked.
            resp.headers
                .push(("cache-control".into(), "private, no-store".into()));
            resp.headers
                .push(("vary".into(), "accept, authorization, cookie".into()));
        }
        resp
    }

    /// The machine-readable list of everything this vault speaks (§1.4).
    pub fn discovery(&self, base: &str) -> Json {
        let manifest = self.surface.manifest();
        let mut surfaces = Json::obj();
        if self.has(SurfaceKind::Rest) {
            surfaces = surfaces.set(
                "rest",
                Json::obj()
                    .set("base", Json::str(format!("{base}/api/v1")))
                    .set(
                        "openapi",
                        Json::str(format!("{base}/api/v1/openapi.json")),
                    )
                    .set("spec", Json::str("OpenAPI 3.1"))
                    .build(),
            );
        }
        if self.has(SurfaceKind::Mcp) {
            surfaces = surfaces.set(
                "mcp",
                Json::obj()
                    .set("endpoint", Json::str(format!("{base}/mcp")))
                    .set(
                        "transports",
                        Json::strings(["streamable-http (JSON only)", "stdio: basalt mcp"]),
                    )
                    .set("protocol_versions", Json::strings(MCP_VERSIONS))
                    .build(),
            );
        }
        Json::obj()
            .set("basalt", Json::Int(1))
            .set(
                "vault",
                manifest.get("vault").cloned().unwrap_or(Json::Null),
            )
            .set(
                "publish",
                manifest.get("publish").cloned().unwrap_or(Json::Null),
            )
            .set(
                "index_state",
                Json::str(self.surface.index_state().as_str()),
            )
            .set("operations", Json::strings(OPERATIONS.iter().map(|o| o.name)))
            .set("surfaces", surfaces.build())
            .set(
                "notes",
                Json::strings([
                    "Every surface answers for the principal the gatekeeper reduced the request to (§12.1).",
                    "A 404 means \"no such object\" or \"you may not discover it\" and the two are indistinguishable (§12.3).",
                    "All surfaces are read-only: §12 defines a read surface.",
                ]),
            )
            .build()
    }

    /// The OpenAPI document, for `basalt schema openapi`.
    pub fn openapi(&self, base: &str) -> Json {
        openapi_document(&self.surface, base)
    }
}

fn weak_etag(bytes: &[u8]) -> String {
    format!("W/\"{}\"", &crate::order::hex(&Sha256::digest(bytes))[..32])
}
