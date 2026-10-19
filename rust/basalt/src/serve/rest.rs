//! The REST surface, PROTOCOL §12.3 and INTEROP §2.
//!
//! The route table below is the single source of truth: the dispatcher and the
//! OpenAPI 3.1 document are both generated from it, so a route cannot exist
//! without being described, and a description cannot drift from the route it
//! documents. `basalt schema openapi` prints the same document the server
//! serves at `/api/v1/openapi.json`.

use super::ops::{self, ArgType};
use super::surface::{Fault, RawBody, Surface};
use crate::canonical::Json;
use std::collections::BTreeMap;

pub const API: &str = "/api/v1";

pub struct Param {
    pub name: &'static str,
    /// `path` or `query`.
    pub location: &'static str,
    pub required: bool,
    pub ty: ArgType,
    pub description: &'static str,
    pub default: Option<&'static str>,
}

/// What a route was asked.
pub struct Ask<'a> {
    /// The `{path}` or `{folder}` capture, already percent-decoded.
    pub target: String,
    pub query: &'a BTreeMap<String, String>,
    /// The absolute base URL, for the one route that describes the others.
    pub base: &'a str,
}

impl Ask<'_> {
    fn q(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str).filter(|v| !v.is_empty())
    }

    fn int(&self, name: &str, fallback: i64) -> i64 {
        self.q(name).and_then(|v| v.parse().ok()).unwrap_or(fallback)
    }

    fn flag(&self, name: &str, fallback: bool) -> bool {
        match self.q(name) {
            Some("true") => true,
            Some("false") => false,
            _ => fallback,
        }
    }
}

pub enum Outcome {
    Json(Json),
    Raw(RawBody),
}

pub struct Route {
    pub template: &'static str,
    pub operation_id: &'static str,
    pub summary: &'static str,
    /// The component name in the OpenAPI document, or `Bytes` / `Any`.
    pub schema: &'static str,
    pub params: &'static [Param],
    pub handler: fn(&Surface, &str, &Ask) -> Result<Outcome, Fault>,
}

impl Route {
    /// The fixed prefix a request path must start with, and whether the rest
    /// of the path is a capture.
    fn prefix(&self) -> (&'static str, bool) {
        match self.template.find('{') {
            Some(i) => (&self.template[..i], true),
            None => (self.template, false),
        }
    }

    pub fn matches(&self, path: &str) -> Option<String> {
        let (prefix, captures) = self.prefix();
        if captures {
            path.strip_prefix(prefix).map(percent_decode)
        } else if path == prefix {
            Some(String::new())
        } else {
            None
        }
    }
}

const PATH_PARAM: &[Param] = &[Param {
    name: "path",
    location: "path",
    required: true,
    ty: ArgType::Str,
    description: "Vault path.",
    default: None,
}];

pub static ROUTES: &[Route] = &[
    Route {
        template: "/api/v1/manifest",
        operation_id: "getManifest",
        summary: "The public subset of the manifest (§3.1).",
        schema: "Manifest",
        params: &[],
        handler: |s, _p, _a| Ok(Outcome::Json(s.manifest())),
    },
    Route {
        template: "/api/v1/me",
        operation_id: "getMe",
        summary: "The principal this request reduced to, and its subject set (§8.4).",
        schema: "Identity",
        params: &[],
        handler: |s, p, _a| Ok(Outcome::Json(s.me(p))),
    },
    Route {
        template: "/api/v1/openapi.json",
        operation_id: "getOpenapi",
        summary: "This document.",
        schema: "Any",
        params: &[],
        handler: |s, _p, a| Ok(Outcome::Json(openapi_document(s, a.base))),
    },
    Route {
        template: "/api/v1/node/{path}",
        operation_id: "getNode",
        summary: "Content plus metadata and edges, if `read` (§12.3).",
        schema: "NodeResponse",
        params: PATH_PARAM,
        handler: |s, p, a| Ok(Outcome::Json(s.node(p, &a.target)?)),
    },
    Route {
        template: "/api/v1/raw/{path}",
        operation_id: "getRaw",
        summary: "The bytes of a node, if `read`. May 302 to a presigned URL (§12.4).",
        schema: "Bytes",
        params: PATH_PARAM,
        handler: |s, p, a| Ok(Outcome::Raw(s.raw(p, &a.target)?)),
    },
    Route {
        template: "/api/v1/list/{folder}",
        operation_id: "listFolder",
        summary: "Direct entries of a folder, filtered to those with `list` (§12.3).",
        schema: "FolderListing",
        params: &[Param {
            name: "folder",
            location: "path",
            required: true,
            ty: ArgType::Str,
            description: "Folder path, or empty for the root.",
            default: None,
        }],
        handler: |s, p, a| Ok(Outcome::Json(s.list(p, &a.target)?)),
    },
    Route {
        template: "/api/v1/list",
        operation_id: "listRoot",
        summary: "Direct entries of the vault root.",
        schema: "FolderListing",
        params: &[],
        handler: |s, p, _a| Ok(Outcome::Json(s.list(p, "")?)),
    },
    Route {
        template: "/api/v1/nodes",
        operation_id: "listNodes",
        summary: "Every readable node entry, in §13.3 order.",
        schema: "NodeCatalogue",
        params: &[
            Param {
                name: "limit",
                location: "query",
                required: false,
                ty: ArgType::Int,
                description: "Maximum entries.",
                default: Some("100"),
            },
            Param {
                name: "offset",
                location: "query",
                required: false,
                ty: ArgType::Int,
                description: "Entries to skip.",
                default: Some("0"),
            },
            Param {
                name: "published",
                location: "query",
                required: false,
                ty: ArgType::Bool,
                description: "Exclude nodes whose frontmatter sets `publish: false`.",
                default: Some("false"),
            },
        ],
        handler: |s, p, a| {
            Ok(Outcome::Json(s.nodes(
                p,
                a.int("limit", 100),
                a.int("offset", 0),
                a.flag("published", false),
            )))
        },
    },
    Route {
        template: "/api/v1/links/{path}",
        operation_id: "getLinks",
        summary: "Out-edges and backlinks, redacted in place per §9.5.",
        schema: "LinkSet",
        params: PATH_PARAM,
        handler: |s, p, a| Ok(Outcome::Json(s.links(p, &a.target)?)),
    },
    Route {
        template: "/api/v1/search",
        operation_id: "search",
        summary: "Postings filtered to readable nodes, not merely re-ranked (§12.5).",
        schema: "SearchResult",
        params: &[
            Param {
                name: "q",
                location: "query",
                required: true,
                ty: ArgType::Str,
                description: "Query terms.",
                default: None,
            },
            Param {
                name: "limit",
                location: "query",
                required: false,
                ty: ArgType::Int,
                description: "Maximum hits.",
                default: Some("20"),
            },
            Param {
                name: "offset",
                location: "query",
                required: false,
                ty: ArgType::Int,
                description: "Hits to skip.",
                default: Some("0"),
            },
        ],
        handler: |s, p, a| {
            Ok(Outcome::Json(s.search(
                p,
                a.q("q").unwrap_or(""),
                a.int("limit", 20),
                a.int("offset", 0),
            )?))
        },
    },
    Route {
        template: "/api/v1/tree",
        operation_id: "getTree",
        summary: "The navigable tree, pruned to what is visible (§12.3).",
        schema: "TreeResponse",
        params: &[],
        handler: |s, p, _a| Ok(Outcome::Json(s.tree(p)?)),
    },
    Route {
        template: "/api/v1/tags",
        operation_id: "getTags",
        summary: "Tag postings, filtered to readable nodes (§9.6).",
        schema: "TagListing",
        params: &[],
        handler: |s, p, _a| Ok(Outcome::Json(s.tags(p)?)),
    },
    Route {
        template: "/api/v1/effective",
        operation_id: "getEffective",
        summary: "Effective rights with the deciding ACE per right; needs `read_acl` (§8.7).",
        schema: "Effective",
        params: &[
            Param {
                name: "path",
                location: "query",
                required: true,
                ty: ArgType::Str,
                description: "Vault path, or empty for the root folder.",
                default: None,
            },
            Param {
                name: "principal",
                location: "query",
                required: false,
                ty: ArgType::Str,
                description: "Defaults to the requesting principal.",
                default: None,
            },
        ],
        handler: |s, p, a| {
            Ok(Outcome::Json(s.effective(
                p,
                a.query.get("path").map(String::as_str).unwrap_or(""),
                a.q("principal"),
            )?))
        },
    },
];

pub fn route_for(path: &str) -> Option<(&'static Route, String)> {
    ROUTES
        .iter()
        .find_map(|r| r.matches(path).map(|target| (r, target)))
}

/// RFC 9457 problem details, carrying the legacy `error` member as well so a
/// client written against the pre-annex gatekeeper keeps working.
pub fn problem(fault: Fault, detail: Option<&str>) -> Json {
    let title = match fault {
        Fault::NotFound => "Not found",
        Fault::Forbidden => "Forbidden",
        Fault::Unauthenticated => "Authentication required",
        Fault::BadRequest => "Bad request",
        Fault::MethodNotAllowed => "Method not allowed",
        Fault::Internal => "Internal error",
    };
    let mut out = Json::obj()
        .set(
            "type",
            Json::str(format!("urn:basalt:problem:{}", fault.code())),
        )
        .set("title", Json::str(title))
        .set("error", Json::str(fault.code()));
    if let Some(d) = detail {
        out = out.set("detail", Json::str(d));
    }
    out.build()
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

// ------------------------------------------------------------------ OpenAPI

fn nullable(ty: &str) -> Json {
    Json::strings([ty, "null"])
}

fn prop(ty: &str, description: &str) -> Json {
    Json::obj()
        .set("type", Json::str(ty))
        .set("description", Json::str(description))
        .build()
}

fn simple(ty: &str) -> Json {
    Json::obj().set("type", Json::str(ty)).build()
}

fn array_of(items: Json) -> Json {
    Json::obj()
        .set("type", Json::str("array"))
        .set("items", items)
        .build()
}

fn reference(name: &str) -> Json {
    Json::obj()
        .set("$ref", Json::str(format!("#/components/schemas/{name}")))
        .build()
}

fn object_with(properties: Json) -> Json {
    Json::obj()
        .set("type", Json::str("object"))
        .set("properties", properties)
        .build()
}

/// The component schemas. Names and field names match the reference
/// implementation's document, so a client generated against either one works
/// against both — which is the whole claim INTEROP §9 tests.
fn schemas() -> Json {
    let heading = object_with(
        Json::obj()
            .set("level", simple("integer"))
            .set("slug", simple("string"))
            .set("text", simple("string"))
            .build(),
    );

    let node_entry = Json::obj()
        .set("type", Json::str("object"))
        .set(
            "description",
            Json::str("A node entry as it appears in index/nodes.json (§10.1)."),
        )
        .set(
            "required",
            Json::strings(["path", "id", "kind", "title", "content_hash"]),
        )
        .set(
            "properties",
            Json::obj()
                .set("path", prop("string", "Vault path (§2.1)."))
                .set("id", prop("string", "ULID node id (§4.1)."))
                .set(
                    "kind",
                    Json::obj()
                        .set("type", Json::str("string"))
                        .set("enum", Json::strings(["note", "data", "asset", "opaque"]))
                        .build(),
                )
                .set("title", simple("string"))
                .set("size", simple("integer"))
                .set(
                    "content_hash",
                    Json::obj()
                        .set("type", Json::str("string"))
                        .set("pattern", Json::str("^sha256:[0-9a-f]{64}$"))
                        .build(),
                )
                .set(
                    "etag",
                    prop(
                        "string",
                        "Store etag; excluded from conformance comparison (§13.2).",
                    ),
                )
                .set("publish", simple("boolean"))
                .set("tags", array_of(simple("string")))
                .set("aliases", array_of(simple("string")))
                .set("headings", array_of(heading))
                .set("errors", array_of(simple("string")))
                .build(),
        )
        .build();

    let entry_ref = object_with(
        Json::obj()
            .set("id", simple("string"))
            .set(
                "path",
                Json::obj()
                    .set("type", nullable("string"))
                    .set(
                        "description",
                        Json::str("Null when the reference is redacted (§9.5)."),
                    )
                    .build(),
            )
            .set("title", Json::obj().set("type", nullable("string")).build())
            .set("kind", simple("string"))
            .build(),
    );

    let link_edge = Json::obj()
        .set("type", Json::str("object"))
        .set(
            "description",
            Json::str(
                "A resolved edge from index/links.json (§10.2). `to: \"redacted\"` is §9.5.",
            ),
        )
        .set(
            "properties",
            Json::obj()
                .set("from", simple("string"))
                .set("to", Json::obj().set("type", nullable("string")).build())
                .set(
                    "kind",
                    Json::obj()
                        .set("type", Json::str("string"))
                        .set(
                            "enum",
                            Json::strings(["wiki", "embed", "md", "external", "tag"]),
                        )
                        .build(),
                )
                .set("raw", simple("string"))
                .set("alias", Json::obj().set("type", nullable("string")).build())
                .set("anchor", Json::obj().set("type", nullable("string")).build())
                .set("anchor_resolved", simple("boolean"))
                .set("ambiguous", simple("boolean"))
                .set("candidates", array_of(simple("string")))
                .set("line", simple("integer"))
                .set("col", simple("integer"))
                .set("target", reference("Entry"))
                .build(),
        )
        .build();

    let right = Json::obj()
        .set("type", Json::str("string"))
        .set(
            "enum",
            Json::strings(crate::acl::RIGHTS.iter().copied()),
        )
        .build();

    let link_set = object_with(
        Json::obj()
            .set("path", simple("string"))
            .set("out", array_of(reference("LinkEdge")))
            .set("backlinks", array_of(reference("Entry")))
            .build(),
    );

    let tree_node = Json::obj()
        .set("type", nullable("object"))
        .set(
            "properties",
            Json::obj()
                .set("folder", simple("string"))
                .set("title", simple("string"))
                .set("entries", array_of(reference("Entry")))
                .set("folders", array_of(reference("TreeNode")))
                .build(),
        )
        .build();

    Json::obj()
        .set("Any", Json::obj().build())
        .set(
            "Bytes",
            Json::obj()
                .set("type", Json::str("string"))
                .set("format", Json::str("binary"))
                .build(),
        )
        .set("NodeEntry", node_entry)
        .set("Entry", entry_ref)
        .set("LinkEdge", link_edge)
        .set("Right", right)
        .set(
            "Manifest",
            object_with(
                Json::obj()
                    .set(
                        "basalt",
                        Json::obj()
                            .set("type", Json::str("integer"))
                            .set("const", Json::Int(1))
                            .build(),
                    )
                    .set(
                        "vault",
                        object_with(
                            Json::obj()
                                .set("id", simple("string"))
                                .set("title", Json::obj().set("type", nullable("string")).build())
                                .build(),
                        ),
                    )
                    .set(
                        "publish",
                        object_with(
                            Json::obj()
                                .set(
                                    "audience",
                                    Json::obj()
                                        .set("type", Json::str("string"))
                                        .set(
                                            "enum",
                                            Json::strings(["public", "gated", "private"]),
                                        )
                                        .build(),
                                )
                                .set("home", Json::obj().set("type", nullable("string")).build())
                                .build(),
                        ),
                    )
                    .set(
                        "index_state",
                        Json::obj()
                            .set("type", Json::str("string"))
                            .set("enum", Json::strings(["fresh", "stale", "rebuilt"]))
                            .build(),
                    )
                    .build(),
            ),
        )
        .set(
            "Identity",
            object_with(
                Json::obj()
                    .set("principal", simple("string"))
                    .set(
                        "display_name",
                        Json::obj().set("type", nullable("string")).build(),
                    )
                    .set(
                        "subjects",
                        Json::obj()
                            .set("type", Json::str("array"))
                            .set("items", simple("string"))
                            .set(
                                "description",
                                Json::str("The effective subject set used by §8.4 step 1."),
                            )
                            .build(),
                    )
                    .set("anonymous", simple("boolean"))
                    .build(),
            ),
        )
        .set(
            "NodeResponse",
            object_with(
                Json::obj()
                    .set("node", reference("NodeEntry"))
                    .set(
                        "text",
                        Json::obj()
                            .set("type", nullable("string"))
                            .set("description", Json::str("Null for binary kinds."))
                            .build(),
                    )
                    .set("media_type", simple("string"))
                    .set("links", reference("LinkSet"))
                    .build(),
            ),
        )
        .set(
            "NodeCatalogue",
            object_with(
                Json::obj()
                    .set("total", simple("integer"))
                    .set("offset", simple("integer"))
                    .set("limit", simple("integer"))
                    .set("entries", array_of(reference("NodeEntry")))
                    .build(),
            ),
        )
        .set(
            "FolderListing",
            object_with(
                Json::obj()
                    .set("folder", simple("string"))
                    .set("entries", array_of(reference("Entry")))
                    .set("folders", array_of(simple("string")))
                    .build(),
            ),
        )
        .set("LinkSet", link_set)
        .set(
            "SearchResult",
            object_with(
                Json::obj()
                    .set("query", simple("string"))
                    .set("total", simple("integer"))
                    .set("offset", simple("integer"))
                    .set(
                        "hits",
                        array_of(
                            Json::obj()
                                .set(
                                    "allOf",
                                    Json::arr([
                                        reference("NodeEntry"),
                                        object_with(
                                            Json::obj().set("score", simple("integer")).build(),
                                        ),
                                    ]),
                                )
                                .build(),
                        ),
                    )
                    .build(),
            ),
        )
        .set(
            "TreeResponse",
            object_with(Json::obj().set("tree", reference("TreeNode")).build()),
        )
        .set("TreeNode", tree_node)
        .set(
            "TagListing",
            object_with(
                Json::obj()
                    .set(
                        "tags",
                        array_of(object_with(
                            Json::obj()
                                .set("tag", simple("string"))
                                .set("nodes", array_of(reference("Entry")))
                                .build(),
                        )),
                    )
                    .build(),
            ),
        )
        .set(
            "Effective",
            object_with(
                Json::obj()
                    .set("principal", simple("string"))
                    .set("path", simple("string"))
                    .set("granted", array_of(reference("Right")))
                    .set(
                        "decisions",
                        Json::obj()
                            .set("type", Json::str("object"))
                            .set(
                                "additionalProperties",
                                object_with(
                                    Json::obj()
                                        .set(
                                            "decision",
                                            Json::obj()
                                                .set("type", Json::str("string"))
                                                .set("enum", Json::strings(["allow", "deny"]))
                                                .build(),
                                        )
                                        .set("by", prop("string", "The deciding ACE (§8.7)."))
                                        .set(
                                            "failed_at",
                                            Json::obj().set("type", nullable("string")).build(),
                                        )
                                        .build(),
                                ),
                            )
                            .build(),
                    )
                    .set(
                        "failed_at",
                        Json::obj()
                            .set("type", nullable("string"))
                            .set(
                                "description",
                                Json::str("The ancestor whose traverse check failed (§8.5)."),
                            )
                            .build(),
                    )
                    .build(),
            ),
        )
        .set(
            "Problem",
            Json::obj()
                .set("type", Json::str("object"))
                .set(
                    "description",
                    Json::str(
                        "RFC 9457 problem details. `error` repeats the code for older clients.",
                    ),
                )
                .set(
                    "properties",
                    Json::obj()
                        .set("type", simple("string"))
                        .set("title", simple("string"))
                        .set("detail", simple("string"))
                        .set("error", simple("string"))
                        .build(),
                )
                .build(),
        )
        .build()
}

fn problem_response(description: &str) -> Json {
    Json::obj()
        .set("description", Json::str(description))
        .set(
            "content",
            Json::obj()
                .set(
                    "application/problem+json",
                    Json::obj().set("schema", reference("Problem")).build(),
                )
                .build(),
        )
        .build()
}

/// The OpenAPI 3.1 document for the REST surface, generated from [`ROUTES`].
pub fn openapi_document(surface: &Surface, base: &str) -> Json {
    let mut paths = Json::obj();
    for r in ROUTES {
        let parameters = Json::arr(r.params.iter().map(|p| {
            let mut schema = Json::obj().set("type", Json::str(p.ty.json_schema_type()));
            if let Some(d) = p.default {
                schema = match p.ty {
                    ArgType::Int => schema.set("default", Json::Int(d.parse().unwrap_or(0))),
                    ArgType::Bool => schema.set("default", Json::Bool(d == "true")),
                    ArgType::Str => schema.set("default", Json::str(d)),
                };
            }
            Json::obj()
                .set("name", Json::str(p.name))
                .set("in", Json::str(p.location))
                .set("required", Json::Bool(p.required))
                .set("description", Json::str(p.description))
                .set("schema", schema.build())
                .build()
        }));

        let content = if r.schema == "Bytes" {
            Json::obj()
                .set(
                    "*/*",
                    Json::obj().set("schema", reference("Bytes")).build(),
                )
                .build()
        } else {
            Json::obj()
                .set(
                    "application/json",
                    Json::obj().set("schema", reference(r.schema)).build(),
                )
                .build()
        };

        let mut responses = Json::obj()
            .set(
                "200",
                Json::obj()
                    .set("description", Json::str("OK"))
                    .set("content", content)
                    .set(
                        "headers",
                        Json::obj()
                            .set(
                                "ETag",
                                Json::obj().set("schema", simple("string")).build(),
                            )
                            .set(
                                "X-Basalt-Vault",
                                Json::obj().set("schema", simple("string")).build(),
                            )
                            .set(
                                "X-Basalt-Index-State",
                                Json::obj()
                                    .set(
                                        "schema",
                                        Json::obj()
                                            .set("type", Json::str("string"))
                                            .set(
                                                "enum",
                                                Json::strings(["fresh", "stale", "rebuilt"]),
                                            )
                                            .build(),
                                    )
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            )
            .set(
                "304",
                Json::obj()
                    .set("description", Json::str("Not modified."))
                    .build(),
            )
            .set(
                "403",
                problem_response(
                    "The principal may know the object exists but lacks `read` (§12.3).",
                ),
            )
            .set(
                "404",
                problem_response(
                    "No such object, or the principal may not discover it (§12.3).",
                ),
            );

        if r.schema == "Bytes" {
            responses = responses.set(
                "302",
                Json::obj()
                    .set(
                        "description",
                        Json::str("Presigned redirect, in `redirect` delivery mode (§12.4)."),
                    )
                    .set(
                        "headers",
                        Json::obj()
                            .set(
                                "Location",
                                Json::obj()
                                    .set(
                                        "schema",
                                        Json::obj()
                                            .set("type", Json::str("string"))
                                            .set("format", Json::str("uri"))
                                            .build(),
                                    )
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            );
        }

        let mut operation = Json::obj()
            .set("operationId", Json::str(r.operation_id))
            .set("summary", Json::str(r.summary))
            .set("responses", responses.build());
        if !r.params.is_empty() {
            operation = operation.set("parameters", parameters);
        }
        paths = paths.set(
            r.template,
            Json::obj().set("get", operation.build()).build(),
        );
    }

    Json::obj()
        .set("openapi", Json::str("3.1.0"))
        .set(
            "info",
            Json::obj()
                .set(
                    "title",
                    Json::str(format!("Basalt gatekeeper — {}", surface.vault_id())),
                )
                .set("version", Json::str("1.0.0"))
                .set(
                    "summary",
                    Json::str("Read surface for a Basalt vault, enforcing §8 on every response."),
                )
                .set(
                    "description",
                    Json::str(
                        "Every response is evaluated for the requesting principal (§8.4). A 404 \
                         means either \"no such object\" or \"you may not discover it\" and the \
                         two are deliberately indistinguishable (§12.3). Derived responses are \
                         private: their etag depends on the requester's subject set (§12.5).",
                    ),
                )
                .set(
                    "license",
                    Json::obj()
                        .set("name", Json::str("MIT"))
                        .set("identifier", Json::str("MIT"))
                        .build(),
                )
                .build(),
        )
        .set(
            "servers",
            Json::arr([Json::obj().set("url", Json::str(base)).build()]),
        )
        .set("paths", paths.build())
        .set(
            "components",
            Json::obj()
                .set("schemas", schemas())
                .set(
                    "securitySchemes",
                    // §12.1 puts authentication out of scope: the gatekeeper
                    // must reduce a request to exactly one principal and must
                    // never let a client assert its own id. These are the
                    // shapes deployments actually use.
                    Json::obj()
                        .set(
                            "bearer",
                            Json::obj()
                                .set("type", Json::str("http"))
                                .set("scheme", Json::str("bearer"))
                                .build(),
                        )
                        .set(
                            "cookie",
                            Json::obj()
                                .set("type", Json::str("apiKey"))
                                .set("in", Json::str("cookie"))
                                .set("name", Json::str("session"))
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .build()
}

/// Every operation in the shared table reachable over REST, for the discovery
/// document (INTEROP §1.4).
pub fn operation_names() -> Vec<&'static str> {
    ops::OPERATIONS.iter().map(|o| o.name).collect()
}
