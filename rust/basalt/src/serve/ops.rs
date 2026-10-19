//! The operation table, INTEROP §1.2.
//!
//! REST has a route per operation and the method-call surfaces (MCP tools,
//! and JSON-RPC or gRPC when a deployment adds them) have one entry each.
//! They are the same operations, so they are declared once here with the
//! arguments each takes, and every surface projects this table into its own
//! naming convention: `basalt.<name>` for JSON-RPC, `basalt_<name>` for an
//! MCP tool, the `proto` field for gRPC.
//!
//! `conformance/cases/interop/surfaces.yaml` pins the names, the spellings and
//! which arguments are required; the interop test reads them from there rather
//! than from this file, so a rename here fails against the corpus.

use super::surface::{base64, Answer, Fault, RawBody, Surface};
use crate::canonical::Json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgType {
    Str,
    Int,
    Bool,
}

impl ArgType {
    pub fn json_schema_type(self) -> &'static str {
        match self {
            Self::Str => "string",
            Self::Int => "integer",
            Self::Bool => "boolean",
        }
    }
}

pub struct Arg {
    pub name: &'static str,
    pub ty: ArgType,
    pub required: bool,
    pub description: &'static str,
    /// Rendered into the JSON Schema `default`, and into the OpenAPI
    /// parameter, so a client sees the same defaults the code applies.
    pub default: Option<&'static str>,
}

pub struct Operation {
    pub name: &'static str,
    /// The gRPC/Connect method name (INTEROP §5), declared even where this
    /// implementation does not yet serve that profile, so the table stays the
    /// one place the spellings live.
    pub proto: &'static str,
    pub summary: &'static str,
    pub args: &'static [Arg],
    pub call: fn(&Surface, &str, &Json) -> Answer,
}

impl Operation {
    /// The JSON Schema an MCP client gets for `tools/list`.
    pub fn input_schema(&self) -> Json {
        let mut properties = Json::obj();
        for a in self.args {
            let mut prop = Json::obj()
                .set("type", Json::str(a.ty.json_schema_type()))
                .set("description", Json::str(a.description));
            if let Some(d) = a.default {
                prop = prop.set("default", literal(a.ty, d));
            }
            properties = properties.set(a.name, prop.build());
        }
        Json::obj()
            .set("type", Json::str("object"))
            .set("properties", properties.build())
            .set(
                "required",
                Json::strings(self.args.iter().filter(|a| a.required).map(|a| a.name)),
            )
            .set("additionalProperties", Json::Bool(false))
            .build()
    }
}

fn literal(ty: ArgType, raw: &str) -> Json {
    match ty {
        ArgType::Int => Json::Int(raw.parse().unwrap_or(0)),
        ArgType::Bool => Json::Bool(raw == "true"),
        ArgType::Str => Json::str(raw),
    }
}

// ------------------------------------------------------- argument accessors

pub fn opt_str<'a>(params: &'a Json, name: &str) -> Option<&'a str> {
    params.get(name).and_then(|v| v.as_str())
}

pub fn need_str<'a>(params: &'a Json, name: &str) -> Result<&'a str, Fault> {
    match opt_str(params, name) {
        Some(v) if !v.is_empty() => Ok(v),
        // A missing required argument is the client's mistake, and §12.3's
        // ambiguity rule does not apply to it: there is no object involved yet.
        _ => Err(Fault::BadRequest),
    }
}

pub fn int_or(params: &Json, name: &str, fallback: i64) -> i64 {
    match params.get(name) {
        Some(Json::Int(i)) => *i,
        // A JSON-RPC or proto3-JSON client may send a 64-bit integer as a
        // string; accepting both costs nothing and refusing one is a mystery.
        Some(Json::Str(s)) => s.parse().unwrap_or(fallback),
        _ => fallback,
    }
}

pub fn bool_or(params: &Json, name: &str, fallback: bool) -> bool {
    match params.get(name) {
        Some(Json::Bool(b)) => *b,
        Some(Json::Str(s)) => s == "true",
        _ => fallback,
    }
}

// ------------------------------------------------------------- the table

const NO_ARGS: &[Arg] = &[];

pub static OPERATIONS: &[Operation] = &[
    Operation {
        name: "manifest",
        proto: "GetManifest",
        summary: "The vault manifest: id, title, audience, index freshness (§3.1).",
        args: NO_ARGS,
        call: |s, _p, _a| Ok(s.manifest()),
    },
    Operation {
        name: "me",
        proto: "GetIdentity",
        summary: "The principal this request reduced to, and its subject set (§8.4).",
        args: NO_ARGS,
        call: |s, p, _a| Ok(s.me(p)),
    },
    Operation {
        name: "node",
        proto: "GetNode",
        summary: "Read one node: metadata, text and edges, if the principal holds `read`.",
        args: &[
            Arg {
                name: "path",
                ty: ArgType::Str,
                required: true,
                description: "Vault path, e.g. \"Notes/Columns.md\".",
                default: None,
            },
            Arg {
                name: "include_text",
                ty: ArgType::Bool,
                required: false,
                description: "Include the UTF-8 text. Default true.",
                default: Some("true"),
            },
            Arg {
                name: "include_bytes",
                ty: ArgType::Bool,
                required: false,
                description: "Include the raw bytes, base64-encoded. Default false.",
                default: Some("false"),
            },
        ],
        call: |s, p, a| {
            let path = need_str(a, "path")?;
            let mut out = s.node(p, path)?;
            let obj = out.as_object_mut().expect("node response is an object");
            if !bool_or(a, "include_text", true) {
                obj.remove("text");
            }
            if bool_or(a, "include_bytes", false) {
                // Bytes, never a presigned URL: §12.4 keeps a bearer token out
                // of any body a client may cache.
                let encoded = match s.raw(p, path)? {
                    RawBody::Bytes { bytes, .. } => Json::str(base64(&bytes)),
                    RawBody::Redirect(_) => Json::Null,
                };
                obj.insert("base64".into(), encoded);
            }
            Ok(out)
        },
    },
    Operation {
        name: "list",
        proto: "ListFolder",
        summary: "Direct entries of a folder, filtered to those the principal may see.",
        args: &[Arg {
            name: "folder",
            ty: ArgType::Str,
            required: false,
            description: "Folder path with a trailing slash, or \"\" for the root.",
            default: None,
        }],
        call: |s, p, a| s.list(p, opt_str(a, "folder").unwrap_or("")),
    },
    Operation {
        name: "nodes",
        proto: "ListNodes",
        summary: "Every readable node entry, in §13.3 order.",
        args: &[
            Arg {
                name: "limit",
                ty: ArgType::Int,
                required: false,
                description: "Maximum entries. Default 100, cap 1000.",
                default: Some("100"),
            },
            Arg {
                name: "offset",
                ty: ArgType::Int,
                required: false,
                description: "Entries to skip.",
                default: Some("0"),
            },
            Arg {
                name: "published",
                ty: ArgType::Bool,
                required: false,
                description: "Exclude nodes whose frontmatter sets publish: false.",
                default: Some("false"),
            },
        ],
        call: |s, p, a| {
            Ok(s.nodes(
                p,
                int_or(a, "limit", 100),
                int_or(a, "offset", 0),
                bool_or(a, "published", false),
            ))
        },
    },
    Operation {
        name: "links",
        proto: "GetLinks",
        summary: "Out-edges and backlinks for a node. Invisible targets are redacted (§9.5).",
        args: &[Arg {
            name: "path",
            ty: ArgType::Str,
            required: true,
            description: "Vault path.",
            default: None,
        }],
        call: |s, p, a| s.links(p, need_str(a, "path")?),
    },
    Operation {
        name: "search",
        proto: "Search",
        summary: "Full-text search over readable nodes only (§12.5).",
        args: &[
            Arg {
                name: "q",
                ty: ArgType::Str,
                required: true,
                description: "Query terms.",
                default: None,
            },
            Arg {
                name: "limit",
                ty: ArgType::Int,
                required: false,
                description: "Maximum hits. Default 20, cap 200.",
                default: Some("20"),
            },
            Arg {
                name: "offset",
                ty: ArgType::Int,
                required: false,
                description: "Hits to skip.",
                default: Some("0"),
            },
        ],
        call: |s, p, a| {
            s.search(
                p,
                need_str(a, "q")?,
                int_or(a, "limit", 20),
                int_or(a, "offset", 0),
            )
        },
    },
    Operation {
        name: "tree",
        proto: "GetTree",
        summary: "The navigable folder tree, pruned to what the principal may see.",
        args: NO_ARGS,
        call: |s, p, _a| s.tree(p),
    },
    Operation {
        name: "tags",
        proto: "GetTags",
        summary: "Tags and the readable nodes carrying them (§9.6).",
        args: NO_ARGS,
        call: |s, p, _a| s.tags(p),
    },
    Operation {
        name: "recent",
        proto: "GetRecent",
        summary: "Readable nodes by store mtime, newest first.",
        args: &[
            Arg {
                name: "limit",
                ty: ArgType::Int,
                required: false,
                description: "Maximum entries. Default 20, cap 500.",
                default: Some("20"),
            },
            Arg {
                name: "published",
                ty: ArgType::Bool,
                required: false,
                description: "Exclude nodes whose frontmatter sets publish: false. Default true.",
                default: Some("true"),
            },
        ],
        call: |s, p, a| {
            Ok(s.recent(
                p,
                int_or(a, "limit", 20),
                bool_or(a, "published", true),
            ))
        },
    },
    Operation {
        name: "effective",
        proto: "GetEffectiveRights",
        summary: "Effective rights and the deciding ACE per right. Needs `read_acl` (§8.7).",
        args: &[
            Arg {
                name: "path",
                ty: ArgType::Str,
                required: true,
                description: "Vault path, or \"\" for the root folder.",
                default: None,
            },
            Arg {
                name: "principal",
                ty: ArgType::Str,
                required: false,
                description: "Principal to evaluate. Defaults to the caller.",
                default: None,
            },
        ],
        call: |s, p, a| {
            // `path: ""` is the root folder and a legitimate question, so this
            // one reads the argument without insisting it be non-empty.
            let path = opt_str(a, "path").ok_or(Fault::BadRequest)?;
            s.effective(p, path, opt_str(a, "principal"))
        },
    },
];

pub fn by_name(name: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|o| o.name == name)
}

pub fn by_proto(method: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|o| o.proto == method)
}
