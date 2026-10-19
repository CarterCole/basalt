//! The Model Context Protocol surface, INTEROP §4.2.
//!
//! An MCP client — an agent, an editor, a desktop assistant — gets the vault
//! as tools plus resources, over the JSON-RPC framing in [`super::jsonrpc`].
//! The point of routing it through [`Surface`] rather than handing a model the
//! bucket is §8: a model driving this connection sees exactly what its
//! principal sees, and `tools/call` on an unreadable node comes back as a tool
//! error rather than as content.

use super::jsonrpc::{Methods, RpcError, INVALID_PARAMS};
use super::ops::{self, OPERATIONS};
use super::surface::{base64, RawBody, Surface};
use crate::canonical::Json;

/// Versions this server speaks, newest first (INTEROP §4.2.1).
pub const MCP_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
pub const MCP_LATEST: &str = MCP_VERSIONS[0];

/// MCP's own "resource not found", from the spec's error examples.
pub const RESOURCE_ERROR: i64 = -32002;

pub const TOOL_PREFIX: &str = "basalt_";

const INSTRUCTIONS: &str = "This server exposes one Basalt vault — a markdown knowledge
vault in an object store. Every call is evaluated against the vault's access
control list for the principal this connection was opened as, so the tools
return that principal's view and nothing else. A node that is missing and a
node that exists but may not be discovered are deliberately indistinguishable.

Start with basalt_tree or basalt_search to find paths, then basalt_node to read
one. basalt_links gives the graph around a node; an edge whose target reads
\"redacted\" points at a node this principal may not see, and is kept rather than
dropped so the graph stays honest.";

/// The MCP tool list, projected from the shared operation table.
pub fn tools() -> Json {
    Json::arr(OPERATIONS.iter().map(|op| {
        Json::obj()
            .set("name", Json::str(format!("{TOOL_PREFIX}{}", op.name)))
            .set("description", Json::str(op.summary))
            .set("inputSchema", op.input_schema())
            .build()
    }))
}

/// Percent-encode one path segment.
///
/// The unreserved set is JavaScript's `encodeURIComponent`, not RFC 3986's,
/// so a resource URI from this implementation is byte-identical to one from
/// the reference — a client holding both open must see one id per node.
fn encode_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        let keep = b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b);
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn decode(s: &str) -> String {
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

pub fn uri_for(vault_id: &str, path: &str) -> String {
    let encoded: Vec<String> = path.split('/').map(encode_segment).collect();
    format!("basalt://{vault_id}/{}", encoded.join("/"))
}

/// `basalt://<vault>/<path>` back to a vault path.
fn path_from_uri(vault_id: &str, uri: &str) -> Result<String, RpcError> {
    let rest = uri
        .strip_prefix("basalt://")
        .ok_or_else(|| RpcError::new(INVALID_PARAMS, format!("unsupported scheme: {uri}")))?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a, p),
        None => (rest, ""),
    };
    // A client holding several vaults open must not cross them.
    if !authority.is_empty() && !authority.eq_ignore_ascii_case(vault_id) {
        return Err(RpcError::new(
            RESOURCE_ERROR,
            format!("resource belongs to another vault: {authority}"),
        ));
    }
    Ok(decode(path))
}

fn mime_for(entry: Option<&Json>, media_type: &str) -> String {
    match entry.and_then(|e| e.get("kind")).and_then(|k| k.as_str()) {
        Some("note") => "text/markdown".to_string(),
        _ => media_type.to_string(),
    }
}

/// Build the method table for one principal.
///
/// Stateless by design: the HTTP transport builds a table per request so the
/// principal cannot outlive the request that established it (§12.1), and the
/// stdio transport builds one for the life of the process.
pub fn methods<'a>(
    surface: &'a Surface,
    principal: &'a str,
    server_version: &'a str,
) -> Methods<'a> {
    Methods::new()
        .on("initialize", move |params| {
            let asked = params.get("protocolVersion").and_then(|v| v.as_str());
            // §4.2.1: echo a version we both speak, else answer with ours and
            // let the client decide. Silently pretending to speak the client's
            // version is how a handshake turns into a mystery later.
            let version = match asked {
                Some(v) if MCP_VERSIONS.contains(&v) => v,
                _ => MCP_LATEST,
            };
            let title = surface.with_vault(|v| {
                v.manifest
                    .vault_title
                    .clone()
                    .unwrap_or_else(|| v.manifest.vault_id.clone())
            });
            Ok(Json::obj()
                .set("protocolVersion", Json::str(version))
                .set(
                    "capabilities",
                    Json::obj()
                        .set(
                            "tools",
                            Json::obj().set("listChanged", Json::Bool(false)).build(),
                        )
                        .set(
                            "resources",
                            Json::obj()
                                .set("listChanged", Json::Bool(false))
                                .set("subscribe", Json::Bool(false))
                                .build(),
                        )
                        .build(),
                )
                .set(
                    "serverInfo",
                    Json::obj()
                        .set("name", Json::str("basalt"))
                        .set("version", Json::str(server_version))
                        .set("title", Json::str(format!("Basalt vault {title}")))
                        .build(),
                )
                .set("instructions", Json::str(INSTRUCTIONS))
                .build())
        })
        .on("notifications/initialized", |_| Ok(Json::obj().build()))
        .on("notifications/cancelled", |_| Ok(Json::obj().build()))
        .on("ping", |_| Ok(Json::obj().build()))
        .on("tools/list", |_| {
            Ok(Json::obj().set("tools", tools()).build())
        })
        .on("tools/call", move |params| {
            let raw = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let name = raw.strip_prefix(TOOL_PREFIX).unwrap_or(raw);
            let Some(op) = ops::by_name(name) else {
                return Err(RpcError::new(
                    INVALID_PARAMS,
                    format!("unknown tool {raw}"),
                ));
            };
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Json::obj().build());
            match (op.call)(surface, principal, &args) {
                Ok(data) => Ok(Json::obj()
                    .set(
                        "content",
                        Json::arr([Json::obj()
                            .set("type", Json::str("text"))
                            .set("text", Json::str(data.to_canonical_string()))
                            .build()]),
                    )
                    .build()),
                // A denial is a tool result, not a transport error: the model
                // asked a reasonable question and the answer is "you may not
                // see that", which it needs to be able to read.
                Err(fault) => Ok(Json::obj()
                    .set("isError", Json::Bool(true))
                    .set(
                        "content",
                        Json::arr([Json::obj()
                            .set("type", Json::str("text"))
                            .set(
                                "text",
                                Json::str(
                                    Json::obj()
                                        .set("error", Json::str(fault.code()))
                                        .set("status", Json::Int(fault.status() as i64))
                                        .build()
                                        .to_canonical_string(),
                                ),
                            )
                            .build()]),
                    )
                    .build()),
            }
        })
        .on("resources/list", move |params| {
            let vault_id = surface.vault_id();
            let entries = surface.readable(principal, false);
            let cursor = ops::int_or(params, "cursor", 0).max(0) as usize;
            let page: Vec<&Json> = entries.iter().skip(cursor).take(100).collect();
            let listed = page.len();
            let resources = Json::arr(page.into_iter().map(|e| {
                let path = e.get("path").and_then(|p| p.as_str()).unwrap_or_default();
                Json::obj()
                    .set("uri", Json::str(uri_for(&vault_id, path)))
                    .set("name", Json::str(path))
                    .set("title", Json::opt_str(e.get("title").and_then(|t| t.as_str())))
                    .set(
                        "mimeType",
                        Json::str(mime_for(Some(e), "application/octet-stream")),
                    )
                    .set(
                        "size",
                        Json::Int(match e.get("size") {
                            Some(Json::Int(n)) => *n,
                            _ => 0,
                        }),
                    )
                    .build()
            }));
            let mut out = Json::obj().set("resources", resources);
            if cursor + listed < entries.len() {
                out = out.set("nextCursor", Json::str((cursor + listed).to_string()));
            }
            Ok(out.build())
        })
        .on("resources/templates/list", |_| {
            Ok(Json::obj()
                .set(
                    "resourceTemplates",
                    Json::arr([Json::obj()
                        .set("uriTemplate", Json::str("basalt://{vault}/{path}"))
                        .set("name", Json::str("vault-node"))
                        .set("title", Json::str("A node in a Basalt vault"))
                        .set(
                            "description",
                            Json::str(
                                "The bytes of one node, if the principal holds `read` on it (§8.1).",
                            ),
                        )
                        .build()]),
                )
                .build())
        })
        .on("resources/read", move |params| {
            let uri = params
                .get("uri")
                .and_then(|u| u.as_str())
                .ok_or_else(|| RpcError::new(INVALID_PARAMS, "uri is required"))?;
            let vault_id = surface.vault_id();
            let path = path_from_uri(&vault_id, uri)?;

            let fail = |fault: super::surface::Fault| {
                RpcError::with_data(
                    RESOURCE_ERROR,
                    fault.code(),
                    Json::obj()
                        .set("uri", Json::str(uri))
                        .set("status", Json::Int(fault.status() as i64))
                        .build(),
                )
            };

            let node = surface.node(principal, &path).map_err(fail)?;
            let text = node.get("text").and_then(|t| t.as_str()).map(String::from);
            let media = node
                .get("media_type")
                .and_then(|m| m.as_str())
                .unwrap_or("application/octet-stream");
            let mime = mime_for(node.get("node"), media);

            let content = match text {
                Some(text) => Json::obj()
                    .set("uri", Json::str(uri))
                    .set("mimeType", Json::str(mime))
                    .set("text", Json::str(text))
                    .build(),
                None => {
                    let bytes = match surface.raw(principal, &path).map_err(fail)? {
                        RawBody::Bytes { bytes, .. } => bytes,
                        // §12.4 keeps a presigned URL out of every body; a
                        // redirect-mode deployment serves resources as bytes.
                        RawBody::Redirect(_) => Vec::new(),
                    };
                    Json::obj()
                        .set("uri", Json::str(uri))
                        .set("mimeType", Json::str(mime))
                        .set("blob", Json::str(base64(&bytes)))
                        .build()
                }
            };
            Ok(Json::obj()
                .set("contents", Json::arr([content]))
                .build())
        })
}
