//! The write operation, PROTOCOL §12.7.
//!
//! Kept apart from `ops.rs` on purpose. `ops.rs` is every read operation, and
//! its table is projected into REST and MCP at once, which is what keeps them
//! equivalent. A write must not arrive on both by accident: it is offered by
//! the one transport where the caller is a local process the operator started
//! and named a principal for (`basalt mcp --writable`), and nowhere else.
//!
//! No behaviour here: authorization, collisions and identity all live in
//! [`crate::store`]. This file turns tool arguments into bytes and tells the
//! surface its cache is stale.

use super::surface::{base64_decode, Surface};
use crate::canonical::Json;
use crate::store::{store_object, Provenance, StoreError, StoreRequest, MAX_STORE_BYTES};
use crate::yamltext::Out;

pub const STORE_SUMMARY: &str = "Store a NEW note, image or other file in the vault. The \
extension of `path` decides what it is: .md is a note; .png, .jpg, .pdf and the like are \
assets; .json/.yaml are data. Give `text` for anything that is UTF-8 text, `base64` for \
binary. Never overwrites: a path that already exists is a conflict, so choose another. Needs \
`create_child` on the folder. Do not write a `basalt:` block: the id is assigned, and the \
vault stamps who stored it (`created_by`: the agent, the account and the credentials behind \
them), replacing anything you put there. Returns the id and a `link` you can paste into a note.";

/// The `basalt_store` input schema, the same one the reference serves.
pub fn store_input_schema() -> Json {
    let s = |d: &str| Json::obj().set("type", Json::str("string")).set("description", Json::str(d)).build();
    Json::obj()
        .set("type", Json::str("object"))
        .set(
            "properties",
            Json::obj()
                .set(
                    "path",
                    s("Where to put it, relative to the vault root, e.g. \"Notes/Idea.md\" or \
                       \"Assets/photo.png\". Files other than notes must be inside a folder."),
                )
                .set("text", s("The content, for a note or other UTF-8 text file. Not with base64."))
                .set("base64", s("The content, base64-encoded, for an image or any binary file. Not with text."))
                .set("title", s("A note's frontmatter title (if it has none), or an asset's display title."))
                .set("alt", s("Alt text for an image or other asset."))
                .build(),
        )
        .set("required", Json::arr([Json::str("path")]))
        .set("additionalProperties", Json::Bool(false))
        .build()
}

/// MCP tool annotations: this adds an object and changes nothing that
/// exists, a stronger statement than most write tools can make.
pub fn store_annotations() -> Json {
    Json::obj()
        .set("readOnlyHint", Json::Bool(false))
        .set("destructiveHint", Json::Bool(false))
        .set("idempotentHint", Json::Bool(false))
        .set("openWorldHint", Json::Bool(false))
        .build()
}

fn out_json(o: &Out) -> Json {
    match o {
        Out::Str(s) => Json::str(s),
        Out::Map(m) => {
            let mut b = Json::obj();
            for (k, v) in m {
                b = b.set(k, out_json(v));
            }
            b.build()
        }
    }
}

/// Store one new object as `principal`, through the surface. `who` is the
/// connection's agent, account, caller and client, fixed by the operator and
/// the handshake — a separate argument from `args`, which is whatever the
/// model sent, because the model does not get to say who it is.
pub fn store_through(surface: &Surface, principal: &str, args: &Json, who: &Provenance) -> Result<Json, StoreError> {
    let str_arg = |k: &str| -> Result<Option<String>, StoreError> {
        match args.get(k) {
            None | Some(Json::Null) => Ok(None),
            Some(Json::Str(s)) => Ok(Some(s.clone())),
            Some(_) => Err(StoreError::bad(format!("{k} must be a string"))),
        }
    };
    let path = str_arg("path")?.unwrap_or_default();
    let text = str_arg("text")?;
    let b64 = str_arg("base64")?;
    let bytes = match (text, b64) {
        (Some(t), None) => t.into_bytes(),
        (None, Some(b)) => {
            if b.len() > MAX_STORE_BYTES.div_ceil(3) * 4 + b.len() / 76 * 2 + 4 {
                return Err(StoreError {
                    code: "too_large",
                    status: 413,
                    detail: format!("over the {MAX_STORE_BYTES} byte limit"),
                });
            }
            base64_decode(&b).ok_or_else(|| {
                StoreError::bad("base64 must be the bare encoding of the bytes, not a data: URI")
            })?
        }
        _ => return Err(StoreError::bad("give exactly one of text or base64")),
    };
    let title = str_arg("title")?;
    let alt = str_arg("alt")?;

    let result = surface.with_vault_mut(|v| {
        store_object(
            v,
            &StoreRequest {
                principal: Some(principal),
                path: &path,
                bytes: &bytes,
                title: title.as_deref(),
                alt: alt.as_deref(),
                provenance: Some(who),
                reindex: true,
                max_bytes: None,
            },
        )
    });
    // Dropped on failure too: a store that wrote the object and then failed
    // to refresh the indexes has still changed what is on disk.
    surface.invalidate();
    let stored = result?;
    surface.set_index_state(crate::vault::IndexState::Fresh);

    // Ready to paste into a note; the path form is unambiguous (§9.3).
    let kind = stored.kind.as_str();
    let target = if kind == "note" {
        let lower = stored.path.to_lowercase();
        if lower.ends_with(".markdown") {
            stored.path[..stored.path.len() - 9].to_string()
        } else if lower.ends_with(".md") {
            stored.path[..stored.path.len() - 3].to_string()
        } else {
            stored.path.clone()
        }
    } else {
        stored.path.clone()
    };
    let link = if kind == "asset" { format!("![[{target}]]") } else { format!("[[{target}]]") };
    let mut out = Json::obj()
        .set("path", Json::str(&stored.path))
        .set("id", Json::str(&stored.id))
        .set("kind", Json::str(kind))
        .set("media_type", Json::str(stored.media_type))
        .set("size", Json::Int(stored.size as i64))
        .set("content_hash", Json::str(&stored.content_hash))
        .set("created", Json::Bool(true))
        .set("link", Json::str(link));
    if let Some(by) = &stored.created_by {
        out = out.set("created_by", out_json(by));
    }
    Ok(out.build())
}
