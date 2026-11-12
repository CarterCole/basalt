//! Moving folders to and from GitHub gists: `basalt gist export` and
//! `basalt gist import`.
//!
//! These are copies between a vault, in whatever store it lives, and one gist.
//! They are not sync: nothing is merged, and an import never overwrites.
//!
//! - **export** reads a folder of the vault and writes its text files to a
//!   gist. A gist is flat, so a file's path inside the folder becomes one file
//!   name ([`encode_name`]). Anything a gist cannot hold, a binary file or an
//!   empty one, is left out and reported by name, never dropped silently.
//! - **import** reads every file of a gist and stores each as a NEW object
//!   under a folder of the vault (§12.7): it gets an id, and is refused, not
//!   replaced, if the path is taken. Notes keep their text, and take a new id.
//!
//! Exporting sends notes to GitHub. A secret gist is unlisted, not private:
//! anyone with its URL can read it, and `audience: private` in basalt.yaml is
//! enforced by a basalt server, not by GitHub. So secret is the default, public
//! has to be asked for, and `dry_run` says what would be sent before it is.

use crate::keys::{is_valid_key, key_to_path, CONTENT};
use crate::order::sort_utf8;
use crate::store::{store_object, Provenance, StoreRequest, Stored};
use crate::transport::gist::{
    decode_name, encode_name, why_not_text, Gist, GistApi, GistError, MAX_GIST_FILES,
};
use crate::transport::BatchInfo;
use crate::vault::Vault;
use std::collections::BTreeMap;
use unicode_normalization::UnicodeNormalization;

const MAX_NAME_BYTES: usize = 255;
const DEFAULT_DESCRIPTION: &str = "Exported from a Basalt vault";

/// `Notes` → `Notes/`; `/` or empty → empty (the whole vault).
pub fn folder_path(input: &str) -> String {
    let f = input.trim_start_matches('/');
    if f.is_empty() || f.ends_with('/') {
        f.to_string()
    } else {
        format!("{f}/")
    }
}

/// A file a gist cannot hold, and why: `empty`, `not_text`, `name_too_long` or
/// `invalid_key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub path: String,
    pub reason: &'static str,
}

/// One file ready to send.
#[derive(Debug, Clone)]
pub struct Picked {
    pub name: String,
    pub path: String,
    pub bytes: Vec<u8>,
}

/// What a folder would send.
#[derive(Debug, Clone, Default)]
pub struct Collected {
    /// In key order.
    pub files: Vec<Picked>,
    /// The ones a gist cannot hold.
    pub skipped: Vec<Skipped>,
    /// How many a principal may not read (not named, since naming them would tell).
    pub withheld: usize,
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

/// What a folder (or, with `whole`, every key of the vault) would send.
pub fn collect(vault: &Vault, folder: &str, whole: bool, principal: Option<&str>) -> Result<Collected, String> {
    let prefix = if whole { String::new() } else { format!("{CONTENT}{folder}") };
    let mut keys: Vec<String> = vault
        .transport
        .list_all(&prefix)
        .map_err(err)?
        .into_iter()
        .filter(|k| k.starts_with(&prefix))
        .collect();
    sort_utf8(&mut keys);
    let mut out = Collected::default();
    for key in keys {
        let path = if whole { key.clone() } else { key_to_path(&key).unwrap_or(&key).to_string() };
        // A key §1.1 forbids (a decomposed macOS file name, say) is not an
        // object of the vault: it is in no index. Say so, rather than send or
        // lose it.
        if !is_valid_key(&key) {
            out.skipped.push(Skipped { path, reason: "invalid_key" });
            continue;
        }
        if let Some(p) = principal {
            if !vault.can(p, key_to_path(&key).unwrap_or(&key), &["read"]).allowed {
                out.withheld += 1;
                continue;
            }
        }
        let Some(bytes) = vault.transport.get(&key).map_err(err)? else {
            continue; // raced with a delete
        };
        if let Some(reason) = why_not_text(&bytes) {
            out.skipped.push(Skipped { path, reason });
            continue;
        }
        let name = encode_name(if whole { &key } else { &path[folder.len()..] });
        if name.len() > MAX_NAME_BYTES {
            out.skipped.push(Skipped { path, reason: "name_too_long" });
            continue;
        }
        out.files.push(Picked { name, path, bytes });
    }
    Ok(out)
}

/// What to export, and where.
#[derive(Debug, Clone, Default)]
pub struct ExportArgs<'a> {
    /// `Projects/Basalt/`; empty is every content file.
    pub folder: &'a str,
    /// The whole vault, keys and all (operator only): a gist `--gist ID` opens.
    pub whole: bool,
    /// An existing gist (an id) to write into, not a new one.
    pub update: Option<&'a str>,
    /// With `update`, remove the gist's files the export does not have.
    pub prune: bool,
    /// A public gist. New gists only: GitHub does not let a gist change sides.
    pub public: bool,
    pub description: Option<&'a str>,
    /// Send only what this principal may read.
    pub principal: Option<&'a str>,
    /// Work out what would go and send nothing.
    pub dry_run: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ExportReport {
    pub count: usize,
    pub skipped: Vec<Skipped>,
    pub withheld: usize,
    pub names: Vec<String>,
    pub bytes: usize,
    pub dry_run: bool,
    pub public: bool,
    pub id: Option<String>,
    pub url: Option<String>,
    /// A new gist was made.
    pub created: bool,
    /// An existing gist was changed (false when it already matched).
    pub updated: bool,
    pub written: usize,
    pub removed: usize,
    pub unchanged: usize,
    /// Files in the updated gist that the folder does not have, left alone.
    pub left: Vec<String>,
}

/// Send a folder to a gist.
pub fn export_to_gist(vault: &Vault, api: &GistApi, a: &ExportArgs<'_>) -> Result<ExportReport, String> {
    if a.whole && a.principal.is_some() {
        return Err("--whole copies the vault as it is, ACLs and all; it is for the operator, \
                    so it does not take --principal"
            .into());
    }
    if a.update.is_some() && a.public {
        return Err("--public chooses the visibility of a NEW gist; a gist cannot change sides, \
                    so it does not go with --update"
            .into());
    }
    if a.prune && a.update.is_none() {
        return Err("--prune is for --update".into());
    }

    let picked = collect(vault, a.folder, a.whole, a.principal)?;
    let base = ExportReport {
        count: picked.files.len(),
        skipped: picked.skipped.clone(),
        withheld: picked.withheld,
        names: picked.files.iter().map(|f| f.name.clone()).collect(),
        bytes: picked.files.iter().map(|f| f.bytes.len()).sum(),
        ..Default::default()
    };
    if picked.files.is_empty() {
        let from = if a.whole || a.folder.is_empty() { "the vault" } else { a.folder };
        return Err(format!(
            "nothing to export from {from}{}",
            if picked.skipped.is_empty() {
                String::new()
            } else {
                format!(" ({} file(s) are not text a gist can hold)", picked.skipped.len())
            }
        ));
    }
    if picked.files.len() > MAX_GIST_FILES {
        return Err(format!(
            "{} files is more than a gist shows ({MAX_GIST_FILES}); export a smaller folder",
            picked.files.len()
        ));
    }
    if a.dry_run {
        return Ok(ExportReport { dry_run: true, public: a.public, ..base });
    }

    let mut text: BTreeMap<String, String> = BTreeMap::new();
    for f in &picked.files {
        // collect() only lets UTF-8 through.
        text.insert(f.name.clone(), String::from_utf8_lossy(&f.bytes).into_owned());
    }

    let Some(update) = a.update else {
        let g = api
            .create(&text, a.description.unwrap_or(DEFAULT_DESCRIPTION), a.public)
            .map_err(err)?;
        return Ok(ExportReport { id: Some(g.id), url: g.url, public: g.public, created: true, ..base });
    };

    let g = api.get(update).map_err(err)?;
    if g.truncated {
        return Err(err(GistError::new(
            "too_big",
            format!(
                "gist {update} has more than {MAX_GIST_FILES} files, which the API will not list, \
                 so it cannot be updated safely"
            ),
        )));
    }
    let mut changes: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut unchanged = 0;
    for (name, content) in &text {
        let same = g
            .files
            .get(name)
            .and_then(|f| f.content.as_deref())
            .is_some_and(|c| c == content.as_bytes());
        if same {
            unchanged += 1;
        } else {
            changes.insert(name.clone(), Some(content.clone()));
        }
    }
    let extra: Vec<String> = g.files.keys().filter(|n| !text.contains_key(*n)).cloned().collect();
    if a.prune {
        for n in &extra {
            changes.insert(n.clone(), None);
        }
    }
    let written = changes.values().filter(|c| c.is_some()).count();
    let removed = changes.values().filter(|c| c.is_none()).count();
    let report = ExportReport {
        id: Some(g.id.clone()),
        url: g.url.clone(),
        public: g.public,
        updated: true,
        written,
        removed,
        unchanged,
        left: if a.prune { Vec::new() } else { extra },
        ..base
    };
    if written == 0 && removed == 0 && a.description.is_none() {
        return Ok(ExportReport { updated: false, ..report });
    }
    let after = api.update(update, &changes, a.description).map_err(err)?;
    Ok(ExportReport { url: after.url.or(g.url), ..report })
}

/// What an import did.
#[derive(Debug, Clone)]
pub struct ImportReport {
    pub gist: Gist,
    pub stored: Vec<Stored>,
    /// A gist file name, and why it was not stored.
    pub refused: Vec<(String, String)>,
}

/// Store every file of a gist as a new object under `to`.
///
/// One file that cannot be stored (a taken path, a name that is not a valid
/// path, a principal without `create_child`) is reported and the rest still
/// go. On a git store the whole import is one commit, on a gist store one
/// revision. `log` is called for each object as it is stored.
pub fn import_from_gist(
    vault: &mut Vault,
    api: &GistApi,
    id: &str,
    to: &str,
    principal: Option<&str>,
    provenance: Option<&Provenance>,
    mut log: impl FnMut(&Stored),
) -> Result<ImportReport, String> {
    let g = api.get(id).map_err(err)?;
    if g.truncated {
        return Err(err(GistError::new(
            "too_big",
            format!(
                "gist {id} has more than {MAX_GIST_FILES} files, which the API will not list; \
                 clone it with git and add the files instead"
            ),
        )));
    }
    let mut stored: Vec<Stored> = Vec::new();
    let mut refused: Vec<(String, String)> = Vec::new();
    let mut names: Vec<String> = g.files.keys().cloned().collect();
    if names.is_empty() {
        return Ok(ImportReport { gist: g, stored, refused });
    }
    sort_utf8(&mut names);

    vault.transport.begin_batch().map_err(err)?;
    let mut failure: Option<String> = None;
    for name in &names {
        let rel: String = decode_name(name).nfc().collect();
        let path = format!("{to}{rel}");
        let attempt = api.content(&g.files[name]).map_err(err).and_then(|bytes| {
            store_object(
                vault,
                &StoreRequest {
                    principal,
                    path: &path,
                    bytes: &bytes,
                    title: None,
                    alt: None,
                    provenance,
                    reindex: false,
                    max_bytes: None,
                },
            )
            .map_err(err)
        });
        match attempt {
            Ok(r) => {
                log(&r);
                stored.push(r);
            }
            Err(e) => refused.push((name.clone(), e)),
        }
    }
    if !stored.is_empty() {
        if let Err(e) = vault.reindex(true) {
            failure = Some(format!(
                "stored, but refreshing the indexes failed: {e}. Run `basalt index --write`."
            ));
        }
    }
    let n = stored.len();
    let mut trailers = Vec::new();
    if let Some(p) = principal {
        trailers.push(("Basalt-Principal".to_string(), p.to_string()));
    }
    trailers.push(("Basalt-Source".to_string(), format!("gist:{}", g.id)));
    let info = BatchInfo {
        message: Some(format!("Import {n} file{} from gist {}", if n == 1 { "" } else { "s" }, g.id)),
        trailers,
    };
    if let Err(e) = vault.finish_batch(&info) {
        failure.get_or_insert(e.to_string());
    }
    match failure {
        Some(f) => Err(f),
        None => Ok(ImportReport { gist: g, stored, refused }),
    }
}
