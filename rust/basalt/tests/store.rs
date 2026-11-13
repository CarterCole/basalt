//! Runs `conformance/cases/store/creation.yaml`, PROTOCOL §12.7.
//!
//! The TypeScript and Python runners execute the same file, so the three
//! write paths agree on every case it holds. Expectations live in the corpus;
//! this file only knows how to ask.

mod support;

use basalt::serve::surface::base64_decode;
use basalt::store::{check_provenance_label, normalize_caller, store_object, Client, Provenance, StoreRequest};
use basalt::transport::FsTransport;
use basalt::vault::Vault;
use serde_yaml_ng::Value as Yaml;
use std::path::{Path, PathBuf};
use support::{cases, conformance_dir, load};

/// A scratch copy of a directory, removed on drop.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

fn scratch(tag: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!(
        "basalt-store-{tag}-{}-{}",
        std::process::id(),
        basalt::ulid()
    ));
    copy_dir(&conformance_dir().join("vaults/minimal/vault"), &dir);
    Scratch(dir)
}

fn text(v: &Yaml, k: &str) -> Option<String> {
    v.get(k).and_then(|x| x.as_str()).map(str::to_string)
}

fn bytes_of(req: &Yaml) -> Vec<u8> {
    match text(req, "base64") {
        Some(b) => base64_decode(&b).expect("valid base64 in the corpus"),
        None => text(req, "text").unwrap_or_default().into_bytes(),
    }
}

fn provenance_of(req: &Yaml) -> Option<Provenance> {
    let p = req.get("provenance")?;
    if p.is_null() {
        return Some(Provenance::default());
    }
    Some(Provenance {
        agent: text(p, "agent"),
        account: text(p, "account"),
        caller: text(p, "caller"),
        client: p.get("client").map(|c| Client {
            name: text(c, "name"),
            version: text(c, "version"),
        }),
    })
}

fn store(v: &mut Vault, req: &Yaml) -> Result<basalt::store::Stored, basalt::store::StoreError> {
    let bytes = bytes_of(req);
    let principal = text(req, "principal");
    let path = text(req, "path").unwrap_or_default();
    let title = text(req, "title");
    let alt = text(req, "alt");
    let prov = provenance_of(req);
    store_object(
        v,
        &StoreRequest {
            principal: principal.as_deref(),
            path: &path,
            bytes: &bytes,
            title: title.as_deref(),
            alt: alt.as_deref(),
            provenance: prov.as_ref(),
            reindex: true,
            max_bytes: None,
        },
    )
}

fn file_at(dir: &Path, key: &str) -> Option<Vec<u8>> {
    let p = dir.join(key);
    p.is_file().then(|| std::fs::read(p).unwrap())
}

fn yaml(text: &str) -> Yaml {
    serde_yaml_ng::from_str(text).unwrap()
}

/// The stamp without `at`, after checking `at` is RFC 3339 UTC to the second.
fn stamp_without_at(stamp: Option<&Yaml>) -> Option<Yaml> {
    let mut m = stamp?.as_mapping()?.clone();
    let at = m.remove("at").and_then(|a| a.as_str().map(str::to_string));
    let at = at.expect("created_by.at is present");
    let re = regex::Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$").unwrap();
    assert!(re.is_match(&at), "created_by.at is {at}");
    Some(Yaml::Mapping(m))
}

fn run_store_case(c: &Yaml) -> Result<(), String> {
    let name = text(c, "name").unwrap();
    let dir = scratch("corpus");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir.0))).map_err(|e| e.to_string())?;
    v.reindex(true).map_err(|e| e.to_string())?;
    for g in c.get("given").and_then(|g| g.as_sequence()).cloned().unwrap_or_default() {
        store(&mut v, &g).map_err(|e| format!("given {:?}: {e}", text(&g, "path")))?;
    }

    let req = c.get("request").unwrap();
    let path = text(req, "path").unwrap_or_default();
    let key = format!("content/{path}");
    let index_before = std::fs::read_to_string(dir.0.join("index/nodes.json")).unwrap();
    let folder = path.rsplit_once('/').map(|(f, _)| f.to_string());
    let sidecar_file = |f: &str| dir.0.join("meta/folders").join(f).join("entries.yaml");
    let sidecar_before = folder
        .as_deref()
        .and_then(|f| std::fs::read_to_string(sidecar_file(f)).ok())
        .map(|t| yaml(&t));

    if let Some(code) = text(c, "refused") {
        let before = file_at(&dir.0, &key);
        match store(&mut v, req) {
            Ok(r) => return Err(format!("{name}: stored {} instead of refusing", r.path)),
            Err(e) if e.code != code => return Err(format!("{name}: refused {e}, expected {code}")),
            Err(_) => {}
        }
        if file_at(&dir.0, &key) != before {
            return Err(format!("{name}: the refusal changed {key}"));
        }
        if std::fs::read_to_string(dir.0.join("index/nodes.json")).unwrap() != index_before {
            return Err(format!("{name}: the refusal changed the stored indexes"));
        }
        return Ok(());
    }

    let r = store(&mut v, req).map_err(|e| format!("{name}: {e}"))?;
    let want = text(c, "stored").unwrap();
    if r.kind.as_str() != want {
        return Err(format!("{name}: stored as {}, expected {want}", r.kind.as_str()));
    }
    if !basalt::frontmatter::is_ulid(&r.id) {
        return Err(format!("{name}: {} is not a ULID", r.id));
    }

    let mut fresh = Vault::open(Box::new(FsTransport::new(&dir.0))).unwrap();
    fresh.reindex(false).unwrap();
    let idx = fresh.indexes.as_ref().unwrap();
    let node = idx
        .node(&path)
        .ok_or_else(|| format!("{name}: {path} is not indexed"))?;
    if node.id.as_deref() != Some(r.id.as_str()) {
        return Err(format!("{name}: indexed with id {:?}, store said {}", node.id, r.id));
    }
    if idx.node_data.iter().any(|n| n.path != path && n.id.as_deref() == Some(r.id.as_str())) {
        return Err(format!("{name}: the id is not fresh"));
    }
    let stored_index = std::fs::read_to_string(dir.0.join("index/nodes.json")).unwrap();
    if !stored_index.contains(&r.id) {
        return Err(format!("{name}: the stored indexes were not refreshed"));
    }
    if let Some(t) = text(c, "title") {
        if node.title.as_deref() != Some(t.as_str()) {
            return Err(format!("{name}: title {:?}, expected {t:?}", node.title));
        }
    }

    let on_disk = std::fs::read(dir.0.join(&key)).unwrap();
    let stamp = if want == "note" {
        let split = basalt::frontmatter::split_frontmatter(std::str::from_utf8(&on_disk).unwrap());
        let fm = yaml(split.raw.as_deref().unwrap_or(""));
        let b = fm.get("basalt").cloned().unwrap_or(Yaml::Null);
        if b.get("id").and_then(|i| i.as_str()) != Some(r.id.as_str()) {
            return Err(format!("{name}: frontmatter id is not {}", r.id));
        }
        b.get("created_by").cloned()
    } else {
        if on_disk != bytes_of(req) {
            return Err(format!("{name}: not stored byte for byte"));
        }
        let f = folder.as_deref().unwrap();
        let sc = yaml(&std::fs::read_to_string(sidecar_file(f)).unwrap());
        let base = path.rsplit('/').next().unwrap();
        let own = sc.get("entries").and_then(|e| e.get(base)).cloned().unwrap_or(Yaml::Null);
        if own.get("id").and_then(|i| i.as_str()) != Some(r.id.as_str()) {
            return Err(format!("{name}: sidecar id is not {}", r.id));
        }
        if let Some(alt) = text(c, "alt") {
            if text(&own, "alt").as_deref() != Some(alt.as_str()) {
                return Err(format!("{name}: alt is {:?}", text(&own, "alt")));
            }
        }
        for keep in support::list(c, "sidecar_keeps") {
            let was = sidecar_before.as_ref().and_then(|s| s.get("entries")).and_then(|e| e.get(keep.as_str()));
            let now = sc.get("entries").and_then(|e| e.get(keep.as_str()));
            if was != now {
                return Err(format!("{name}: sidecar entry {keep} changed"));
            }
        }
        own.get("created_by").cloned()
    };

    match c.get("created_by") {
        None => {}
        Some(Yaml::Null) => {
            if stamp.is_some() {
                return Err(format!("{name}: stamped, expected no stamp"));
            }
        }
        Some(want) => {
            let got = stamp_without_at(stamp.as_ref());
            if got.as_ref() != Some(want) {
                return Err(format!("{name}: created_by {got:?}, expected {want:?}"));
            }
        }
    }
    Ok(())
}

/// §2.2 folds names with NFC and lowercase, and the collision check is built
/// on that fold. A case-insensitive filesystem folds further — APFS and NTFS
/// take `ſite` (U+017F, long s) for `Site` — so a path spelled that way passed
/// as a folder nobody had made yet, was authorized as one, and was then
/// written into the existing folder the writer has no right on. The
/// filesystem transport now refuses the write, and the refusal is the
/// conflict any other §2.2 collision gets.
///
/// Not a corpus case: an object store does not alias names, so what this
/// asserts is true only of a filesystem that does.
#[test]
fn a_store_cannot_reach_a_protected_folder_through_filesystem_case_folding() {
    let dir = Scratch(std::env::temp_dir().join(format!(
        "basalt-store-alias-{}-{}",
        std::process::id(),
        basalt::ulid()
    )));
    let root = &dir.0;
    let write = |key: &str, body: &str| {
        let p = root.join(key);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    };
    write(
        "content/Site/Home.md",
        "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# Home\n",
    );
    if !root.join("content/ſite").exists() {
        eprintln!("skipped: {} does not fold ſite onto Site", root.display());
        return;
    }
    write(
        "basalt.yaml",
        "basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n  title: Aliases\npublish:\n  audience: gated\n",
    );
    write(
        "principals/users.yaml",
        "users:\n  - {id: u:carter, status: active}\n  - {id: u:editor, status: active}\n",
    );
    // The editor may add anywhere the root's grant reaches ...
    write(
        "meta/acl/acl.yaml",
        "folder:\n  owner: u:carter\n  dacl:\n    \
         - {type: allow, subject: everyone, rights: [traverse, list], flags: [ci]}\n    \
         - {type: allow, subject: u:editor, rights: [read, create_child], flags: [ci, oi]}\n",
    );
    // ... which is not into Site/: it is protected, so nothing is inherited.
    write(
        "meta/acl/Site/acl.yaml",
        "folder:\n  owner: u:carter\n  protected: true\n  dacl:\n    \
         - {type: allow, subject: everyone, rights: [read, list, traverse], flags: [oi]}\n",
    );

    let mut v = Vault::open(Box::new(FsTransport::new(root))).expect("vault opens");
    v.reindex(true).expect("reindex");
    let mut attempt = |path: &str| {
        store_object(
            &mut v,
            &StoreRequest {
                principal: Some("u:editor"),
                path,
                bytes: b"# Planted\n",
                title: None,
                alt: None,
                provenance: None,
                reindex: true,
                max_bytes: None,
            },
        )
    };

    let direct = attempt("Site/Planted.md").expect_err("Site/ is closed to the editor");
    assert_eq!((direct.code, direct.status), ("forbidden", 403));
    attempt("Drafts/Mine.md").expect("a folder of the editor's own is open to them");

    let aliased = attempt("ſite/Planted.md").expect_err("ſite/ is Site/ on this filesystem");
    assert_eq!(
        (aliased.code, aliased.status),
        ("conflict", 409),
        "{aliased}"
    );
    assert_eq!(
        aliased.detail,
        "ſite/ is the same folder as Site/ on this filesystem"
    );
    // Deeper, and for a file that is not a note (so a sidecar would follow).
    let deeper = attempt("ſite/Sub/planted.png").expect_err("still Site/");
    assert_eq!((deeper.code, deeper.status), ("conflict", 409), "{deeper}");

    let mut site: Vec<String> = std::fs::read_dir(root.join("content/Site"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    site.sort();
    assert_eq!(
        site,
        ["Home.md"],
        "nothing was planted in the protected folder"
    );
    assert!(
        !root.join("meta/folders/Site").exists(),
        "and no sidecar was written for it"
    );
}

#[test]
fn store_corpus() {
    let doc = load("cases/store/creation.yaml");
    let mut failures = Vec::new();
    let mut ran = 0;
    for c in cases(&doc) {
        ran += 1;
        let name = text(&c, "name").unwrap();
        match text(&c, "kind").as_deref() {
            Some("label") => {
                let ok = check_provenance_label("agent", text(&c, "value").as_deref()).is_ok();
                if Some(ok) != c.get("ok").and_then(|o| o.as_bool()) {
                    failures.push(format!("{name}: accepted = {ok}"));
                }
            }
            Some("caller") => {
                let got = normalize_caller(text(&c, "value").as_deref()).ok().flatten();
                if got != text(&c, "out") {
                    failures.push(format!("{name}: {got:?}"));
                }
            }
            Some("store") => {
                if let Err(e) = run_store_case(&c) {
                    failures.push(e);
                }
            }
            other => failures.push(format!("{name}: unknown kind {other:?}")),
        }
    }
    assert!(ran > 0);
    assert!(failures.is_empty(), "{} of {ran} store cases failed:\n  {}", failures.len(), failures.join("\n  "));
}
