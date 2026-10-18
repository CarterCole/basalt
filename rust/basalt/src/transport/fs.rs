//! Local filesystem transport, PROTOCOL §1.
//!
//! A vault on disk is a plain folder: `content/` opens in Obsidian, a text
//! editor, `rg` or `git` with no knowledge of this protocol (§3). That is the
//! whole point of keeping identity in the content rather than in an index.

use super::{Capability, ListOpts, Listing, PutMeta, Result, Stat, Transport, TransportError};
use crate::keys::validate_key;
use md5::{Digest as _, Md5};
use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct FsTransport {
    root: PathBuf,
    caps: BTreeSet<Capability>,
}

impl FsTransport {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
            caps: [
                Capability::ConditionalPut,
                Capability::RangeGet,
                Capability::BatchDelete,
            ]
            .into_iter()
            .collect(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Map a key to an absolute path, refusing anything that escapes the root.
    ///
    /// `validate_key` already rejects `..` segments, but a transport is the
    /// last line of defense and a path-traversal bug here reads the whole
    /// disk, so the check is repeated structurally rather than trusted.
    fn resolve(&self, key: &str) -> Result<PathBuf> {
        let candidate = Path::new(key);
        for c in candidate.components() {
            match c {
                Component::Normal(_) => {}
                _ => {
                    return Err(TransportError::Backend(format!(
                        "key escapes vault root: {key}"
                    )))
                }
            }
        }
        Ok(self.root.join(candidate))
    }
}

fn mtime_of(meta: &fs::Metadata) -> Option<String> {
    let d = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?;
    Some(rfc3339(d.as_secs()))
}

/// RFC 3339 in UTC to whole seconds. Hand-rolled because a date crate is a
/// large dependency to carry for one timestamp format, and `generated` is
/// excluded from comparison anyway (§13.2).
pub fn rfc3339(epoch_secs: u64) -> String {
    let days = (epoch_secs / 86_400) as i64;
    let secs_of_day = epoch_secs % 86_400;
    // Civil-from-days, Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// The current instant as an RFC 3339 UTC string.
pub fn now_rfc3339() -> String {
    rfc3339(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// The errors a filesystem raises for a key that an object store would simply
/// not have, PROTOCOL §1.
///
/// `get` and `stat` answer NOT_FOUND for these, and `delete` answers success
/// (§1.2). Three cases, all of which are "this key does not exist" on a bucket:
///
/// - **NotFound**, the obvious one.
/// - **IsADirectory**: `content/Notes` is a folder on disk and not an object,
///   and §2.1 says folders are virtual and never stored — so no key names it.
/// - **NotADirectory**: `content/Notes/x.md` where `content/Notes` is a *file*.
///   A bucket has no opinion about the shape of a key's prefix.
///
/// Surfacing any of them as an error would make this transport disagree with
/// every store the protocol targets, which is the hazard §1.2 names.
fn is_absent(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::NotFound | ErrorKind::IsADirectory | ErrorKind::NotADirectory
    )
}

impl Transport for FsTransport {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match fs::read(self.resolve(key)?) {
            Ok(b) => Ok(Some(b)),
            Err(e) if is_absent(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn put(&self, key: &str, bytes: &[u8], meta: &PutMeta) -> Result<Stat> {
        validate_key(key)?;
        let path = self.resolve(key)?;
        if let Some(want) = &meta.if_match {
            let have = self.stat(key)?.and_then(|s| s.etag);
            if &have != want {
                return Err(TransportError::PreconditionFailed(key.to_string()));
            }
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        // Write to a temp file and rename, so a reader never sees a
        // half-written object — §1 promises read-after-write for a single key.
        let tmp = path.with_extension(format!(
            "{}.{}.tmp",
            path.extension().and_then(|e| e.to_str()).unwrap_or(""),
            std::process::id()
        ));
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, &path)?;
        Ok(Stat {
            size: bytes.len() as u64,
            etag: Some(format!("\"{}\"", crate::order::hex(&Md5::digest(bytes)))),
            mtime: fs::metadata(&path).ok().and_then(|m| mtime_of(&m)),
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        // §1.2: idempotent, and it reports nothing.
        //
        // The invariant worth holding is that `delete` removes exactly what
        // `get` would have returned, so the two cannot disagree about what an
        // object is. Anything `get` reads as NOT_FOUND is therefore a no-op
        // here: a missing path, a directory (§2.1 — folders are virtual and
        // never stored, so no key names one), and a path whose own prefix is a
        // file. On a bucket all three are simply absent keys, and a delete of
        // an absent key succeeds.
        //
        // Deciding this from `metadata` rather than from `remove_file`'s error
        // is not fussiness: `unlink` on a directory is EPERM on macOS and
        // EISDIR on Linux, so matching error kinds would be a per-platform
        // list that silently grows a hole on the next platform.
        let path = self.resolve(key)?;
        match fs::metadata(&path) {
            Ok(m) if !m.is_file() => return Ok(()),
            Err(e) if is_absent(&e) => return Ok(()),
            Err(e) => return Err(e.into()),
            Ok(_) => {}
        }
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            // Lost a race with another writer; §1.2 says the caller learns
            // nothing from a delete either way.
            Err(e) if is_absent(&e) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn list(&self, prefix: &str, opts: &ListOpts) -> Result<Listing> {
        let mut keys = Vec::new();
        let mut prefixes = BTreeSet::new();
        let mut stack = vec![(self.root.clone(), String::new())];

        while let Some((dir, rel)) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
                    continue
                }
                Err(e) => return Err(e.into()),
            };
            for entry in entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                // In-flight writes and tool droppings are not vault objects.
                if name.ends_with(".tmp") || name == ".DS_Store" || name == ".git" {
                    continue;
                }
                let key = if rel.is_empty() {
                    name.clone()
                } else {
                    format!("{rel}/{name}")
                };
                let ft = entry.file_type()?;
                if ft.is_dir() {
                    // Prune subtrees that cannot contain the prefix.
                    let as_folder = format!("{key}/");
                    if !as_folder.starts_with(prefix) && !prefix.starts_with(&as_folder) {
                        continue;
                    }
                    stack.push((entry.path(), key));
                } else if ft.is_file() && key.starts_with(prefix) {
                    if let Some(d) = opts.delimiter {
                        if let Some(i) = key[prefix.len()..].find(d) {
                            prefixes.insert(format!(
                                "{prefix}{}",
                                &key[prefix.len()..prefix.len() + i + d.len_utf8()]
                            ));
                            continue;
                        }
                    }
                    keys.push(key);
                }
            }
        }
        Ok(Listing {
            keys,
            prefixes: prefixes.into_iter().collect(),
            cursor: None,
        })
    }

    fn stat(&self, key: &str) -> Result<Option<Stat>> {
        let path = self.resolve(key)?;
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(e) if is_absent(&e) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !meta.is_file() {
            return Ok(None);
        }
        // No cheap server-side etag on a filesystem, so hash the bytes. §10.1
        // treats `content_hash` as authoritative precisely because etags are
        // not comparable across stores.
        let bytes = fs::read(&path)?;
        Ok(Some(Stat {
            size: meta.len(),
            etag: Some(format!("\"{}\"", crate::order::hex(&Md5::digest(&bytes)))),
            mtime: mtime_of(&meta),
        }))
    }

    fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.caps
    }
}
