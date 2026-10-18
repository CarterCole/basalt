//! An in-memory transport. Not a conformance target in itself — it exists so
//! the indexer and the ACL engine can be exercised without touching a disk,
//! and so a test can build a vault key by key.

use super::{Capability, ListOpts, Listing, PutMeta, Result, Stat, Transport, TransportError};
use crate::keys::validate_key;
use md5::{Digest as _, Md5};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

pub struct MemoryTransport {
    objects: RwLock<BTreeMap<String, Vec<u8>>>,
    caps: BTreeSet<Capability>,
}

impl Default for MemoryTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTransport {
    pub fn new() -> Self {
        Self {
            objects: RwLock::new(BTreeMap::new()),
            caps: [Capability::ConditionalPut, Capability::BatchDelete]
                .into_iter()
                .collect(),
        }
    }

    /// Seed an object, bypassing validation — for building a fixture vault
    /// that deliberately contains an illegal key.
    pub fn seed(&self, key: &str, bytes: impl Into<Vec<u8>>) {
        self.objects
            .write()
            .unwrap()
            .insert(key.to_string(), bytes.into());
    }
}

fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", crate::order::hex(&Md5::digest(bytes)))
}

impl Transport for MemoryTransport {
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.read().unwrap().get(key).cloned())
    }

    fn put(&self, key: &str, bytes: &[u8], meta: &PutMeta) -> Result<Stat> {
        validate_key(key)?;
        let mut objects = self.objects.write().unwrap();
        if let Some(want) = &meta.if_match {
            let have = objects.get(key).map(|b| etag(b));
            if &have != want {
                return Err(TransportError::PreconditionFailed(key.to_string()));
            }
        }
        objects.insert(key.to_string(), bytes.to_vec());
        Ok(Stat {
            size: bytes.len() as u64,
            etag: Some(etag(bytes)),
            mtime: None,
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        self.objects.write().unwrap().remove(key);
        Ok(())
    }

    fn list(&self, prefix: &str, opts: &ListOpts) -> Result<Listing> {
        let objects = self.objects.read().unwrap();
        let mut keys = Vec::new();
        let mut prefixes = BTreeSet::new();
        for k in objects.keys() {
            if !k.starts_with(prefix) {
                continue;
            }
            if let Some(d) = opts.delimiter {
                if let Some(i) = k[prefix.len()..].find(d) {
                    prefixes.insert(format!(
                        "{prefix}{}",
                        &k[prefix.len()..prefix.len() + i + 1]
                    ));
                    continue;
                }
            }
            keys.push(k.clone());
        }
        Ok(Listing {
            keys,
            prefixes: prefixes.into_iter().collect(),
            cursor: None,
        })
    }

    fn stat(&self, key: &str) -> Result<Option<Stat>> {
        Ok(self.objects.read().unwrap().get(key).map(|b| Stat {
            size: b.len() as u64,
            etag: Some(etag(b)),
            mtime: None,
        }))
    }

    fn capabilities(&self) -> &BTreeSet<Capability> {
        &self.caps
    }
}
