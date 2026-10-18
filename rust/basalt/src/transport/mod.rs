//! The substrate, PROTOCOL §1.
//!
//! A transport is an adapter over a flat key-value blob namespace and nothing
//! more. The five operations below are the whole contract; everything above
//! them — virtual folders, stable identity, inherited permissions, the link
//! graph — is content inside the same key space.
//!
//! The trait is synchronous on purpose. §1 asks for whole-object reads and
//! writes with no transactions, no streaming and no fan-out, so async buys
//! nothing at this boundary; the S3 adapter owns a runtime internally and
//! blocks, which keeps the indexer, the ACL engine and the CLI free of a
//! runtime they have no use for.

use std::collections::BTreeSet;
use std::fmt;

pub mod fs;
pub mod memory;
#[cfg(feature = "s3")]
pub mod s3;

pub use fs::FsTransport;
pub use memory::MemoryTransport;
#[cfg(feature = "s3")]
pub use s3::{S3Flavor, S3Transport};

/// Optional capabilities, each declared in the manifest (§3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Presign,
    ConditionalPut,
    RangeGet,
    Versioning,
    BatchDelete,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Presign => "presign",
            Self::ConditionalPut => "conditional_put",
            Self::RangeGet => "range_get",
            Self::Versioning => "versioning",
            Self::BatchDelete => "batch_delete",
        }
    }
}

/// The three fields §1 permits `stat` to report, and no more. A transport is
/// explicitly not allowed to be asked for per-object metadata beyond these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub size: u64,
    pub etag: Option<String>,
    pub mtime: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PutMeta {
    pub content_type: Option<String>,
    /// Optimistic concurrency (§11.3), honored only with `conditional_put`.
    /// `Some(None)` means if-none-match: create only.
    pub if_match: Option<Option<String>>,
}

impl PutMeta {
    pub fn content_type(ct: &str) -> Self {
        Self {
            content_type: Some(ct.to_string()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ListOpts {
    pub delimiter: Option<char>,
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Listing {
    pub keys: Vec<String>,
    pub prefixes: Vec<String>,
    pub cursor: Option<String>,
}

#[derive(Debug)]
pub enum TransportError {
    Io(std::io::Error),
    /// A write was rejected by §1.1 before it reached the store.
    Key(crate::keys::KeyError),
    /// A conditional write lost the race (§11.3). A conflict is surfaced
    /// rather than retried: last-write-wins on a knowledge vault silently
    /// destroys work.
    PreconditionFailed(String),
    Unsupported(&'static str),
    Backend(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Key(e) => write!(f, "{e}"),
            Self::PreconditionFailed(k) => write!(f, "precondition failed for {k}"),
            Self::Unsupported(c) => write!(f, "transport does not provide {c}"),
            Self::Backend(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<std::io::Error> for TransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<crate::keys::KeyError> for TransportError {
    fn from(e: crate::keys::KeyError) -> Self {
        Self::Key(e)
    }
}

pub type Result<T> = std::result::Result<T, TransportError>;

/// The five operations of §1, plus the optional `presign` of §12.4.
pub trait Transport: Send + Sync {
    /// Whole-object read. `None` is NOT_FOUND.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;

    /// Create or replace, atomic per key.
    fn put(&self, key: &str, bytes: &[u8], meta: &PutMeta) -> Result<Stat>;

    /// Remove one key. Idempotent, and §1.2 forbids reporting whether the key
    /// existed — hence the unit return. A filesystem *can* answer cheaply,
    /// which is exactly the trap: the boolean silently becomes wrong the day
    /// the vault moves to a bucket.
    fn delete(&self, key: &str) -> Result<()>;

    /// Enumerate. Paginated, and §1 promises no ordering: the caller sorts.
    fn list(&self, prefix: &str, opts: &ListOpts) -> Result<Listing>;

    /// Metadata without the body. `None` is NOT_FOUND.
    fn stat(&self, key: &str) -> Result<Option<Stat>>;

    fn capabilities(&self) -> &BTreeSet<Capability>;

    fn has(&self, cap: Capability) -> bool {
        self.capabilities().contains(&cap)
    }

    /// Mint a time-limited direct read URL (§12.4).
    fn presign(&self, _key: &str, _ttl_seconds: u64) -> Result<String> {
        Err(TransportError::Unsupported("presign"))
    }

    /// Enumerate every key under a prefix, following pagination to the end.
    fn list_all(&self, prefix: &str) -> Result<Vec<String>> {
        let mut keys = Vec::new();
        let mut cursor = None;
        loop {
            let page = self.list(
                prefix,
                &ListOpts {
                    delimiter: None,
                    cursor: cursor.clone(),
                },
            )?;
            keys.extend(page.keys);
            match page.cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(keys)
    }
}
