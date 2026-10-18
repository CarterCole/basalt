//! # Basalt Protocol v1
//!
//! A portable, self-describing knowledge vault that lives in any key-value
//! object store, with real per-object access control and fully derived
//! indexes. This crate is a complete implementation of
//! `protocol/PROTOCOL.md`; the section references throughout the source point
//! at the clause each piece of behavior comes from.
//!
//! Two properties are load-bearing and shape every module here:
//!
//! 1. **Content is the only source of truth.** Every index under `index/` is
//!    derived. Delete all of them and [`vault::Vault::reindex`] rebuilds the
//!    lot from content alone, byte for byte.
//! 2. **Index generation is deterministic.** Two independent implementations,
//!    given the same content, emit byte-identical index objects (§13) — which
//!    is what makes conformance mechanically checkable rather than a matter of
//!    opinion. The conformance suite in `tests/` checks this crate's output
//!    against the committed bytes of the reference implementation.
//!
//! ## Conformance
//!
//! This implementation targets **L4**: transport, content, index, security and
//! the gatekeeper HTTP surface. L5 (history) is not implemented.
//!
//! ```no_run
//! use basalt::{transport::FsTransport, vault::Vault};
//!
//! let mut vault = Vault::open(Box::new(FsTransport::new("/path/to/vault")))?;
//! vault.reindex(true)?;
//! let decision = vault.can("u:carter", "Notes/Secrets.md", &["read"]);
//! println!("{}", decision.allowed);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod acl;
pub mod canonical;
pub mod frontmatter;
pub mod gatekeeper;
pub mod indexer;
pub mod keys;
pub mod links;
pub mod manifest;
pub mod order;
pub mod security;
pub mod transport;
pub mod vault;

pub use canonical::Json;
pub use manifest::Manifest;
pub use vault::Vault;

/// Crockford base32, lowercase, with `i`, `l`, `o` and `u` omitted (§4.1).
const B32: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Mint a ULID (§4.1): a 48-bit millisecond timestamp followed by 80 bits of
/// randomness, rendered as 26 characters of lowercase Crockford base32.
///
/// §4.1 is explicit that node ids are opaque — implementations MUST NOT parse
/// meaning out of them beyond the timestamp prefix, and MUST NOT assume they
/// sort in creation order across machines.
pub fn ulid() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    ulid_from(ms, rand::random::<u128>())
}

/// Deterministic ULID construction, so a test can pin one.
pub fn ulid_from(epoch_ms: u64, randomness: u128) -> String {
    let mut out = [0u8; 26];
    // 10 characters of timestamp: 48 bits in base32 is 9.6 characters, so the
    // top character carries only the low two bits of the 50-bit field.
    let mut t = epoch_ms & ((1 << 48) - 1);
    for i in (0..10).rev() {
        out[i] = B32[(t & 31) as usize];
        t >>= 5;
    }
    // 16 characters of randomness: 80 bits.
    let mut r = randomness & ((1u128 << 80) - 1);
    for i in (10..26).rev() {
        out[i] = B32[(r & 31) as usize];
        r >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("base32 alphabet is ASCII")
}
