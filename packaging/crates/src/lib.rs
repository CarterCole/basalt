//! The Basalt conformance corpus, as a crate.
//!
//! The corpus is language-neutral YAML plus whole vaults with expected index
//! output (PROTOCOL §14.2). This crate exists so a *published* implementation
//! can reach it: the corpus lives at the repository root, outside every
//! package directory, and `cargo package` would otherwise ship zero fixture
//! files.

use std::path::{Path, PathBuf};

/// The corpus root.
///
/// Resolves two ways on purpose. In a published crate the fixtures sit in
/// `assets/` inside the package. In the workspace they do not — the corpus is
/// the repository's own `conformance/` directory, and reading it directly is
/// what makes a fixture fix break every implementation's tests the same
/// minute, rather than when someone remembers to re-sync.
pub fn corpus_dir() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let embedded = manifest.join("assets");
    if embedded.is_dir() {
        return embedded;
    }
    manifest.join("../../conformance")
}

/// A path within the corpus, e.g. `cases/acl/evaluation.yaml`.
pub fn case(relative: &str) -> PathBuf {
    corpus_dir().join(relative)
}

/// A conformance vault, e.g. `minimal` → `<corpus>/vaults/minimal/vault`.
pub fn vault(name: &str) -> PathBuf {
    corpus_dir().join("vaults").join(name).join("vault")
}

/// A vault's committed expected index output.
pub fn expected(name: &str) -> PathBuf {
    corpus_dir().join("vaults").join(name).join("expected")
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_corpus_is_reachable() {
        assert!(super::case("manifest.yaml").is_file(), "corpus manifest missing");
        assert!(super::vault("minimal").is_dir(), "minimal vault missing");
        assert!(super::expected("minimal").is_dir(), "expected output missing");
    }
}
