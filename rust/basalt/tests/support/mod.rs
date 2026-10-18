#![allow(dead_code)]
//! Shared plumbing for the conformance runners.
//!
//! Expectations live in `conformance/`, never here: PROTOCOL §14.2 is explicit
//! that no implementation defines its own answers for behavior the spec
//! covers, so every assertion in these tests reads its expected value out of
//! the committed corpus.

use serde_yaml_ng::Value as Yaml;
use std::path::{Path, PathBuf};

/// The corpus root, found relative to this crate rather than to the cwd.
pub fn conformance_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .canonicalize()
        .expect("conformance/ is a sibling of rust/")
}

pub fn load(rel: &str) -> Yaml {
    let path = conformance_dir().join(rel);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_yaml_ng::from_str(&text)
        .unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

pub fn cases(doc: &Yaml) -> Vec<Yaml> {
    doc.get("cases")
        .and_then(|c| c.as_sequence())
        .cloned()
        .unwrap_or_default()
}

pub fn s(v: &Yaml, key: &str) -> Option<String> {
    match v.get(key) {
        Some(Yaml::String(x)) => Some(x.clone()),
        Some(Yaml::Number(n)) => Some(n.to_string()),
        Some(Yaml::Bool(b)) => Some(b.to_string()),
        _ => None,
    }
}

/// A key that is present and explicitly null, as distinct from absent — the
/// corpus uses `resolves_to: null` and `id: null` to mean "and that is the
/// expected answer".
pub fn present(v: &Yaml, key: &str) -> bool {
    v.get(key).is_some()
}

pub fn opt_s(v: &Yaml, key: &str) -> Option<String> {
    s(v, key)
}

pub fn b(v: &Yaml, key: &str) -> Option<bool> {
    v.get(key).and_then(|x| x.as_bool())
}

pub fn n(v: &Yaml, key: &str) -> Option<i64> {
    v.get(key).and_then(|x| x.as_i64())
}

pub fn list(v: &Yaml, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(|x| x.as_sequence())
        .map(|seq| {
            seq.iter()
                .filter_map(|i| match i {
                    Yaml::String(x) => Some(x.clone()),
                    Yaml::Number(x) => Some(x.to_string()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A tiny pass/fail collector, so one failing case names itself and the rest
/// still run — the same reason §10.8 collects integrity findings rather than
/// throwing on the first one.
#[derive(Default)]
pub struct Report {
    pub failures: Vec<String>,
    pub passed: usize,
}

impl Report {
    pub fn check(
        &mut self,
        case: &str,
        what: &str,
        got: impl std::fmt::Debug,
        want: impl std::fmt::Debug,
    ) {
        let g = format!("{got:?}");
        let w = format!("{want:?}");
        if g == w {
            self.passed += 1;
        } else {
            self.failures
                .push(format!("{case}: {what}\n     got  {g}\n     want {w}"));
        }
    }

    pub fn finish(self, suite: &str) {
        if !self.failures.is_empty() {
            panic!(
                "\n{} conformance failures in {suite} ({} assertions passed):\n\n  {}\n",
                self.failures.len(),
                self.passed,
                self.failures.join("\n  ")
            );
        }
        eprintln!("{suite}: {} assertions passed", self.passed);
    }
}
