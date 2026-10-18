//! Descriptor lookup and the full access check, PROTOCOL §8.5 and §8.6.
//!
//! `evaluate_chain` in `acl.rs` decides one object against one chain. This
//! module builds those chains from the vault's ACL files and composes the
//! traverse checks — which are separate evaluations, not one flattened pass.

use crate::acl::{
    evaluate_chain, ChainLink, Decision, Descriptor, EvalOpts, Outcome, Principals, RightDecision,
    RIGHTS,
};
use crate::keys::{ancestors_of, basename, is_folder, parent_folder};
use std::collections::BTreeMap;

/// A parsed `meta/acl/<folder>/acl.yaml`: the descriptor for the folder itself
/// and for its direct entries (§8.6).
///
/// The grouping is per folder rather than per object for a practical reason:
/// evaluating §8.4 for a node at depth *d* takes *d* fetches rather than *2d*,
/// and every fetch is cacheable by folder.
#[derive(Debug, Clone, Default)]
pub struct FolderAcl {
    pub folder: Option<Descriptor>,
    pub entries: BTreeMap<String, Descriptor>,
}

/// A descriptor store backed by per-folder ACL files, with inline frontmatter
/// descriptors overriding them.
#[derive(Debug, Clone, Default)]
pub struct DescriptorStore {
    pub folder_acls: BTreeMap<String, FolderAcl>,
    /// §8.6: an inline descriptor **replaces** the node's entry in the folder
    /// ACL file; the two are never merged. Merging two hand-edited sources
    /// would make the effective ACL depend on load order, so the protocol
    /// picks one winner — inline, because it travels with the content.
    pub inline_acls: BTreeMap<String, Descriptor>,
}

impl DescriptorStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_folder(&self, folder: &str) -> Option<&Descriptor> {
        self.folder_acls.get(folder)?.folder.as_ref()
    }

    pub fn for_node(&self, node_path: &str) -> Option<&Descriptor> {
        if let Some(d) = self.inline_acls.get(node_path) {
            return Some(d);
        }
        self.folder_acls
            .get(parent_folder(node_path))?
            .entries
            .get(basename(node_path))
    }

    pub fn for_path(&self, path: &str) -> Option<&Descriptor> {
        if is_folder(path) {
            self.for_folder(path)
        } else {
            self.for_node(path)
        }
    }

    /// The chain for a path (§8.4 step 2): the object's own descriptor, then
    /// each ancestor folder's, nearest first, stopping at the first
    /// `protected: true`.
    pub fn chain_for(&self, path: &str) -> Vec<ChainLink> {
        let own = self.for_path(path).cloned().unwrap_or_default();
        let own_protected = own.protected;
        let mut chain = vec![ChainLink {
            path: path.to_string(),
            descriptor: own,
            distance: 0,
        }];
        if own_protected {
            return chain;
        }

        // `ancestors_of` returns root-first; walk it backwards for
        // nearest-first, which is the order §8.4 step 4 sorts within a band.
        let ancestors = ancestors_of(path);
        let mut distance = 1;
        for folder in ancestors.iter().rev() {
            if folder == path {
                continue;
            }
            let d = self.for_folder(folder).cloned().unwrap_or_default();
            let stop = d.protected;
            chain.push(ChainLink {
                path: folder.clone(),
                descriptor: d,
                distance,
            });
            distance += 1;
            if stop {
                break; // §8.3: inheritance stops here.
            }
        }
        chain
    }
}

/// The result of a complete access check.
#[derive(Debug, Clone)]
pub struct AccessResult {
    pub allowed: bool,
    pub decisions: BTreeMap<String, RightDecision>,
    /// The ancestor folder whose traverse check failed — the single most
    /// useful thing to report when a deep vault denies something unexpectedly.
    pub failed_at: Option<String>,
    pub subjects: Vec<String>,
}

impl From<Outcome> for AccessResult {
    fn from(o: Outcome) -> Self {
        Self {
            allowed: o.allowed,
            decisions: o.decisions,
            failed_at: None,
            subjects: o.subjects,
        }
    }
}

impl AccessResult {
    /// The rights that resolved to allow, in §13.3 order.
    pub fn granted(&self) -> Vec<String> {
        self.decisions
            .iter()
            .filter(|(_, d)| d.decision == Decision::Allow)
            .map(|(r, _)| r.clone())
            .collect()
    }
}

/// The complete access check: the leaf decision plus the ancestor traverse
/// chain (§8.5).
///
/// Reading `Notes/Private/Secrets.md` requires `read` on that node **and**
/// `traverse` on `Notes/` and `Notes/Private/`. Each ancestor's traverse is
/// decided by that ancestor's own chain, including its own inheritance — the
/// checks compose, they are not one flattened pass.
pub fn check_access(
    store: &DescriptorStore,
    principals: &Principals,
    principal_id: &str,
    path: &str,
    rights: &[String],
    opts: EvalOpts,
) -> AccessResult {
    let target_is_folder = is_folder(path);
    let leaf = evaluate_chain(
        principals,
        principal_id,
        &store.chain_for(path),
        rights,
        target_is_folder,
        opts,
    );

    if !opts.bypass_traverse {
        let traverse = ["traverse".to_string()];
        for folder in ancestors_of(path) {
            if folder == path {
                continue;
            }
            let t = evaluate_chain(
                principals,
                principal_id,
                &store.chain_for(&folder),
                &traverse,
                true,
                opts,
            );
            if !t.allowed {
                let by = t.decisions["traverse"].by.clone();
                let decisions = rights
                    .iter()
                    .map(|r| {
                        (
                            r.clone(),
                            RightDecision {
                                decision: Decision::Deny,
                                by: by.clone(),
                                failed_at: Some(folder.clone()),
                            },
                        )
                    })
                    .collect();
                return AccessResult {
                    allowed: false,
                    decisions,
                    failed_at: Some(folder),
                    subjects: leaf.subjects,
                };
            }
        }
    }

    AccessResult::from(leaf)
}

/// Effective rights for a principal on a path (§8.7) — the Windows "Effective
/// Access" equivalent, with the deciding ACE for each right.
///
/// §8.7 only SHOULDs this, but without it an inherited-deny misconfiguration
/// in a deep tree is close to undiagnosable, which is why §14.3 makes the
/// self-check that surfaces it mandatory.
pub fn effective_rights(
    store: &DescriptorStore,
    principals: &Principals,
    principal_id: &str,
    path: &str,
    opts: EvalOpts,
) -> AccessResult {
    let all: Vec<String> = RIGHTS.iter().map(|s| s.to_string()).collect();
    check_access(store, principals, principal_id, path, &all, opts)
}
