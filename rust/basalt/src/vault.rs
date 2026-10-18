//! The Vault facade, PROTOCOL §3 — loading, scanning, indexing, reading.

use crate::acl::{Descriptor, Group, Principals, User};
use crate::canonical::{parse_json, Json};
use crate::frontmatter::{kind_for, parse_note, with_id, yaml_text, Kind, Severity};
use crate::indexer::{
    build_indexes, build_search_index, compute_digest, BuildInput, BuiltIndexes, FolderRecord,
    IndexedNode, Issue, Scanned, Sidecar, SidecarEntry,
};
use crate::keys::{
    basename, implied_folders, is_valid_key, key_to_path, parent_folder, path_to_key, CONTENT,
    MANIFEST, META, PRINCIPALS,
};
use crate::manifest::{Manifest, StalePolicy};
use crate::order::{compare_utf8, sort_utf8};
use crate::security::{check_access, effective_rights, AccessResult, DescriptorStore, FolderAcl};
use crate::transport::{fs::now_rfc3339, PutMeta, Transport};
use serde_yaml_ng::Value as Yaml;
use std::collections::BTreeMap;

/// The seven index objects of §10, by name and key.
pub const INDEX_KEYS: [(&str, &str); 7] = [
    ("nodes", "index/nodes.json"),
    ("links", "index/links.json"),
    ("backlinks", "index/backlinks.json"),
    ("tags", "index/tags.json"),
    ("search", "index/search.json"),
    ("digest", "index/digest.json"),
    ("integrity", "index/integrity.json"),
];

/// How an index pass persists what it built.
#[derive(Debug, Clone, Copy, Default)]
pub struct IndexWrite {
    /// Persist the rebuilt indexes to `index/`.
    pub persist: bool,
    /// §10.7: permit replacing a non-empty stored index with an empty one.
    /// Only ever set from an explicit human instruction.
    pub force: bool,
}

impl IndexWrite {
    /// Build in memory and write nothing.
    pub fn dry() -> Self {
        Self::default()
    }
    /// Build and persist, with the §10.7 guard in force.
    pub fn persist() -> Self {
        Self {
            persist: true,
            force: false,
        }
    }
    /// Build and persist, overriding the §10.7 guard.
    pub fn forced() -> Self {
        Self {
            persist: true,
            force: true,
        }
    }
}

/// Freshness, as §12.3 asks every response to report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexState {
    Fresh,
    Stale,
    Rebuilt,
}

impl IndexState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Rebuilt => "rebuilt",
        }
    }
}

#[derive(Debug)]
pub enum VaultError {
    Transport(crate::transport::TransportError),
    Manifest(String),
    NotAVault(String),
    /// §10.7: a write pass refused to replace a non-empty stored index with an
    /// empty one. Indexes are derived, so this cannot lose content — but a
    /// vault whose indexes have gone empty looks empty to every reader until
    /// someone notices, and the usual cause is a transport pointed at the
    /// wrong place rather than an emptied vault.
    EmptyIndexRefused {
        found: usize,
        previously: usize,
    },
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "{e}"),
            Self::Manifest(m) => write!(f, "{m}"),
            Self::NotAVault(m) => write!(f, "{m}"),
            // §10.7 SHOULDs both counts, since "0 nodes found, 1284
            // previously indexed" names the problem precisely.
            Self::EmptyIndexRefused { found, previously } => write!(
                f,
                "refusing to overwrite the stored index: {found} nodes found, \
                 {previously} previously indexed — check the transport is pointed \
                 at the right vault (§10.7), or pass force to write anyway"
            ),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<crate::transport::TransportError> for VaultError {
    fn from(e: crate::transport::TransportError) -> Self {
        Self::Transport(e)
    }
}

pub type Result<T> = std::result::Result<T, VaultError>;

/// A built index set plus the parsed node and edge data behind it.
pub struct Indexes {
    pub nodes: Json,
    pub links: Json,
    pub backlinks: Json,
    pub tags: Json,
    pub search: Json,
    pub digest: Json,
    pub integrity: Json,
    pub node_data: Vec<IndexedNode>,
    pub edges: Vec<crate::indexer::Edge>,
    pub issues: Vec<Issue>,
    pub source_digest: String,
}

impl Indexes {
    pub fn by_name(&self, name: &str) -> Option<&Json> {
        match name {
            "nodes" => Some(&self.nodes),
            "links" => Some(&self.links),
            "backlinks" => Some(&self.backlinks),
            "tags" => Some(&self.tags),
            "search" => Some(&self.search),
            "digest" => Some(&self.digest),
            "integrity" => Some(&self.integrity),
            _ => None,
        }
    }

    pub fn node(&self, path: &str) -> Option<&IndexedNode> {
        self.node_data.iter().find(|n| n.path == path)
    }

    pub fn node_by_id(&self, id: &str) -> Option<&IndexedNode> {
        self.node_data.iter().find(|n| n.id.as_deref() == Some(id))
    }
}

pub struct Vault {
    pub transport: Box<dyn Transport>,
    pub manifest: Manifest,
    pub principals: Principals,
    pub descriptors: DescriptorStore,
    pub folder_records: BTreeMap<String, FolderRecord>,
    pub sidecars: BTreeMap<String, Sidecar>,
    pub indexes: Option<Indexes>,
}

impl Vault {
    /// Open a vault: read the manifest, the principals, the folder records and
    /// the ACL files. Content is not read until [`Vault::reindex`].
    pub fn open(transport: Box<dyn Transport>) -> Result<Self> {
        let raw = Self::read_text(&*transport, MANIFEST)?.ok_or_else(|| {
            VaultError::NotAVault(format!("not a Basalt vault: {MANIFEST} is missing"))
        })?;
        let parsed: Yaml = serde_yaml_ng::from_str(&raw)
            .map_err(|e| VaultError::Manifest(format!("{MANIFEST}: {e}")))?;
        let manifest = Manifest::from_yaml(&parsed).map_err(VaultError::Manifest)?;

        let principals = Self::load_principals(&*transport)?;
        let mut v = Self {
            transport,
            manifest,
            principals,
            descriptors: DescriptorStore::new(),
            folder_records: BTreeMap::new(),
            sidecars: BTreeMap::new(),
            indexes: None,
        };
        v.load_meta()?;
        Ok(v)
    }

    fn read_text(t: &dyn Transport, key: &str) -> Result<Option<String>> {
        Ok(t.get(key)?
            .map(|b| String::from_utf8_lossy(&b).into_owned()))
    }

    fn read_yaml(t: &dyn Transport, key: &str) -> Result<Option<Yaml>> {
        // §3 reads human-authored YAML permissively: any valid YAML 1.2. A
        // file that will not parse is treated as absent rather than fatal,
        // which keeps a typo in one folder's ACL from taking the vault down —
        // and the ACL then grants nothing, which is the safe direction.
        Ok(Self::read_text(t, key)?.and_then(|s| serde_yaml_ng::from_str(&s).ok()))
    }

    fn load_principals(t: &dyn Transport) -> Result<Principals> {
        let users = Self::read_yaml(t, &format!("{PRINCIPALS}users.yaml"))?
            .and_then(|y| y.get("users").and_then(|u| u.as_sequence()).cloned())
            .map(|seq| {
                seq.iter()
                    .filter_map(|u| {
                        Some(User {
                            id: u.get("id").and_then(yaml_text)?,
                            display: u.get("display").and_then(yaml_text),
                            status: u.get("status").and_then(yaml_text),
                            expires: u.get("expires").and_then(yaml_text),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let groups = Self::read_yaml(t, &format!("{PRINCIPALS}groups.yaml"))?
            .and_then(|y| y.get("groups").and_then(|g| g.as_sequence()).cloned())
            .map(|seq| {
                seq.iter()
                    .filter_map(|g| {
                        Some(Group {
                            id: g.get("id").and_then(yaml_text)?,
                            display: g.get("display").and_then(yaml_text),
                            members: g
                                .get("members")
                                .and_then(|m| m.as_sequence())
                                .map(|s| s.iter().filter_map(yaml_text).collect())
                                .unwrap_or_default(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let roles = Self::read_yaml(t, &format!("{PRINCIPALS}roles.yaml"))?
            .and_then(|y| y.get("roles").and_then(|r| r.as_mapping()).cloned())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| {
                        let name = k.as_str()?.to_string();
                        let rights = v
                            .as_sequence()?
                            .iter()
                            .filter_map(yaml_text)
                            .collect::<Vec<_>>();
                        Some((name, rights))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Principals::new(users, groups, roles))
    }

    fn load_meta(&mut self) -> Result<()> {
        let keys = self.transport.list_all(META)?;
        let mut folder_acls: BTreeMap<String, FolderAcl> = BTreeMap::new();

        for key in keys {
            if let Some(rest) = key.strip_prefix(&format!("{META}acl/")) {
                if let Some(folder) = rest.strip_suffix("acl.yaml") {
                    let Some(y) = Self::read_yaml(&*self.transport, &key)? else {
                        continue;
                    };
                    let mut acl = FolderAcl::default();
                    if let Some(f) = y.get("folder") {
                        acl.folder = Some(Descriptor::from_yaml(f));
                    }
                    if let Some(entries) = y.get("entries").and_then(|e| e.as_mapping()) {
                        for (k, v) in entries {
                            if let Some(name) = k.as_str() {
                                acl.entries
                                    .insert(name.to_string(), Descriptor::from_yaml(v));
                            }
                        }
                    }
                    folder_acls.insert(folder.to_string(), acl);
                }
            } else if let Some(rest) = key.strip_prefix(&format!("{META}folders/")) {
                if let Some(folder) = rest.strip_suffix("folder.yaml") {
                    let Some(y) = Self::read_yaml(&*self.transport, &key)? else {
                        continue;
                    };
                    self.folder_records.insert(
                        folder.to_string(),
                        FolderRecord {
                            id: y
                                .get("basalt")
                                .and_then(|b| b.get("id"))
                                .and_then(yaml_text),
                            title: y.get("title").and_then(yaml_text),
                            order: y
                                .get("order")
                                .and_then(|o| o.as_sequence())
                                .map(|s| s.iter().filter_map(yaml_text).collect())
                                .unwrap_or_default(),
                            sort: y.get("sort").and_then(yaml_text),
                            publish: y.get("publish").and_then(|p| p.as_bool()) != Some(false),
                        },
                    );
                } else if let Some(folder) = rest.strip_suffix("entries.yaml") {
                    let Some(y) = Self::read_yaml(&*self.transport, &key)? else {
                        continue;
                    };
                    let mut sc = Sidecar::default();
                    if let Some(entries) = y.get("entries").and_then(|e| e.as_mapping()) {
                        for (k, v) in entries {
                            if let Some(name) = k.as_str() {
                                sc.entries.insert(
                                    name.to_string(),
                                    SidecarEntry {
                                        id: v.get("id").and_then(yaml_text),
                                        title: v.get("title").and_then(yaml_text),
                                    },
                                );
                            }
                        }
                    }
                    self.sidecars.insert(folder.to_string(), sc);
                }
            }
        }

        self.descriptors = DescriptorStore {
            folder_acls,
            inline_acls: BTreeMap::new(),
        };
        Ok(())
    }

    // ------------------------------------------------------------ scanning

    /// Read every content object.
    ///
    /// Keys that §1.1 rejects are skipped rather than erroring: a vault can
    /// arrive carrying an illegal key (an NFD filename from a Mac, say), and
    /// the index pass reports it instead of refusing to run.
    pub fn scan(&self) -> Result<Vec<Scanned>> {
        let mut keys: Vec<String> = self
            .transport
            .list_all(CONTENT)?
            .into_iter()
            .filter(|k| k.starts_with(CONTENT) && is_valid_key(k))
            .collect();
        sort_utf8(&mut keys);

        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            // §1 promises nothing about `list` reflecting a recent write, so a
            // key that vanished between the listing and the read is normal.
            let Some(bytes) = self.transport.get(&key)? else {
                continue;
            };
            let st = self.transport.stat(&key)?;
            let path = key_to_path(&key).unwrap_or(&key).to_string();
            out.push(Scanned {
                size: st.as_ref().map(|s| s.size).unwrap_or(bytes.len() as u64),
                etag: st.and_then(|s| s.etag),
                key,
                path,
                bytes,
            });
        }
        Ok(out)
    }

    /// Rebuild every index from content alone. `write` persists them.
    pub fn reindex(&mut self, write: bool) -> Result<()> {
        self.reindex_opts(if write {
            IndexWrite::persist()
        } else {
            IndexWrite::dry()
        })
    }

    /// Rebuild, with explicit control over the §10.7 write guard.
    pub fn reindex_opts(&mut self, write: IndexWrite) -> Result<()> {
        let scanned = self.scan()?;
        let generated = now_rfc3339();
        self.reindex_with_opts(&scanned, &generated, write)
    }

    /// Rebuild with a caller-supplied `generated` stamp. The conformance
    /// fixtures pin it to the epoch so that two runs are byte-comparable
    /// without relying on §13.2's exclusion.
    pub fn reindex_with(
        &mut self,
        scanned: &[Scanned],
        generated: &str,
        write: bool,
    ) -> Result<()> {
        self.reindex_with_opts(
            scanned,
            generated,
            if write {
                IndexWrite::persist()
            } else {
                IndexWrite::dry()
            },
        )
    }

    /// Rebuild from a given scan, with explicit control over the §10.7 guard.
    pub fn reindex_with_opts(
        &mut self,
        scanned: &[Scanned],
        generated: &str,
        write: IndexWrite,
    ) -> Result<()> {
        let built: BuiltIndexes = build_indexes(BuildInput {
            scanned,
            vault_id: &self.manifest.vault_id,
            sidecars: &self.sidecars,
            folder_records: &self.folder_records,
            generated,
        });

        // §8.6: an inline frontmatter descriptor replaces the node's entry in
        // the folder ACL file. Installed before the search pass, because the
        // leak rule in §8.8 is evaluated against the *effective* ACL.
        self.descriptors.inline_acls = built
            .node_data
            .iter()
            .filter_map(|n| n.acl.clone().map(|d| (n.path.clone(), d)))
            .collect();

        let opts = self.manifest.eval_opts();
        let descriptors = &self.descriptors;
        let principals = &self.principals;
        let search = build_search_index(
            &built.node_data,
            &self.manifest.vault_id,
            &built.source_digest,
            generated,
            |n| {
                // §8.8: text is indexed only from nodes that grant `read` to
                // `everyone`. Evaluated as the anonymous principal against a
                // public ceiling, which also forces the `publish` right of
                // §8.1 — "readable by everyone with an account" is not the
                // same as "safe to put in a world-readable index".
                check_access(
                    descriptors,
                    principals,
                    "anonymous",
                    &n.path,
                    &["read".to_string()],
                    crate::acl::EvalOpts {
                        audience: crate::acl::Audience::Public,
                        ..opts
                    },
                )
                .allowed
            },
        );

        let indexes = Indexes {
            nodes: built.nodes,
            links: built.links,
            backlinks: built.backlinks,
            tags: built.tags,
            search,
            digest: built.digest,
            integrity: built.integrity,
            node_data: built.node_data,
            edges: built.edges,
            issues: built.issues,
            source_digest: built.source_digest,
        };

        if write.persist {
            // §10.7: refuse to replace a non-empty stored index with an empty
            // one unless explicitly forced. The same reasoning as §11.3 — on a
            // knowledge vault, silent destruction is worse than a refusal.
            if indexes.node_data.is_empty() && !write.force {
                let previously = self.stored_node_count()?;
                if previously > 0 {
                    // The in-memory indexes are left as they were, so a caller
                    // that handles the error still sees the vault it had.
                    return Err(VaultError::EmptyIndexRefused {
                        found: 0,
                        previously,
                    });
                }
            }
            for (name, key) in INDEX_KEYS {
                if let Some(obj) = indexes.by_name(name) {
                    self.transport.put(
                        key,
                        &obj.to_canonical_bytes(),
                        &PutMeta::content_type("application/json"),
                    )?;
                }
            }
        }
        self.indexes = Some(indexes);
        Ok(())
    }

    /// How many nodes the stored `index/nodes.json` claims, for the §10.7
    /// guard. A stored index that will not parse counts as zero: it is already
    /// unusable, so overwriting it destroys nothing.
    pub fn stored_node_count(&self) -> Result<usize> {
        Ok(Self::read_text(&*self.transport, "index/nodes.json")?
            .and_then(|t| parse_json(&t).ok())
            .and_then(|j| j.get("entries").and_then(|e| e.as_array()).map(|a| a.len()))
            .unwrap_or(0))
    }

    /// Load the stored index objects without rebuilding.
    pub fn load_stored_indexes(&self) -> Result<BTreeMap<String, Json>> {
        let mut out = BTreeMap::new();
        for (name, key) in INDEX_KEYS {
            if let Some(text) = Self::read_text(&*self.transport, key)? {
                if let Ok(v) = parse_json(&text) {
                    out.insert(name.to_string(), v);
                }
            }
        }
        Ok(out)
    }

    /// Index freshness (§10.6): the current digest against the stored index's
    /// `source_digest`. One comparison, never timestamps — §1 forbids relying
    /// on those.
    pub fn index_state(&self) -> Result<(IndexState, String, Option<String>)> {
        let scanned = self.scan()?;
        let entries: Vec<(String, String)> = scanned
            .iter()
            .map(|s| {
                use sha2::{Digest as _, Sha256};
                (
                    s.path.clone(),
                    format!("sha256:{}", crate::order::hex(&Sha256::digest(&s.bytes))),
                )
            })
            .collect();
        let current = compute_digest(&entries).root;
        let stored = self
            .load_stored_indexes()?
            .get("nodes")
            .and_then(|n| n.get("source_digest"))
            .and_then(|d| d.as_str())
            .map(str::to_string);
        let state = match &stored {
            Some(s) if *s == current => IndexState::Fresh,
            _ => IndexState::Stale,
        };
        Ok((state, current, stored))
    }

    /// Honor `index.stale_policy` (§10.6, §3.1).
    pub fn ensure_indexes(&mut self) -> Result<IndexState> {
        let (state, _, _) = self.index_state()?;
        match (state, self.manifest.stale_policy) {
            (IndexState::Fresh, _) => {
                if self.indexes.is_none() {
                    self.reindex(false)?;
                }
                Ok(IndexState::Fresh)
            }
            (_, StalePolicy::Rebuild) => {
                self.reindex(false)?;
                Ok(IndexState::Rebuilt)
            }
            (_, StalePolicy::ServeStale) => {
                if self.indexes.is_none() {
                    self.reindex(false)?;
                }
                Ok(IndexState::Stale)
            }
            (_, StalePolicy::Refuse) => Ok(IndexState::Stale),
        }
    }

    // ------------------------------------------------------------- reading

    /// Check access for a principal on a path (§8).
    pub fn can(&self, principal: &str, path: &str, rights: &[&str]) -> AccessResult {
        let rights: Vec<String> = rights.iter().map(|r| r.to_string()).collect();
        check_access(
            &self.descriptors,
            &self.principals,
            principal,
            path,
            &rights,
            self.manifest.eval_opts(),
        )
    }

    /// Effective rights with the deciding ACE per right (§8.7).
    pub fn effective(&self, principal: &str, path: &str) -> AccessResult {
        effective_rights(
            &self.descriptors,
            &self.principals,
            principal,
            path,
            self.manifest.eval_opts(),
        )
    }

    /// Read a node for a principal.
    ///
    /// §12.3: the 404/403 split is an information-leak boundary. A 403 on a
    /// path the requester was not allowed to discover confirms that path
    /// exists, so "cannot know it exists" must be indistinguishable from
    /// "does not exist".
    pub fn read_node(&self, principal: &str, path: &str) -> Result<NodeResponse> {
        let Some(indexes) = &self.indexes else {
            return Ok(NodeResponse::status(404));
        };
        let Some(node) = indexes.node(path) else {
            return Ok(NodeResponse::status(404));
        };
        let decision = self.can(principal, path, &["read"]);
        if !decision.allowed {
            let discoverable = self.can(principal, parent_folder(path), &["list"]).allowed;
            return Ok(NodeResponse::status(if discoverable { 403 } else { 404 }));
        }
        let Some(bytes) = self.transport.get(&path_to_key(path))? else {
            return Ok(NodeResponse::status(404));
        };
        let text = if matches!(node.kind, Kind::Note | Kind::Data) {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        } else {
            None
        };
        Ok(NodeResponse {
            status: 200,
            path: Some(path.to_string()),
            id: node.id.clone(),
            kind: Some(node.kind),
            title: node.title.clone(),
            bytes: Some(bytes),
            text,
        })
    }

    /// Direct entries of a folder, filtered to what the principal may see.
    pub fn list_folder(&self, principal: &str, folder: &str) -> ListResponse {
        if !self.can(principal, folder, &["list"]).allowed {
            // The same 404/403 split as `read_node`, one level up.
            let parent_visible = if folder.is_empty() {
                false
            } else {
                self.can(
                    principal,
                    parent_folder(folder.trim_end_matches('/')),
                    &["list"],
                )
                .allowed
            };
            return ListResponse {
                status: if parent_visible { 403 } else { 404 },
                ..Default::default()
            };
        }
        let Some(indexes) = &self.indexes else {
            return ListResponse {
                status: 404,
                ..Default::default()
            };
        };

        let mut entries: Vec<ListEntry> = Vec::new();
        for n in &indexes.node_data {
            if parent_folder(&n.path) != folder {
                continue;
            }
            if !self.can(principal, &n.path, &["read"]).allowed {
                continue;
            }
            entries.push(ListEntry {
                path: n.path.clone(),
                kind: n.kind.as_str().to_string(),
                title: n.title.clone(),
                id: n.id.clone(),
            });
        }
        entries.sort_by(|a, b| compare_utf8(&a.path, &b.path));

        let mut folders: Vec<String> = implied_folders(indexes.node_data.iter().map(|n| &n.path))
            .into_iter()
            .filter(|f| parent_folder(f.trim_end_matches('/')) == folder)
            .filter(|f| self.can(principal, f, &["list"]).allowed)
            .collect();
        sort_utf8(&mut folders);

        ListResponse {
            status: 200,
            entries,
            folders,
        }
    }

    /// Out-edges and backlinks for a node, redacted per §9.5.
    ///
    /// A redacted edge is returned with its target replaced rather than
    /// removed: dropping it would make the graph silently wrong, and a reader
    /// could not tell a redacted link from a dangling one.
    pub fn links(&self, principal: &str, path: &str) -> LinksResponse {
        let Some(indexes) = &self.indexes else {
            return LinksResponse {
                status: 404,
                ..Default::default()
            };
        };
        let Some(node) = indexes.node(path) else {
            return LinksResponse {
                status: 404,
                ..Default::default()
            };
        };
        if !self.can(principal, path, &["read"]).allowed {
            return LinksResponse {
                status: 403,
                ..Default::default()
            };
        }
        let Some(node_id) = node.id.clone() else {
            return LinksResponse {
                status: 200,
                ..Default::default()
            };
        };

        let redact_titles = self.manifest.redact_titles;
        let visible = |id: &str| {
            indexes
                .node_by_id(id)
                .is_some_and(|n| self.can(principal, &n.path, &["read"]).allowed)
        };

        let out = indexes
            .edges
            .iter()
            .filter(|e| e.from == node_id)
            .map(|e| {
                let mut shaped = LinkView {
                    kind: e.kind.as_str().to_string(),
                    raw: e.raw.clone(),
                    alias: e.alias.clone(),
                    anchor: e.anchor.clone(),
                    line: e.line,
                    col: e.col,
                    to: e.to.clone(),
                    target_path: None,
                    target_title: None,
                    redacted: false,
                };
                if let Some(to) = &e.to {
                    match indexes.node_by_id(to) {
                        Some(t) if visible(to) => {
                            shaped.target_path = Some(t.path.clone());
                            shaped.target_title = t.title.clone();
                        }
                        Some(t) => {
                            shaped.to = Some("redacted".into());
                            shaped.redacted = true;
                            // §9.5: when redact_titles is false the edge keeps
                            // its target's title, so readers see *that*
                            // something exists without reading it. Opt-in,
                            // because a title discloses the thing it names.
                            shaped.target_title =
                                if redact_titles { None } else { t.title.clone() };
                        }
                        None => {}
                    }
                }
                shaped
            })
            .collect();

        let mut back: Vec<BacklinkView> = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for e in &indexes.edges {
            if e.to.as_deref() != Some(node_id.as_str()) || seen.contains(&e.from) {
                continue;
            }
            seen.push(e.from.clone());
            let Some(src) = indexes.node_by_id(&e.from) else {
                continue;
            };
            if visible(&e.from) {
                back.push(BacklinkView {
                    id: src.id.clone().unwrap_or_default(),
                    path: Some(src.path.clone()),
                    title: src.title.clone(),
                });
            } else {
                back.push(BacklinkView {
                    id: "redacted".into(),
                    path: None,
                    title: if redact_titles {
                        None
                    } else {
                        src.title.clone()
                    },
                });
            }
        }
        back.sort_by(|a, b| compare_utf8(&a.id, &b.id));

        LinksResponse {
            status: 200,
            out,
            backlinks: back,
        }
    }

    /// Search, filtered to readable nodes (§12.5).
    pub fn search(&self, principal: &str, query: &str) -> Vec<SearchHit> {
        let Some(indexes) = &self.indexes else {
            return Vec::new();
        };
        let terms = indexes.search.get("terms").and_then(|t| t.as_object());
        let Some(terms) = terms else {
            return Vec::new();
        };

        let mut scores: BTreeMap<String, i64> = BTreeMap::new();
        for tok in crate::indexer::tokenize(query) {
            let Some(Json::Array(postings)) = terms.get(&tok) else {
                continue;
            };
            for p in postings {
                let Some(id) = p.get("node").and_then(|n| n.as_str()) else {
                    continue;
                };
                let Some(n) = indexes.node_by_id(id) else {
                    continue;
                };
                if !self.can(principal, &n.path, &["read"]).allowed {
                    continue;
                }
                let tf = match p.get("tf") {
                    Some(Json::Int(i)) => *i,
                    _ => 0,
                };
                *scores.entry(id.to_string()).or_insert(0) += tf;
            }
        }
        let mut hits: Vec<SearchHit> = scores
            .into_iter()
            .filter_map(|(id, score)| {
                let n = indexes.node_by_id(&id)?;
                Some(SearchHit {
                    id,
                    path: n.path.clone(),
                    title: n.title.clone(),
                    score,
                })
            })
            .collect();
        hits.sort_by(|a, b| b.score.cmp(&a.score).then(compare_utf8(&a.path, &b.path)));
        hits
    }

    /// The navigable tree, pruned to what the principal may see (§12.3).
    ///
    /// §15 asks implementations to omit counts of invisible entries, since a
    /// pruned tree that reports "3 hidden" still leaks how many siblings
    /// exist. This one reports nothing about what it pruned.
    pub fn tree(&self, principal: &str) -> Option<TreeNode> {
        self.tree_at(principal, "")
    }

    fn tree_at(&self, principal: &str, folder: &str) -> Option<TreeNode> {
        let listing = self.list_folder(principal, folder);
        if listing.status != 200 {
            return None;
        }
        Some(TreeNode {
            title: self
                .folder_records
                .get(folder)
                .and_then(|r| r.title.clone())
                .or_else(|| {
                    let name = basename(folder.trim_end_matches('/'));
                    if name.is_empty() {
                        self.manifest.vault_title.clone()
                    } else {
                        Some(name.to_string())
                    }
                }),
            folder: folder.to_string(),
            entries: listing.entries,
            folders: listing
                .folders
                .iter()
                .filter_map(|f| self.tree_at(principal, f))
                .collect(),
        })
    }

    // ------------------------------------------------------------- writing

    /// Mint ids for unbound objects and persist them (§4.3) — frontmatter for
    /// notes, the folder's entry sidecar otherwise.
    ///
    /// A read-only implementation MUST instead surface unbound objects with
    /// `id: null` and MUST NOT invent ephemeral ids, which is what the index
    /// pass does when this is never called.
    pub fn mint_ids(&mut self) -> Result<Vec<(String, String)>> {
        let mut minted = Vec::new();
        let scanned = self.scan()?;
        for item in &scanned {
            let kind = kind_for(&item.path);
            if kind == Kind::Note {
                let text = String::from_utf8_lossy(&item.bytes).into_owned();
                if parse_note(&text, &item.path).id.is_some() {
                    continue;
                }
                let id = crate::ulid();
                match with_id(&text, &id) {
                    Ok(updated) => {
                        self.transport
                            .put(&item.key, updated.as_bytes(), &PutMeta::default())?;
                        minted.push((item.path.clone(), id));
                    }
                    Err(why) => {
                        // §13.4: an implementation that cannot preserve
                        // comments MUST refuse to rewrite the file and MUST
                        // report it, rather than silently stripping them.
                        eprintln!("refusing to rewrite {}: {why}", item.path);
                    }
                }
            } else {
                let folder = parent_folder(&item.path).to_string();
                let name = basename(&item.path).to_string();
                if self
                    .sidecars
                    .get(&folder)
                    .and_then(|s| s.entries.get(&name))
                    .and_then(|e| e.id.as_ref())
                    .is_some()
                {
                    continue;
                }
                let id = crate::ulid();
                let sc = self.sidecars.entry(folder.clone()).or_default();
                sc.entries.entry(name).or_default().id = Some(id.clone());
                let yaml = render_sidecar(sc);
                self.transport.put(
                    &format!("{META}folders/{folder}entries.yaml"),
                    yaml.as_bytes(),
                    &PutMeta::default(),
                )?;
                minted.push((item.path.clone(), id));
            }
        }
        Ok(minted)
    }

    // -------------------------------------------------------------- export

    /// Export the vault as a public static vault (§12.6).
    ///
    /// The export includes only nodes granting both `read` and `publish` to
    /// `anonymous` under §8.4, and regenerates every index from that filtered
    /// subset rather than copying the vault's own — §8.8 is explicit that
    /// copying `index/` alongside public content is non-conforming, because it
    /// leaks the private half of the graph.
    ///
    /// The result is a complete, smaller vault: it carries its own manifest,
    /// its own ACL granting the public what it may see, and its own digest, and
    /// is itself servable by a gatekeeper. "Export" and "publish a subset" are
    /// the same operation.
    ///
    /// On the one place §12.6 reads two ways: it asks for links to excluded
    /// nodes to be "redacted per §9.5" *and* for every index to be regenerated
    /// from the filtered subset. Those pull apart — a `to: "redacted"` marker
    /// cannot be rebuilt from content that no longer mentions the target, so an
    /// export carrying one would fail its own §14.3 self-check and break the
    /// rebuildability §0 rests on. This implementation follows the explicit
    /// MUST: it regenerates, so an edge to an excluded node is simply
    /// unresolved *within the export*, which is true there. §9.5's redaction
    /// stays where its own wording puts it — on a gatekeeper response.
    pub fn export(
        &mut self,
        dest_box: Box<dyn Transport>,
        opts: ExportOpts,
    ) -> Result<(ExportSummary, Vault)> {
        if self.indexes.is_none() {
            self.reindex(false)?;
        }
        let dest: &dyn Transport = &*dest_box;
        let public_audience = crate::acl::EvalOpts {
            audience: crate::acl::Audience::Public,
            ..self.manifest.eval_opts()
        };

        let indexes = self.indexes.as_ref().unwrap();
        let mut included: Vec<String> = Vec::new();
        let mut excluded: Vec<String> = Vec::new();
        for n in &indexes.node_data {
            // `read` alone is not enough: §8.1 makes `anonymous` need
            // `publish` as well, which is the whole reason "shared with every
            // account" and "on the public internet" are separable decisions.
            let allowed = check_access(
                &self.descriptors,
                &self.principals,
                "anonymous",
                &n.path,
                &["read".to_string()],
                public_audience,
            )
            .allowed;
            // §5.2: `basalt.publish: false` excludes a node from publication
            // independently of its ACL.
            if allowed && n.publish {
                included.push(n.path.clone());
            } else {
                excluded.push(n.path.clone());
            }
        }

        // The manifest. `audience: public` because that is what the export is,
        // and the security block is rewritten rather than copied: the source
        // vault's `bypass_traverse` is a property of how it is served.
        let title = self
            .manifest
            .vault_title
            .as_deref()
            .unwrap_or("Exported vault");
        let vault_id = opts
            .vault_id
            .clone()
            .unwrap_or_else(|| self.manifest.vault_id.clone());
        let home = self
            .manifest
            .home
            .as_deref()
            .filter(|h| included.iter().any(|p| p == h));
        let mut manifest = format!(
            "# Exported by basalt (§12.6): only nodes granting read and publish\n\
             # to `anonymous` are present, and every index is regenerated from\n\
             # this filtered subset rather than copied (§8.8).\n\
             basalt: 1\nvault:\n  id: {vault_id}\n  title: {}\n",
            yaml_scalar_out(title)
        );
        manifest.push_str("publish:\n  audience: public\n");
        if let Some(h) = home {
            manifest.push_str(&format!("  home: {}\n", yaml_scalar_out(h)));
        }
        manifest.push_str("index:\n  stale_policy: rebuild\n");
        manifest.push_str("security:\n  bypass_traverse: false\n  deny_unresolved: true\n");
        dest.put(MANIFEST, manifest.as_bytes(), &PutMeta::default())?;

        // One root ACL granting the public exactly what it may do. Every node
        // present is public by construction, so there are no per-node
        // descriptors to write — and none to leak.
        let root_acl = concat!(
            "# Every object in this export is public by construction (12.6), so one\n",
            "# root descriptor is the whole security model, and there are no per-node\n",
            "# descriptors to write - and so none to leak.\n",
            "folder:\n",
            "  protected: true\n",
            "  dacl:\n",
            "    - {type: allow, subject: everyone, rights: [read, list, traverse, publish], flags: [oi, ci]}\n",
        );
        dest.put(
            &format!("{META}acl/acl.yaml"),
            root_acl.as_bytes(),
            &PutMeta::default(),
        )?;

        // Content. Copied byte for byte, so node ids and `content_hash` carry
        // over and a reader can tell the export's copy of a note is the same
        // note.
        for path in &included {
            let key = path_to_key(path);
            if let Some(bytes) = self.transport.get(&key)? {
                dest.put(&key, &bytes, &PutMeta::default())?;
            }
        }

        // Folder records and entry sidecars for folders that survived — the
        // sidecars carry the node ids of assets, without which an exported
        // image would be unbound (§4.2).
        let surviving: std::collections::BTreeSet<String> = included
            .iter()
            .map(|p| parent_folder(p).to_string())
            .collect();
        for folder in &surviving {
            let rec_key = format!("{META}folders/{folder}folder.yaml");
            if let Some(bytes) = self.transport.get(&rec_key)? {
                dest.put(&rec_key, &bytes, &PutMeta::default())?;
            }
            if let Some(sc) = self.sidecars.get(folder) {
                let kept = Sidecar {
                    entries: sc
                        .entries
                        .iter()
                        .filter(|(name, _)| included.contains(&format!("{folder}{name}")))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                };
                if !kept.entries.is_empty() {
                    dest.put(
                        &format!("{META}folders/{folder}entries.yaml"),
                        render_sidecar(&kept).as_bytes(),
                        &PutMeta::default(),
                    )?;
                }
            }
        }

        // Regenerate every index from the filtered subset. Nothing under
        // `index/`, `principals/` or `meta/acl/` is copied: the export's
        // indexes know only about the export's content, which is the point.
        // The export is now complete on disk; open it as a vault in its own
        // right so its indexes are built the way any other vault's are.
        let mut exported = Vault::open(dest_box)?;
        exported.reindex_opts(IndexWrite::forced())?;

        Ok((
            ExportSummary {
                vault_id,
                included,
                excluded,
                source_digest: exported.indexes.as_ref().unwrap().source_digest.clone(),
            },
            exported,
        ))
    }

    /// Integrity findings from the last index pass, plus the principal-level
    /// findings of §7 (§10.8).
    pub fn integrity(&self) -> Vec<Issue> {
        let mut out: Vec<Issue> = self
            .indexes
            .as_ref()
            .map(|i| i.issues.clone())
            .unwrap_or_default();
        for n in &self.principals.integrity {
            out.push(Issue {
                severity: n.severity,
                code: n.code.clone(),
                path: None,
                detail: Some(n.subject.clone()),
            });
        }
        // §8.4: an ACE whose subject does not resolve is an integrity error,
        // reported here because nothing else walks every stored descriptor.
        let mut seen: Vec<String> = Vec::new();
        for (folder, acl) in &self.descriptors.folder_acls {
            let mut check = |path: &str, d: &Descriptor, out: &mut Vec<Issue>| {
                for ace in &d.dacl {
                    if !self.principals.exists(&ace.subject) && !seen.contains(&ace.subject) {
                        seen.push(ace.subject.clone());
                        out.push(Issue {
                            severity: Severity::Error,
                            code: "UNRESOLVED_SUBJECT".into(),
                            path: Some(path.to_string()),
                            detail: Some(ace.subject.clone()),
                        });
                    }
                    let (_, unresolved) = self.principals.expand_rights(&ace.rights);
                    for r in unresolved {
                        if !seen.contains(&r) {
                            seen.push(r.clone());
                            out.push(Issue {
                                severity: Severity::Error,
                                code: "UNRESOLVED_ROLE".into(),
                                path: Some(path.to_string()),
                                detail: Some(r),
                            });
                        }
                    }
                }
            };
            if let Some(d) = &acl.folder {
                check(folder, d, &mut out);
            }
            for (name, d) in &acl.entries {
                check(&format!("{folder}{name}"), d, &mut out);
            }
        }
        out
    }
}

/// Render an entry sidecar as block-style YAML (§13.4).
///
/// Only used for a sidecar this implementation is creating or extending; a
/// hand-written one with comments is never reserialized, because §13.4 forbids
/// stripping them.
fn render_sidecar(sc: &Sidecar) -> String {
    let mut out = String::from("entries:\n");
    if sc.entries.is_empty() {
        return "entries: {}\n".to_string();
    }
    for (name, e) in &sc.entries {
        out.push_str(&format!("  {}:\n", yaml_key(name)));
        if let Some(id) = &e.id {
            out.push_str(&format!("    id: {id}\n"));
        }
        if let Some(t) = &e.title {
            out.push_str(&format!("    title: {}\n", yaml_scalar_out(t)));
        }
    }
    out
}

fn yaml_key(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        s.to_string()
    } else {
        yaml_scalar_out(s)
    }
}

/// §13.4: double quotes when quoting is needed, never single.
fn yaml_scalar_out(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

// -------------------------------------------------------------- responses

/// Options for [`Vault::export`].
#[derive(Debug, Clone, Default)]
pub struct ExportOpts {
    /// The exported vault's id.
    ///
    /// §12.6 does not say whether an export keeps the source's `vault.id`, and
    /// §3.1 pulls both ways: "copying a vault to a new bucket preserves it,
    /// forking a vault MUST mint a new one", and an export is neither exactly.
    /// The default here preserves it, because the nodes in the export *are*
    /// the same nodes with the same ids. Set this to mint a fresh one when the
    /// export will be served beside the private vault and a client might cache
    /// on `X-Basalt-Vault` (§12.3).
    pub vault_id: Option<String>,
}

/// What an export did, for the operator who has to trust it.
#[derive(Debug, Clone)]
pub struct ExportSummary {
    pub vault_id: String,
    pub included: Vec<String>,
    pub excluded: Vec<String>,
    pub source_digest: String,
}

#[derive(Debug, Clone, Default)]
pub struct NodeResponse {
    pub status: u16,
    pub path: Option<String>,
    pub id: Option<String>,
    pub kind: Option<Kind>,
    pub title: Option<String>,
    pub bytes: Option<Vec<u8>>,
    pub text: Option<String>,
}

impl NodeResponse {
    fn status(status: u16) -> Self {
        Self {
            status,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ListEntry {
    pub path: String,
    pub kind: String,
    pub title: Option<String>,
    pub id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ListResponse {
    pub status: u16,
    pub entries: Vec<ListEntry>,
    pub folders: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LinkView {
    pub kind: String,
    pub raw: String,
    pub alias: Option<String>,
    pub anchor: Option<String>,
    pub line: usize,
    pub col: usize,
    pub to: Option<String>,
    pub target_path: Option<String>,
    pub target_title: Option<String>,
    pub redacted: bool,
}

#[derive(Debug, Clone)]
pub struct BacklinkView {
    pub id: String,
    pub path: Option<String>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LinksResponse {
    pub status: u16,
    pub out: Vec<LinkView>,
    pub backlinks: Vec<BacklinkView>,
}

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: String,
    pub path: String,
    pub title: Option<String>,
    pub score: i64,
}

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub folder: String,
    pub title: Option<String>,
    pub entries: Vec<ListEntry>,
    pub folders: Vec<TreeNode>,
}
