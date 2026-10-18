//! Index generation, PROTOCOL §10.
//!
//! Everything here is derived: delete every index and these functions rebuild
//! all of them from content alone, byte for byte. That property is what makes
//! conformance mechanically checkable, so the only inputs allowed are content
//! bytes and keys — never listing order, never mtimes.

use crate::acl::Descriptor;
use crate::canonical::Json;
use crate::frontmatter::{is_ulid, kind_for, parse_note, Kind, NodeError, Severity};
use crate::keys::{
    basename, find_collisions, find_folder_case_divergence, folders_of, implied_folders,
    key_to_path, parent_folder, stem,
};
use crate::links::{
    anchor_resolves, extract_block_ids, extract_data_links, extract_headings, extract_links,
    tag_closure, EdgeKind, Heading, ResolvableNode, Resolver,
};
use crate::order::{compare_utf8, fold_case, nfc, sort_utf8};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;

pub const SPEC: i64 = 1;

/// `sha256:…` over the concatenation of its parts.
fn sha256_hex(parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    format!("sha256:{}", crate::order::hex(&h.finalize()))
}

fn sha256_raw(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn unhex(hash: &str) -> Vec<u8> {
    let hex = hash.strip_prefix("sha256:").unwrap_or(hash);
    (0..hex.len() / 2)
        .filter_map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

// ------------------------------------------------------------------ input

/// One scanned content object: the key, the path, the bytes, and whatever the
/// transport's `stat` reported.
#[derive(Debug, Clone)]
pub struct Scanned {
    pub key: String,
    pub path: String,
    pub bytes: Vec<u8>,
    pub size: u64,
    pub etag: Option<String>,
}

/// A `meta/folders/<folder>/entries.yaml` sidecar (§6.1).
#[derive(Debug, Clone, Default)]
pub struct Sidecar {
    pub entries: BTreeMap<String, SidecarEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct SidecarEntry {
    pub id: Option<String>,
    pub title: Option<String>,
}

/// A `meta/folders/<folder>/folder.yaml` record (§6).
#[derive(Debug, Clone, Default)]
pub struct FolderRecord {
    pub id: Option<String>,
    pub title: Option<String>,
    pub order: Vec<String>,
    pub sort: Option<String>,
    pub publish: bool,
}

// ----------------------------------------------------------------- output

/// An integrity finding (§10.8). Index passes collect these rather than
/// throwing: refusing to serve a vault because one file has bad frontmatter
/// would be the wrong trade for a publishing system.
#[derive(Debug, Clone)]
pub struct Issue {
    pub severity: Severity,
    pub code: String,
    pub path: Option<String>,
    pub detail: Option<String>,
}

/// A node as the indexer understands it — a superset of what §10.1 serializes,
/// because resolution and ACL evaluation need the parsed body too.
#[derive(Debug, Clone)]
pub struct IndexedNode {
    pub path: String,
    pub kind: Kind,
    pub id: Option<String>,
    pub title: Option<String>,
    pub tags: Vec<String>,
    pub aliases: Vec<String>,
    pub publish: bool,
    pub size: u64,
    pub etag: Option<String>,
    pub content_hash: String,
    pub headings: Vec<Heading>,
    pub block_ids: Vec<String>,
    pub acl: Option<Descriptor>,
    pub errors: Vec<NodeError>,
    pub body: Option<String>,
    pub text: Option<String>,
    pub body_start_line: usize,
}

/// One edge of §10.2.
#[derive(Debug, Clone)]
pub struct Edge {
    pub from: String,
    pub to: Option<String>,
    pub kind: EdgeKind,
    pub raw: String,
    pub alias: Option<String>,
    pub anchor: Option<String>,
    pub anchor_resolved: bool,
    pub ambiguous: bool,
    pub candidates: Vec<String>,
    pub line: usize,
    pub col: usize,
}

/// The merkle root and per-folder subtree hashes of §10.6.
#[derive(Debug, Clone)]
pub struct DigestResult {
    pub root: String,
    pub count: usize,
    pub tree: BTreeMap<String, String>,
}

/// Compute the merkle root over `content/` (§10.6).
///
/// Sorting the *leaf hashes* rather than the paths makes the root independent
/// of traversal order, so a store whose `list` is unordered (§1) cannot change
/// the result.
pub fn compute_digest(entries: &[(String, String)]) -> DigestResult {
    let leaf = |path: &str, content_hash: &str| -> [u8; 32] {
        sha256_raw(&[nfc(path).as_bytes(), &[0u8], &unhex(content_hash)])
    };

    let mut leaves: Vec<[u8; 32]> = entries.iter().map(|(p, h)| leaf(p, h)).collect();
    leaves.sort_unstable();
    let root = if leaves.is_empty() {
        // §10.6: the empty content tree has root sha256("").
        sha256_hex(&[])
    } else {
        let flat: Vec<u8> = leaves.concat();
        sha256_hex(&[&flat])
    };

    // Per-folder subtree hashes, so an incremental pass can skip unchanged
    // folders. Same fold as the root, over that folder's subtree only.
    let mut by_folder: BTreeMap<String, Vec<[u8; 32]>> = BTreeMap::new();
    for (path, hash) in entries {
        for f in folders_of(path) {
            by_folder.entry(f).or_default().push(leaf(path, hash));
        }
    }
    let mut tree: BTreeMap<String, String> = BTreeMap::new();
    for (folder, mut hashes) in by_folder {
        hashes.sort_unstable();
        let flat: Vec<u8> = hashes.concat();
        tree.insert(folder, sha256_hex(&[&flat]));
    }
    // Then each object's own hash. Written after the folders so that a path
    // somehow colliding with a folder spelling resolves to the object.
    for (path, hash) in entries {
        tree.insert(path.clone(), hash.clone());
    }

    DigestResult {
        root,
        count: entries.len(),
        tree,
    }
}

/// The shared envelope of §10.
///
/// `generated` is excluded from the digest and from cross-implementation
/// comparison (§13.2), since two runs at different times over identical
/// content must still produce comparable output.
fn envelope(kind: &str, vault_id: &str, source_digest: &str, generated: &str) -> Json {
    Json::obj()
        .set("basalt", Json::Int(SPEC))
        .set("kind", Json::str(kind))
        .set("vault", Json::str(vault_id))
        .set("generated", Json::str(generated))
        .set("source_digest", Json::str(source_digest))
        .build()
}

fn with(mut env: Json, fields: Vec<(&str, Json)>) -> Json {
    let map = env.as_object_mut().expect("envelope is an object");
    for (k, v) in fields {
        map.insert(k.to_string(), v);
    }
    env
}

/// Everything an index pass produces.
pub struct BuiltIndexes {
    pub nodes: Json,
    pub links: Json,
    pub backlinks: Json,
    pub tags: Json,
    pub digest: Json,
    pub integrity: Json,
    pub source_digest: String,
    /// The parsed nodes, for the search pass and the ACL store.
    pub node_data: Vec<IndexedNode>,
    pub edges: Vec<Edge>,
    pub folders: Vec<String>,
    pub issues: Vec<Issue>,
}

pub struct BuildInput<'a> {
    pub scanned: &'a [Scanned],
    pub vault_id: &'a str,
    pub sidecars: &'a BTreeMap<String, Sidecar>,
    pub folder_records: &'a BTreeMap<String, FolderRecord>,
    pub generated: &'a str,
}

/// Build every index from a scan of content.
pub fn build_indexes(input: BuildInput<'_>) -> BuiltIndexes {
    let BuildInput {
        scanned,
        vault_id,
        sidecars,
        folder_records,
        generated,
    } = input;

    let mut issues: Vec<Issue> = Vec::new();

    // ---- pass 1: parse every object, collect identities -------------------
    let mut order: Vec<&Scanned> = scanned.iter().collect();
    order.sort_by(|a, b| compare_utf8(&a.path, &b.path));

    let mut nodes: Vec<IndexedNode> = Vec::new();
    for item in order {
        let path = item.path.clone();
        let kind = kind_for(&path);
        let content_hash = sha256_hex(&[&item.bytes]);
        let folder = parent_folder(&path);
        let sidecar = sidecars
            .get(folder)
            .and_then(|s| s.entries.get(basename(&path)));

        let mut node = IndexedNode {
            path: path.clone(),
            kind,
            id: None,
            title: None,
            tags: Vec::new(),
            aliases: Vec::new(),
            publish: true,
            size: item.size,
            etag: item.etag.clone(),
            content_hash,
            headings: Vec::new(),
            block_ids: Vec::new(),
            acl: None,
            errors: Vec::new(),
            body: None,
            text: None,
            body_start_line: 1,
        };

        if kind == Kind::Note {
            let text = String::from_utf8_lossy(&item.bytes).into_owned();
            let parsed = parse_note(&text, &path);
            node.id = parsed.id;
            node.title = parsed.title;
            node.tags = parsed.tags;
            node.aliases = parsed.aliases;
            node.publish = parsed.publish;
            node.acl = parsed.acl.as_ref().map(Descriptor::from_yaml);
            node.headings = extract_headings(&parsed.body);
            node.block_ids = extract_block_ids(&parsed.body);
            node.body_start_line = parsed.body_start_line;
            node.errors = parsed.errors;
            node.body = Some(parsed.body);
            node.text = Some(text);
        } else {
            // §4.2: an object that cannot carry frontmatter gets its id from
            // the folder's entry sidecar. The id must live outside any index,
            // because the mapping has to survive losing every index.
            if let Some(id) = sidecar.and_then(|s| s.id.as_deref()) {
                if is_ulid(id) {
                    node.id = Some(id.to_lowercase());
                } else {
                    node.errors.push(NodeError {
                        severity: Severity::Error,
                        code: "INVALID_ID".into(),
                        detail: Some(id.to_string()),
                    });
                }
            }
            node.title = sidecar
                .and_then(|s| s.title.clone())
                .or_else(|| Some(stem(basename(&path)).to_string()));
            if kind == Kind::Data {
                node.text = Some(String::from_utf8_lossy(&item.bytes).into_owned());
            }
        }

        for e in &node.errors {
            issues.push(Issue {
                severity: e.severity,
                code: e.code.clone(),
                path: Some(path.clone()),
                detail: e.detail.clone(),
            });
        }
        nodes.push(node);
    }

    // ---- integrity: key collisions and folder-case divergence -------------
    let keys: Vec<&str> = scanned.iter().map(|s| s.key.as_str()).collect();
    for group in find_collisions(keys.iter().copied()) {
        issues.push(Issue {
            severity: Severity::Error,
            code: "KEY_COLLISION".into(),
            path: Some(key_to_path(&group[0]).unwrap_or(&group[0]).to_string()),
            detail: Some(format!("collides with {}", group[1..].join(", "))),
        });
    }
    for group in find_folder_case_divergence(keys.iter().copied()) {
        issues.push(Issue {
            severity: Severity::Warning,
            code: "FOLDER_CASE_DIVERGENCE".into(),
            path: Some(key_to_path(&group[0]).unwrap_or(&group[0]).to_string()),
            detail: Some(format!("also spelled {}", group[1..].join(", "))),
        });
    }

    // §4.3: the bytewise-first path keeps a duplicated id; every other
    // claimant is treated as unbound and re-minted. Deterministic so that two
    // implementations repairing the same damaged vault reach the same result.
    {
        let mut keeper_of: BTreeMap<String, usize> = BTreeMap::new();
        let mut losers: Vec<(usize, String, String)> = Vec::new();
        for i in 0..nodes.len() {
            let Some(id) = nodes[i].id.clone() else {
                continue;
            };
            match keeper_of.get(&id).copied() {
                None => {
                    keeper_of.insert(id, i);
                }
                Some(k) => {
                    let (loser, winner) = if compare_utf8(&nodes[k].path, &nodes[i].path).is_le() {
                        (i, k)
                    } else {
                        keeper_of.insert(id.clone(), i);
                        (k, i)
                    };
                    losers.push((loser, id, nodes[winner].path.clone()));
                }
            }
        }
        for (i, id, winner_path) in losers {
            issues.push(Issue {
                severity: Severity::Warning,
                code: "DUPLICATE_ID".into(),
                path: Some(nodes[i].path.clone()),
                detail: Some(format!("id {id} also claimed by {winner_path}")),
            });
            nodes[i].id = None;
        }
    }

    for n in &nodes {
        if n.id.is_none() {
            issues.push(Issue {
                severity: Severity::Warning,
                code: "UNBOUND_NODE".into(),
                path: Some(n.path.clone()),
                detail: None,
            });
        }
    }

    // ---- §6.1: a sidecar entry whose object is gone -----------------------
    let present: std::collections::BTreeSet<&str> = nodes.iter().map(|n| n.path.as_str()).collect();
    for (folder, sc) in sidecars {
        for name in sc.entries.keys() {
            let p = format!("{folder}{name}");
            if !present.contains(p.as_str()) {
                issues.push(Issue {
                    severity: Severity::Warning,
                    code: "ORPHAN_SIDECAR".into(),
                    path: Some(p),
                    detail: Some("sidecar entry has no object".into()),
                });
            }
        }
    }

    let folders = implied_folders(nodes.iter().map(|n| n.path.as_str()));
    let _ = folder_records; // folder records decorate; they do not index

    // ---- pass 2: resolve links --------------------------------------------
    let resolver = Resolver::build(nodes.iter().filter_map(|n| {
        n.id.as_ref().map(|id| ResolvableNode {
            id: id.clone(),
            path: n.path.clone(),
            aliases: n.aliases.clone(),
        })
    }));
    let headings_by_path: BTreeMap<String, (Vec<Heading>, Vec<String>)> = nodes
        .iter()
        .map(|n| (n.path.clone(), (n.headings.clone(), n.block_ids.clone())))
        .collect();

    let mut edges: Vec<Edge> = Vec::new();
    // Indexed rather than iterated: the loop writes each node's merged tag set
    // back while the resolver, built from the same slice, is still borrowed.
    #[allow(clippy::needless_range_loop)]
    for i in 0..nodes.len() {
        let Some(from_id) = nodes[i].id.clone() else {
            continue;
        };
        if !nodes[i].kind.linkable() {
            continue;
        }
        let path = nodes[i].path.clone();
        let line_offset = if nodes[i].kind == Kind::Note {
            nodes[i].body_start_line - 1
        } else {
            0
        };

        let (raw_edges, inline_tags) = if nodes[i].kind == Kind::Note {
            let found = extract_links(nodes[i].body.as_deref().unwrap_or(""));
            (found.edges, found.tags)
        } else {
            (
                extract_data_links(nodes[i].text.as_deref().unwrap_or(""), &path),
                Vec::new(),
            )
        };

        // §9.6: frontmatter tags and inline tags merge into one set per node,
        // carrying the implied-parent closure and the first-seen casing.
        let mut tag_order: Vec<(String, String)> = Vec::new();
        for t in nodes[i].tags.iter().chain(inline_tags.iter()) {
            for c in tag_closure(t) {
                let f = fold_case(&c);
                if !tag_order.iter().any(|(k, _)| *k == f) {
                    tag_order.push((f, c));
                }
            }
        }
        nodes[i].tags = tag_order.into_iter().map(|(_, d)| d).collect();

        for e in raw_edges {
            if e.kind == EdgeKind::External {
                edges.push(Edge {
                    from: from_id.clone(),
                    to: None,
                    kind: EdgeKind::External,
                    raw: e.raw,
                    alias: e.alias,
                    anchor: None,
                    anchor_resolved: true,
                    ambiguous: false,
                    candidates: Vec::new(),
                    line: e.line + line_offset,
                    col: e.col,
                });
                continue;
            }

            let r = resolver.resolve(&path, &e.raw);
            if r.ambiguous {
                issues.push(Issue {
                    severity: Severity::Warning,
                    code: "AMBIGUOUS_LINK".into(),
                    path: Some(path.clone()),
                    detail: Some(format!(
                        "\"{}\" matches {} nodes",
                        e.raw,
                        r.candidates.len()
                    )),
                });
            }
            if r.id.is_none() {
                issues.push(Issue {
                    severity: Severity::Warning,
                    code: "UNRESOLVED_LINK".into(),
                    path: Some(path.clone()),
                    detail: Some(format!("\"{}\"", e.raw)),
                });
            }

            // §9.3: a bad fragment does not make the edge unresolved — the
            // node resolved; only the anchor did not.
            let anchor_resolved = match r.path.as_deref().and_then(|p| headings_by_path.get(p)) {
                Some((h, b)) => anchor_resolves(e.anchor.as_deref(), h, b),
                None => e.anchor.is_none(),
            };

            edges.push(Edge {
                from: from_id.clone(),
                to: r.id,
                kind: e.kind,
                raw: e.raw,
                alias: e.alias,
                anchor: e.anchor,
                anchor_resolved,
                ambiguous: r.ambiguous,
                candidates: r.candidates,
                line: e.line + line_offset,
                col: e.col,
            });
        }
    }

    // ---- assemble ---------------------------------------------------------
    let digest_entries: Vec<(String, String)> = nodes
        .iter()
        .map(|n| (n.path.clone(), n.content_hash.clone()))
        .collect();
    let digest = compute_digest(&digest_entries);
    let sd = digest.root.clone();

    let nodes_index = with(
        envelope("nodes", vault_id, &sd, generated),
        vec![(
            "entries",
            Json::arr(nodes.iter().map(|n| {
                let mut tags = n.tags.clone();
                sort_utf8(&mut tags);
                Json::obj()
                    .set("id", Json::opt_str(n.id.as_deref()))
                    .set("path", Json::str(&n.path))
                    .set("kind", Json::str(n.kind.as_str()))
                    .set("title", Json::opt_str(n.title.as_deref()))
                    .set("size", Json::Int(n.size as i64))
                    .set("etag", Json::opt_str(n.etag.as_deref()))
                    .set("content_hash", Json::str(&n.content_hash))
                    .set("tags", Json::strings(&tags))
                    .set("aliases", Json::strings(&n.aliases))
                    .set(
                        "headings",
                        Json::arr(n.headings.iter().map(|h| {
                            Json::obj()
                                .set("level", Json::Int(h.level as i64))
                                .set("text", Json::str(&h.text))
                                .set("slug", Json::str(&h.slug))
                                .build()
                        })),
                    )
                    .set("publish", Json::Bool(n.publish))
                    .set(
                        "errors",
                        Json::strings(n.errors.iter().map(|e| e.code.clone())),
                    )
                    .build()
            })),
        )],
    );

    let links_index = with(
        envelope("links", vault_id, &sd, generated),
        vec![(
            "entries",
            Json::arr(edges.iter().map(|e| {
                Json::obj()
                    .set("from", Json::str(&e.from))
                    .set("to", Json::opt_str(e.to.as_deref()))
                    .set("kind", Json::str(e.kind.as_str()))
                    .set("raw", Json::str(&e.raw))
                    .set("alias", Json::opt_str(e.alias.as_deref()))
                    .set("anchor", Json::opt_str(e.anchor.as_deref()))
                    .set("anchor_resolved", Json::Bool(e.anchor_resolved))
                    .set("ambiguous", Json::Bool(e.ambiguous))
                    .set("candidates", Json::strings(&e.candidates))
                    .set("line", Json::Int(e.line as i64))
                    .set("col", Json::Int(e.col as i64))
                    .build()
            })),
        )],
    );

    // §10.3: reverse adjacency, derived wholly from §10.2 and stored only
    // because computing it on demand means reading the whole edge list for
    // every page view. Target ids sort ascending.
    let mut backlinks: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in &edges {
        if let Some(to) = &e.to {
            let v = backlinks.entry(to.clone()).or_default();
            if !v.contains(&e.from) {
                v.push(e.from.clone());
            }
        }
    }
    let backlinks_index = with(
        envelope("backlinks", vault_id, &sd, generated),
        vec![(
            "entries",
            Json::Object(
                backlinks
                    .into_iter()
                    .map(|(k, mut v)| {
                        sort_utf8(&mut v);
                        (k, Json::strings(&v))
                    })
                    .collect(),
            ),
        )],
    );

    // §10.4: tag display form → sorted node ids, including the implied-parent
    // closure already folded into each node's tags.
    let mut tag_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in &nodes {
        let Some(id) = &n.id else { continue };
        for t in &n.tags {
            let v = tag_map.entry(t.clone()).or_default();
            if !v.contains(id) {
                v.push(id.clone());
            }
        }
    }
    let tags_index = with(
        envelope("tags", vault_id, &sd, generated),
        vec![(
            "entries",
            Json::Object(
                tag_map
                    .into_iter()
                    .map(|(k, mut v)| {
                        sort_utf8(&mut v);
                        (k, Json::strings(&v))
                    })
                    .collect(),
            ),
        )],
    );

    let digest_index = with(
        envelope("digest", vault_id, &sd, generated),
        vec![
            ("root", Json::str(&digest.root)),
            ("count", Json::Int(digest.count as i64)),
            (
                "tree",
                Json::Object(
                    digest
                        .tree
                        .iter()
                        .map(|(k, v)| (k.clone(), Json::str(v)))
                        .collect(),
                ),
            ),
        ],
    );

    let mut sorted_issues = issues.clone();
    sorted_issues.sort_by(|a, b| {
        let key = |i: &Issue| {
            format!(
                "{}\u{0}{}\u{0}{}",
                i.path.as_deref().unwrap_or(""),
                i.code,
                i.detail.as_deref().unwrap_or("")
            )
        };
        compare_utf8(&key(a), &key(b))
    });
    let integrity_index = with(
        envelope("integrity", vault_id, &sd, generated),
        vec![(
            "entries",
            Json::arr(sorted_issues.iter().map(|i| {
                let mut o = Json::obj()
                    .set("severity", Json::str(i.severity.as_str()))
                    .set("code", Json::str(&i.code));
                if let Some(p) = &i.path {
                    o = o.set("path", Json::str(p));
                }
                if let Some(d) = &i.detail {
                    o = o.set("detail", Json::str(d));
                }
                o.build()
            })),
        )],
    );

    BuiltIndexes {
        nodes: nodes_index,
        links: links_index,
        backlinks: backlinks_index,
        tags: tags_index,
        digest: digest_index,
        integrity: integrity_index,
        source_digest: sd,
        node_data: nodes,
        edges,
        folders,
        issues,
    }
}

/// The `basalt-en-v1` stopword list named in §10.5.
pub const STOPWORDS: [&str; 33] = [
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "has", "have", "he",
    "in", "is", "it", "its", "of", "on", "or", "that", "the", "their", "then", "there", "they",
    "this", "to", "was", "were", "will", "with",
];

/// Build the search postings, honoring the leak rule in §8.8.
///
/// `search.json` MUST NOT contain text extracted from a node unless that node
/// grants `read` to `everyone`. This is the sharpest hazard in the protocol:
/// index passes run as `system` and therefore see everything, so the filter
/// has to be here rather than at serving time.
pub fn build_search_index<F>(
    nodes: &[IndexedNode],
    vault_id: &str,
    source_digest: &str,
    generated: &str,
    is_public: F,
) -> Json
where
    F: Fn(&IndexedNode) -> bool,
{
    let mut terms: BTreeMap<String, Vec<(String, i64)>> = BTreeMap::new();
    for n in nodes {
        let Some(id) = &n.id else { continue };
        let Some(text) = n.body.as_deref().or(n.text.as_deref()) else {
            continue;
        };
        if !is_public(n) {
            continue;
        }
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        for tok in tokenize(text) {
            *counts.entry(tok).or_insert(0) += 1;
        }
        for (t, tf) in counts {
            terms.entry(t).or_default().push((id.clone(), tf));
        }
    }

    with(
        envelope("search", vault_id, source_digest, generated),
        vec![
            (
                "terms",
                Json::Object(
                    terms
                        .into_iter()
                        .map(|(t, mut postings)| {
                            postings.sort_by(|a, b| compare_utf8(&a.0, &b.0));
                            (
                                t,
                                Json::arr(postings.into_iter().map(|(node, tf)| {
                                    Json::obj()
                                        .set("node", Json::str(&node))
                                        .set("tf", Json::Int(tf))
                                        .build()
                                })),
                            )
                        })
                        .collect(),
                ),
            ),
            ("stopwords", Json::str("basalt-en-v1")),
            ("stemmer", Json::str("none")),
        ],
    )
}

/// Tokenization per §10.5: Unicode word characters, lowercased, NFC, minus the
/// named stopword list. Declared and reproducible, because a posting list is
/// meaningless without knowing what produced it.
pub fn tokenize(text: &str) -> Vec<String> {
    let lower = nfc(text).to_lowercase();
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in lower.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
        } else if !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out.retain(|t| t.chars().count() >= 2 && !STOPWORDS.contains(&t.as_str()));
    out
}
