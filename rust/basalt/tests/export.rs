//! Static export, PROTOCOL §12.6.
//!
//! §8.8 is blunt that publishing a vault by copying `index/` to a public
//! bucket alongside public content is **not conforming**, because it leaks the
//! private half of the graph. §12.6 defines the safe operation, and these
//! tests are what distinguish the two.

mod support;

use basalt::transport::{FsTransport, MemoryTransport};
use basalt::vault::{ExportOpts, Vault};

fn source() -> Vault {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();
    v
}

/// The minimal vault is `audience: gated` and grants `publish` to nobody, so
/// an export of it is empty — which is the correct and slightly startling
/// answer. §8.1 exists precisely so that "readable by everyone with an
/// account" does not silently mean "on the public internet".
#[test]
fn export_of_a_gated_vault_publishes_nothing() {
    let mut v = source();
    let dest = Box::new(MemoryTransport::new());
    let (summary, exported) = v.export(dest, ExportOpts::default()).unwrap();

    assert!(
        summary.included.is_empty(),
        "nothing in the vault grants publish to anonymous: {:?}",
        summary.included
    );
    assert_eq!(summary.excluded.len(), 4);
    // And the export is still a valid, servable vault.
    assert_eq!(exported.manifest.audience, basalt::acl::Audience::Public);
    assert!(exported.indexes.as_ref().unwrap().node_data.is_empty());
}

/// With `publish` granted, the public subset travels and the private half does
/// not — content, index and all.
#[test]
fn export_carries_only_the_public_subset() {
    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n  title: Source\n\
          publish:\n  audience: gated\n  home: Public.md\n"
            .to_vec(),
    );
    t.seed(
        "content/Public.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000001\ntitle: Public\n---\n\
          # Public\n\nA link to [[Private]] and one to [[Public]].\n"
            .to_vec(),
    );
    t.seed(
        "content/Private.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000002\ntitle: Private\n---\n\
          # Private\n\nacquisition terms draft\n"
            .to_vec(),
    );
    t.seed(
        "principals/users.yaml",
        b"users:\n  - {id: u:carter, status: active}\n".to_vec(),
    );
    t.seed(
        "meta/acl/acl.yaml",
        b"folder:\n  owner: u:carter\n  dacl:\n\
          \x20   - {type: allow, subject: everyone, rights: [read, list, traverse, publish], flags: [oi, ci]}\n\
          entries:\n  Private.md:\n    dacl:\n\
          \x20     - {type: deny, subject: everyone, rights: [read, publish], flags: []}\n\
          \x20     - {type: allow, subject: u:carter, rights: [full_control], flags: []}\n"
            .to_vec(),
    );

    let mut v = Vault::open(Box::new(t)).unwrap();
    v.reindex(false).unwrap();

    let dest = Box::new(MemoryTransport::new());
    let (summary, exported) = v.export(dest, ExportOpts::default()).unwrap();

    assert_eq!(summary.included, vec!["Public.md".to_string()]);
    assert_eq!(summary.excluded, vec!["Private.md".to_string()]);

    // The private note's bytes are simply not there.
    let keys = exported.transport.list_all("").unwrap();
    assert!(
        !keys.iter().any(|k| k.contains("Private")),
        "the private note must not travel: {keys:?}"
    );
    assert!(keys.contains(&"content/Public.md".to_string()));

    // §8.8: the export's indexes were regenerated, not copied — so the edge
    // list has no trace of the private node's id.
    let links = exported
        .indexes
        .as_ref()
        .unwrap()
        .links
        .to_canonical_string();
    assert!(
        !links.contains("01jbq100000000000000000002"),
        "the private node's id leaked into the export's link graph:\n{links}"
    );
    // The edge itself survives as unresolved, because within the export the
    // target genuinely is not there.
    assert!(links.contains("\"raw\": \"Private\""), "{links}");

    // §12.6: `search.json` is rebuilt over public text only.
    let terms = exported
        .indexes
        .as_ref()
        .unwrap()
        .search
        .get("terms")
        .unwrap()
        .as_object()
        .unwrap();
    assert!(
        !terms.contains_key("acquisition"),
        "private text in the export's search index: {:?}",
        terms.keys().collect::<Vec<_>>()
    );

    // No ACLs, principals or indexes were copied from the source.
    assert!(
        !keys.iter().any(|k| k.starts_with("principals/")),
        "principals must not travel: {keys:?}"
    );
    assert_eq!(
        exported.descriptors.folder_acls.len(),
        1,
        "one root descriptor, written fresh"
    );

    // And §12.6's closing claim holds: the export is itself a complete vault,
    // whose stored indexes reproduce from its own content.
    let stored = exported.load_stored_indexes().unwrap();
    assert_eq!(
        stored
            .get("nodes")
            .and_then(|n| n.get("source_digest"))
            .and_then(|d| d.as_str()),
        Some(summary.source_digest.as_str()),
        "the export carries its own digest"
    );
    let fresh = exported.indexes.as_ref().unwrap();
    for name in ["nodes", "links", "backlinks", "tags", "digest"] {
        assert_eq!(
            stored.get(name).unwrap().comparable(),
            fresh.by_name(name).unwrap().comparable(),
            "index/{name}.json in the export reproduces from its own content"
        );
    }
}

/// §5.2: `basalt.publish: false` excludes a node from publication whatever its
/// ACL says, so an export must honor it independently of §8.4.
#[test]
fn export_honors_publish_false() {
    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\npublish:\n  audience: public\n"
            .to_vec(),
    );
    t.seed(
        "content/Draft.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000001\n  publish: false\n---\n# Draft\n"
            .to_vec(),
    );
    t.seed(
        "content/Live.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000002\n---\n# Live\n".to_vec(),
    );
    t.seed(
        "meta/acl/acl.yaml",
        b"folder:\n  dacl:\n\
          \x20   - {type: allow, subject: everyone, rights: [read, list, traverse, publish], flags: [oi, ci]}\n"
            .to_vec(),
    );

    let mut v = Vault::open(Box::new(t)).unwrap();
    v.reindex(false).unwrap();
    let (summary, _) = v
        .export(Box::new(MemoryTransport::new()), ExportOpts::default())
        .unwrap();
    assert_eq!(summary.included, vec!["Live.md".to_string()]);
    assert_eq!(summary.excluded, vec!["Draft.md".to_string()]);
}
