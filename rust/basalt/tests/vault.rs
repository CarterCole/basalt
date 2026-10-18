//! Behavior the fixture corpus does not cover: transport semantics (§1),
//! canonical-serialization rules (§13), identity repair (§4.3), the index leak
//! rule (§8.8) and the redaction rule (§9.5).
//!
//! Everything here is still anchored to a clause of the spec — these are not
//! this implementation's own opinions, they are the parts of the protocol the
//! corpus leaves to prose.

mod support;

use basalt::acl::Decision;
use basalt::canonical::{parse_json, Json};
use basalt::keys::{validate_key, KeyErrorCode};
use basalt::transport::{
    Capability, ListOpts, MemoryTransport, PutMeta, Transport, TransportError,
};
use basalt::vault::Vault;
use std::collections::BTreeMap;

// -------------------------------------------------------------- §1 transport

fn store() -> MemoryTransport {
    MemoryTransport::new()
}

#[test]
fn five_operations() {
    let t = store();
    assert_eq!(t.get("content/a.md").unwrap(), None, "get is NOT_FOUND");
    assert_eq!(t.stat("content/a.md").unwrap(), None, "stat is NOT_FOUND");

    let stat = t
        .put("content/a.md", b"hello", &PutMeta::default())
        .unwrap();
    assert_eq!(stat.size, 5);
    assert_eq!(t.get("content/a.md").unwrap().unwrap(), b"hello");

    let listing = t.list("content/", &ListOpts::default()).unwrap();
    assert_eq!(listing.keys, vec!["content/a.md"]);
}

/// §1.2: `delete` returns no information about whether the key existed, and is
/// idempotent. The signature is the enforcement — there is no boolean to
/// branch on, which is the point: a filesystem *can* answer cheaply, and an
/// implementation built only against one would expose a value that silently
/// becomes wrong on a bucket.
#[test]
fn delete_tells_you_nothing() {
    let t = store();
    t.put("content/a.md", b"x", &PutMeta::default()).unwrap();

    // The return type is the enforcement: `Result<()>` has nothing to branch
    // on, so a caller cannot learn whether the key was there.
    let _: () = t.delete("content/a.md").unwrap();
    let _: () = t.delete("content/a.md").unwrap();
    assert_eq!(t.get("content/a.md").unwrap(), None);
    // And a key that never existed deletes just as successfully.
    assert!(t.delete("content/never-there.md").is_ok());
}

/// §1.1: a key that violates the rules is rejected *on write*, by the
/// transport, before it can reach the store.
#[test]
fn put_rejects_invalid_keys() {
    let t = store();
    for bad in [
        "",
        "/content/a.md",
        "content/a/",
        "content//a.md",
        "content/../a.md",
    ] {
        match t.put(bad, b"x", &PutMeta::default()) {
            Err(TransportError::Key(_)) => {}
            other => panic!("{bad:?} should have been rejected, got {other:?}"),
        }
    }
}

#[test]
fn list_with_delimiter_yields_prefixes() {
    let t = store();
    for k in [
        "content/Notes/a.md",
        "content/Notes/Sub/b.md",
        "content/top.md",
    ] {
        t.put(k, b"x", &PutMeta::default()).unwrap();
    }
    let l = t
        .list(
            "content/",
            &ListOpts {
                delimiter: Some('/'),
                cursor: None,
            },
        )
        .unwrap();
    assert_eq!(l.keys, vec!["content/top.md"]);
    assert_eq!(l.prefixes, vec!["content/Notes/"]);
}

/// §11.3: a failed condition surfaces as a conflict rather than being retried
/// blindly. Last-write-wins on a knowledge vault silently destroys work.
#[test]
fn conditional_put_surfaces_conflicts() {
    let t = store();
    assert!(t.has(Capability::ConditionalPut));
    let stat = t.put("content/a.md", b"v1", &PutMeta::default()).unwrap();

    // if-none-match on an existing key must fail.
    let create_only = PutMeta {
        if_match: Some(None),
        ..Default::default()
    };
    assert!(matches!(
        t.put("content/a.md", b"v2", &create_only),
        Err(TransportError::PreconditionFailed(_))
    ));

    // if-match with the etag we read must succeed; with a stale one, fail.
    let ok = PutMeta {
        if_match: Some(stat.etag.clone()),
        ..Default::default()
    };
    assert!(t.put("content/a.md", b"v2", &ok).is_ok());
    assert!(matches!(
        t.put("content/a.md", b"v3", &ok),
        Err(TransportError::PreconditionFailed(_))
    ));
}

// ---------------------------------------------------------- §13 canonical

/// §13.1: non-ASCII emitted literally, never `\u`-escaped. Escape only what
/// JSON requires plus U+2028 and U+2029 — legal JSON unescaped, but they break
/// the moment the bytes are embedded in a `<script>` tag.
#[test]
fn canonical_escaping() {
    let v = Json::obj()
        .set("plain", Json::str("Café — 日本語 🪨"))
        .set("ctl", Json::str("a\u{1}b"))
        .set("sep", Json::str("x\u{2028}y\u{2029}z"))
        .set("quote", Json::str("a\"b\\c\nd\te"))
        .build();
    let s = v.to_canonical_string();
    assert!(
        s.contains("Café — 日本語 🪨"),
        "non-ASCII must be literal: {s}"
    );
    assert!(s.contains("a\\u0001b"));
    assert!(s.contains("x\\u2028y\\u2029z"));
    assert!(s.contains("a\\\"b\\\\c\\nd\\te"));
    assert!(
        s.ends_with("}\n") && !s.ends_with("}\n\n"),
        "exactly one trailing newline"
    );
}

/// §13.1: empty arrays and objects as `[]` and `{}`; two-space indent; one key
/// or element per line.
#[test]
fn canonical_shape() {
    let v = Json::obj()
        .set("arr", Json::Array(vec![]))
        .set("obj", Json::Object(BTreeMap::new()))
        .set("nested", Json::arr([Json::Int(1), Json::Int(2)]))
        .build();
    assert_eq!(
        v.to_canonical_string(),
        "{\n  \"arr\": [],\n  \"nested\": [\n    1,\n    2\n  ],\n  \"obj\": {}\n}\n"
    );
}

/// §13.3: ordering is by UTF-8 byte sequence, not by UTF-16 code unit.
///
/// This is the one place where a JavaScript implementation that reaches for
/// `<` or a naive `sort()` silently diverges: an astral character sorts *below*
/// U+E000–U+FFFF in UTF-16 (because its surrogate pair starts at U+D800) and
/// *above* them in UTF-8. Rust's `str` ordering is already UTF-8 bytewise, so
/// the test is here to pin the property rather than to catch this crate.
#[test]
fn ordering_is_utf8_bytewise() {
    let astral = "\u{1F5FF}"; // 🗿, UTF-8 f0 9f 97 bf
    let bmp = "\u{FFFD}"; // UTF-8 ef bf bd
    assert!(
        basalt::order::compare_utf8(bmp, astral).is_lt(),
        "U+FFFD sorts below U+1F5FF in UTF-8"
    );
    // And the key order a serialized object comes out in follows that.
    let v = Json::obj()
        .set(astral, Json::Int(1))
        .set(bmp, Json::Int(2))
        .build();
    let s = v.to_canonical_string();
    assert!(
        s.find(bmp).unwrap() < s.find(astral).unwrap(),
        "object keys sort by UTF-8 bytes: {s}"
    );
}

/// §13.1 bans non-integer numbers from index objects outright, which sidesteps
/// every float-formatting disagreement between languages. A float in a *stored*
/// index is therefore a loud failure, not a silent rounding.
#[test]
fn canonical_rejects_floats_on_read() {
    assert!(parse_json("{\"a\": 1}").is_ok());
    let err = parse_json("{\"a\": 1.5}").unwrap_err();
    assert!(err.contains("non-integer"), "{err}");
}

#[test]
fn canonical_round_trips() {
    let text = std::fs::read_to_string(
        support::conformance_dir().join("vaults/minimal/expected/links.json"),
    )
    .unwrap();
    let parsed = parse_json(&text).unwrap();
    assert_eq!(
        parsed.to_canonical_string(),
        text,
        "canonical JSON is a fixed point"
    );
}

// ------------------------------------------------------------- §1.1 keys

#[test]
fn oversized_key_rejected() {
    let long = format!("content/{}.md", "a".repeat(1024));
    assert_eq!(validate_key(&long).unwrap_err().code, KeyErrorCode::TooLong);
}

// -------------------------------------------------- a vault built in memory

struct Builder {
    t: MemoryTransport,
}

impl Builder {
    fn new() -> Self {
        let t = MemoryTransport::new();
        t.seed(
            "basalt.yaml",
            "basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n  title: Test\n\
             publish:\n  audience: public\nsecurity:\n  bypass_traverse: true\n"
                .as_bytes()
                .to_vec(),
        );
        Self { t }
    }
    fn file(self, key: &str, body: &str) -> Self {
        self.t.seed(key, body.as_bytes().to_vec());
        self
    }
    fn open(self) -> Vault {
        let mut v = Vault::open(Box::new(self.t)).expect("vault opens");
        v.reindex(false).expect("reindex");
        v
    }
}

/// §5.2: frontmatter that fails to parse MUST NOT fail the whole index pass.
/// One malformed file must never cost a vault its index.
#[test]
fn malformed_frontmatter_does_not_fail_the_pass() {
    let v = Builder::new()
        .file(
            "content/Bad.md",
            "---\ntitle: \"unterminated\nbasalt: {id: [broken\n---\n# Body Survives\n",
        )
        .file(
            "content/Good.md",
            "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# Good\n",
        )
        .open();

    let ix = v.indexes.as_ref().unwrap();
    assert_eq!(ix.node_data.len(), 2, "both files indexed");
    let bad = ix.node("Bad.md").unwrap();
    assert_eq!(
        bad.title.as_deref(),
        Some("Body Survives"),
        "body indexed anyway"
    );
    assert_eq!(bad.id, None, "no id salvaged from unparseable frontmatter");
    assert!(
        ix.issues
            .iter()
            .any(|i| i.code == "FRONTMATTER_PARSE" && i.path.as_deref() == Some("Bad.md")),
        "the parse failure is reported, not thrown"
    );
}

/// §4.3: two objects carrying the same id — the usual cause being a file
/// copied with its frontmatter intact. The object whose path sorts first keeps
/// the id; every other claimant is unbound and the collision is reported.
#[test]
fn duplicate_ids_resolve_deterministically() {
    let fm = "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# Twin\n";
    let v = Builder::new()
        .file("content/Beta.md", fm)
        .file("content/Alpha.md", fm)
        .open();

    let ix = v.indexes.as_ref().unwrap();
    assert_eq!(
        ix.node("Alpha.md").unwrap().id.as_deref(),
        Some("01jbq100000000000000000001"),
        "the bytewise-first path keeps the id"
    );
    assert_eq!(ix.node("Beta.md").unwrap().id, None, "the loser is unbound");
    assert!(ix.issues.iter().any(|i| i.code == "DUPLICATE_ID"));
    assert!(ix
        .issues
        .iter()
        .any(|i| i.code == "UNBOUND_NODE" && i.path.as_deref() == Some("Beta.md")));
}

/// §2.2: colliding keys are an integrity *error* and MUST NOT be resolved
/// silently; folder-case divergence is a *warning* and MUST NOT be repaired at
/// all, since picking a winner would move a file the author did not ask to
/// move.
#[test]
fn collisions_and_divergence_are_reported_not_fixed() {
    let v = Builder::new()
        .file("content/Notes/Hexes.md", "# A\n")
        .file("content/Notes/hexes.md", "# B\n")
        .file("content/notes/other.md", "# C\n")
        .open();

    let ix = v.indexes.as_ref().unwrap();
    let collision = ix
        .issues
        .iter()
        .find(|i| i.code == "KEY_COLLISION")
        .unwrap();
    assert_eq!(collision.severity, basalt::frontmatter::Severity::Error);
    let divergence = ix
        .issues
        .iter()
        .find(|i| i.code == "FOLDER_CASE_DIVERGENCE")
        .unwrap();
    assert_eq!(divergence.severity, basalt::frontmatter::Severity::Warning);
    // All three objects survive: nothing was renamed or dropped.
    assert_eq!(ix.node_data.len(), 3);
}

/// §2.1: folders are virtual, implied by the paths beneath them. Deleting the
/// last object under a folder makes the folder cease to exist, and an
/// implementation MUST NOT write empty directory markers.
#[test]
fn folders_are_virtual() {
    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n".to_vec(),
    );
    t.seed("content/Notes/Only.md", b"# x\n".to_vec());
    let mut v = Vault::open(Box::new(t)).unwrap();
    v.reindex(false).unwrap();
    assert_eq!(
        basalt::keys::implied_folders(["Notes/Only.md"]),
        vec!["Notes/"]
    );

    v.transport.delete("content/Notes/Only.md").unwrap();
    v.reindex(false).unwrap();
    assert!(
        v.indexes.as_ref().unwrap().node_data.is_empty(),
        "the folder went with its last object"
    );
    let keys = v.transport.list_all("").unwrap();
    assert!(
        !keys.iter().any(|k| k.ends_with('/')),
        "no directory markers were written: {keys:?}"
    );
}

/// §8.8: `search.json` MUST NOT contain text extracted from a node unless that
/// node grants `read` to `everyone`. The index pass runs as `system` and
/// therefore sees everything, so this is the one filter that has to happen at
/// build time rather than at serving time.
#[test]
fn search_index_excludes_private_text() {
    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\npublish:\n  audience: public\n\
          security:\n  bypass_traverse: true\n"
            .to_vec(),
    );
    t.seed(
        "content/Public.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000001\n---\nhexagonal columns everywhere\n"
            .to_vec(),
    );
    t.seed(
        "content/Secret.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000002\n---\nacquisition terms draft\n".to_vec(),
    );
    t.seed(
        "meta/acl/acl.yaml",
        b"folder:\n  dacl:\n    - {type: allow, subject: everyone, rights: [read, publish, list, traverse], flags: [oi, ci]}\n"
            .to_vec(),
    );
    t.seed(
        "principals/users.yaml",
        b"users:\n  - {id: u:carter, status: active}\n".to_vec(),
    );

    let mut v = Vault::open(Box::new(t)).unwrap();
    // Install the deny as an entry descriptor on the root folder's ACL.
    v.descriptors
        .folder_acls
        .get_mut("")
        .unwrap()
        .entries
        .insert(
            "Secret.md".to_string(),
            basalt::acl::Descriptor::from_yaml(
                &serde_yaml_ng::from_str(
                    "dacl:\n  - {type: deny, subject: everyone, rights: [read], flags: []}\n",
                )
                .unwrap(),
            ),
        );
    v.reindex(false).unwrap();

    let terms = v
        .indexes
        .as_ref()
        .unwrap()
        .search
        .get("terms")
        .unwrap()
        .as_object()
        .unwrap();
    assert!(terms.contains_key("hexagonal"), "public text is indexed");
    assert!(
        !terms.contains_key("acquisition"),
        "private text must never enter search.json: {:?}",
        terms.keys().collect::<Vec<_>>()
    );
}

/// §9.5: an edge whose target the principal cannot read MUST NOT be removed —
/// removing it would make the graph silently wrong, and a reader could not tell
/// a redacted link from a dangling one. The target is replaced instead, and the
/// title is omitted while `redact_titles` is on (the default).
#[test]
fn unreadable_edges_are_redacted_not_dropped() {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(basalt::transport::FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();

    // u:reader may read Start Here.md but not the private Columns.md.
    let r = v.links("u:reader", "Notes/Start Here.md");
    assert_eq!(r.status, 200);
    let to_columns = r
        .out
        .iter()
        .find(|l| l.raw == "Columns")
        .expect("the edge is still present");
    assert_eq!(to_columns.to.as_deref(), Some("redacted"));
    assert!(to_columns.redacted);
    assert_eq!(
        to_columns.target_title, None,
        "redact_titles is on by default, and a title leaks the thing it names"
    );
    assert_eq!(
        to_columns.target_path, None,
        "a path is often a sentence (§15)"
    );
    // The readable edge beside it is untouched.
    let to_hexes = r.out.iter().find(|l| l.raw == "Hexes").unwrap();
    assert!(!to_hexes.redacted);
    assert_eq!(to_hexes.target_path.as_deref(), Some("Notes/Hexes.md"));
}

/// §12.3: the 404/403 split is an information-leak boundary. A 403 on a path
/// the requester was not allowed to discover confirms that path exists.
#[test]
fn denial_distinguishes_404_from_403() {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(basalt::transport::FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();

    // u:reader has `list` on Notes/ and so may know Columns.md exists, but
    // cannot read it: 403.
    let r = v.read_node("u:reader", "Notes/Columns.md").unwrap();
    assert_eq!(r.status, 403);
    // The owner reads it.
    let r = v.read_node("u:carter", "Notes/Columns.md").unwrap();
    assert_eq!(r.status, 200);
    // A path that does not exist is 404 for everyone.
    assert_eq!(
        v.read_node("u:carter", "Notes/Nope.md").unwrap().status,
        404
    );
    // And anonymous, denied by the gated ceiling before the DACL is consulted,
    // cannot even list the folder — so it gets 404 rather than 403.
    let r = v.read_node("anonymous", "Notes/Columns.md").unwrap();
    assert_eq!(
        r.status, 404,
        "cannot-know-it-exists is indistinguishable from absent"
    );
}

/// §8.5: the whole traverse chain is required unless the vault opts out. The
/// minimal vault's root grants `traverse` with `ci` precisely so this does not
/// lock everyone out — the accidental lockout §8.5 warns about.
#[test]
fn traverse_chain_composes() {
    let dir = support::conformance_dir().join("vaults/minimal/vault");
    let mut v = Vault::open(Box::new(basalt::transport::FsTransport::new(&dir))).unwrap();
    v.reindex(false).unwrap();
    assert!(!v.manifest.bypass_traverse);

    let ok = v.can("u:reader", "Notes/Hexes.md", &["read"]);
    assert_eq!(ok.decisions["read"].decision, Decision::Allow);
    assert_eq!(ok.failed_at, None);

    // Remove the root traverse grant and every request in the vault dies,
    // whatever the leaf ACLs say.
    v.descriptors.folder_acls.get_mut("").unwrap().folder = None;
    let locked = v.can("u:reader", "Notes/Hexes.md", &["read"]);
    assert_eq!(locked.decisions["read"].decision, Decision::Deny);
    assert_eq!(
        locked.failed_at.as_deref(),
        Some(""),
        "failed at the vault root"
    );
}

/// §4.1: a ULID is 26 characters of lowercase Crockford base32, which omits
/// `i`, `l`, `o` and `u`.
#[test]
fn minted_ulids_are_well_formed() {
    for _ in 0..64 {
        let id = basalt::ulid();
        assert!(
            basalt::frontmatter::is_ulid(&id),
            "{id} is not a well-formed ULID"
        );
    }
    // The timestamp prefix is the only part §4.1 lets an implementation read,
    // and it must order two ids minted a second apart.
    let a = basalt::ulid_from(1_700_000_000_000, 0);
    let b = basalt::ulid_from(1_700_000_001_000, 0);
    assert!(a < b, "{a} should sort before {b}");
}

/// §4.3 and §13.4 together: minting an id into a note must preserve the
/// author's comments and key order, and an implementation that cannot do so
/// MUST refuse to rewrite rather than silently strip them.
#[test]
fn minting_preserves_authored_yaml() {
    let original = "---\n# a comment the author wrote\ntitle: Kept\ntags: [a, b]\nbasalt:\n  aliases: [Alt]\n---\n# Body\n";
    let out = basalt::frontmatter::with_id(original, "01jbq100000000000000000009").unwrap();
    assert!(out.contains("# a comment the author wrote"), "{out}");
    assert!(out.contains("title: Kept"));
    assert!(out.contains("aliases: [Alt]"));
    assert!(out.contains("id: 01jbq100000000000000000009"));
    let reparsed = basalt::frontmatter::parse_note(&out, "x.md");
    assert_eq!(reparsed.id.as_deref(), Some("01jbq100000000000000000009"));
    assert_eq!(reparsed.title.as_deref(), Some("Kept"));
    assert_eq!(reparsed.aliases, vec!["Alt".to_string()]);

    // A flow mapping cannot be edited without restyling it, so it is refused.
    let flow = "---\nbasalt: {aliases: [Alt]}\n---\n# Body\n";
    assert!(basalt::frontmatter::with_id(flow, "01jbq100000000000000000009").is_err());
}

/// §3.1: a reader MUST refuse a vault whose `basalt` major version it does not
/// implement, and MUST tolerate unknown keys within a version it does (§16).
#[test]
fn manifest_version_gate() {
    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 2\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n".to_vec(),
    );
    assert!(Vault::open(Box::new(t)).is_err(), "a v2 vault is refused");

    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n  unknown_key: fine\n\
          future_section:\n  whatever: true\n"
            .to_vec(),
    );
    assert!(
        Vault::open(Box::new(t)).is_ok(),
        "unknown keys within v1 are tolerated"
    );
}

/// §9.4: in data objects, string *values* are scanned and keys never are —
/// scanning keys would turn a dataset's column names into edges.
#[test]
fn data_object_links() {
    let v = Builder::new()
        .file(
            "content/Target.md",
            "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# T\n",
        )
        .file(
            "content/data.yaml",
            "records:\n  - name: Target\n    note: \"[[Target]]\"\n    url: https://example.com/x\n",
        )
        .open();
    let ix = v.indexes.as_ref().unwrap();
    let data_id = ix.node("data.yaml").unwrap().id.clone();
    assert!(
        data_id.is_none(),
        "a data object with no sidecar id is unbound, so it emits no edges"
    );

    // With an id, its values resolve.
    let v = Builder::new()
        .file(
            "content/Target.md",
            "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# T\n",
        )
        .file(
            "content/data.yaml",
            "records:\n  - name: Target\n    note: \"[[Target]]\"\n    url: https://example.com/x\n",
        )
        .file(
            "meta/folders/entries.yaml",
            "entries:\n  data.yaml:\n    id: 01jbq100000000000000000002\n",
        )
        .open();
    let ix = v.indexes.as_ref().unwrap();
    let edges: Vec<_> = ix
        .edges
        .iter()
        .filter(|e| e.from == "01jbq100000000000000000002")
        .collect();
    assert_eq!(
        edges.len(),
        2,
        "the wikilink value and the url value: {edges:?}"
    );
    assert!(edges
        .iter()
        .any(|e| e.raw == "Target" && e.to.as_deref() == Some("01jbq100000000000000000001")));
    assert!(edges
        .iter()
        .any(|e| e.raw == "https://example.com/x" && e.to.is_none()));
    // `name: Target` is a plain value under a non-link key, so it is not an edge.
    assert_eq!(
        edges.iter().filter(|e| e.raw == "Target").count(),
        1,
        "only the wikilink value, not the bare `name` value"
    );
}

/// §6.1: a sidecar entry whose object no longer exists is reported, so a
/// write-capable pass can prune it.
#[test]
fn orphan_sidecar_entries_are_reported() {
    let v = Builder::new()
        .file(
            "content/Keep.md",
            "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# K\n",
        )
        .file(
            "meta/folders/entries.yaml",
            "entries:\n  gone.png:\n    id: 01jbq100000000000000000002\n",
        )
        .open();
    assert!(v
        .indexes
        .as_ref()
        .unwrap()
        .issues
        .iter()
        .any(|i| i.code == "ORPHAN_SIDECAR" && i.path.as_deref() == Some("gone.png")));
}

/// §10.7: a write pass MUST refuse to replace a non-empty stored index with an
/// empty one unless explicitly forced.
///
/// Indexes are derived and rebuildable, so this cannot lose content — but a
/// vault whose indexes have gone empty appears empty to every reader until
/// someone notices, and the usual cause is a transport pointed at the wrong
/// place rather than an emptied vault.
#[test]
fn empty_index_write_is_refused() {
    use basalt::vault::{IndexWrite, VaultError};

    let t = MemoryTransport::new();
    t.seed(
        "basalt.yaml",
        b"basalt: 1\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n".to_vec(),
    );
    t.seed(
        "content/Notes/A.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n".to_vec(),
    );
    t.seed(
        "content/Notes/B.md",
        b"---\nbasalt:\n  id: 01jbq100000000000000000002\n---\n# B\n".to_vec(),
    );

    let mut v = Vault::open(Box::new(t)).unwrap();
    v.reindex_opts(IndexWrite::persist()).unwrap();
    assert_eq!(v.stored_node_count().unwrap(), 2);

    // Now the content disappears — the shape of a transport pointed at the
    // wrong prefix, which is what §10.7 is defending against.
    v.transport.delete("content/Notes/A.md").unwrap();
    v.transport.delete("content/Notes/B.md").unwrap();

    match v.reindex_opts(IndexWrite::persist()) {
        Err(VaultError::EmptyIndexRefused { found, previously }) => {
            assert_eq!((found, previously), (0, 2));
            // §10.7 SHOULDs reporting both counts.
            let msg = VaultError::EmptyIndexRefused { found, previously }.to_string();
            assert!(msg.contains('0') && msg.contains('2'), "{msg}");
        }
        other => panic!("§10.7 guard did not fire: {other:?}"),
    }
    assert_eq!(
        v.stored_node_count().unwrap(),
        2,
        "the stored index is untouched by the refusal"
    );

    // Forced, it writes — because sometimes the vault really is empty.
    v.reindex_opts(IndexWrite::forced()).unwrap();
    assert_eq!(v.stored_node_count().unwrap(), 0);

    // And an empty build over an already-empty stored index needs no force:
    // there is nothing to destroy.
    v.reindex_opts(IndexWrite::persist()).unwrap();
}

/// §1.2, one level down from the obvious case.
///
/// `content/Notes/x.md` where `content/Notes` is a *file* gives ENOTDIR on a
/// filesystem, while on an object store that key simply does not exist and the
/// delete succeeds. A transport that surfaced the error would disagree with
/// every bucket — the same divergence §1.2 was written to close, which is why
/// it is tested rather than assumed.
#[test]
fn delete_succeeds_when_a_parent_is_a_file() {
    let dir = tempdir();
    let t = basalt::transport::FsTransport::new(&dir);
    t.put(
        "content/Notes",
        b"this is a file, not a folder",
        &PutMeta::default(),
    )
    .unwrap();

    assert!(
        t.delete("content/Notes/x.md").is_ok(),
        "a key under a non-directory does not exist, so deleting it succeeds"
    );
    // And the same shape through `get` and `stat` — §1.2 points at `stat` as
    // the way to learn whether a key exists, so it had better answer
    // NOT_FOUND here rather than an OS error.
    assert_eq!(t.get("content/Notes/x.md").unwrap(), None);
    assert_eq!(t.stat("content/Notes/x.md").unwrap(), None);

    // The third shape: a real directory, which §2.1 says is never an object,
    // so no key names it.
    std::fs::create_dir_all(dir.join("content/Real")).unwrap();
    assert_eq!(t.get("content/Real").unwrap(), None);
    assert_eq!(t.stat("content/Real").unwrap(), None);
    assert!(t.delete("content/Real").is_ok());
    assert!(
        dir.join("content/Real").is_dir(),
        "and deleting a non-object left the directory alone"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// A scratch directory under the system temp dir, removed by the caller.
fn tempdir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "basalt-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}
