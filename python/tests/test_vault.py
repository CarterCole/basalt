"""Whole-vault behavior: identity, integrity, minting, ACLs over real content.

Covers the §4-§10 conditions the fixture corpus describes in prose but no
single case file exercises end to end.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from basalt.canonical import canonical_json
from basalt.frontmatter import is_ulid, with_id
from basalt.indexer import EPOCH
from basalt.transport.local import LocalTransport
from basalt.transport.memory import MemoryTransport
from basalt.vault import EmptyIndexRefused, Vault, ulid

MANIFEST = """basalt: 1
vault:
  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P
  title: Test Vault
publish:
  audience: public
security:
  bypass_traverse: true
"""


def build(objects: dict[str, str], *, manifest: str = MANIFEST) -> Vault:
    """A vault in memory, from a map of key to text."""
    transport = MemoryTransport({"basalt.yaml": manifest.encode("utf-8")})
    for key, text in objects.items():
        transport.objects[key] = text.encode("utf-8")
    vault = Vault(transport)
    vault.load()
    return vault


def codes(indexes: dict[str, Any]) -> list[str]:
    return [e["code"] for e in indexes["integrity"]["entries"]]


# --------------------------------------------------------------- identity


def test_unbound_object_is_reported_with_a_null_id() -> None:
    """§4.3 — a read-only pass MUST NOT invent an ephemeral id.

    A transient id would attach ACLs and links to something that ceases to
    exist.
    """
    indexes = build({"content/Notes/New.md": "# New\n"}).reindex(generated=EPOCH)
    entry = indexes["nodes"]["entries"][0]
    assert entry["id"] is None
    assert "UNBOUND_NODE" in codes(indexes)


def test_duplicate_ids_resolve_deterministically() -> None:
    """§4.3 — the bytewise-first path keeps the id; the rest are re-minted.

    Resolution is deterministic so that two implementations repairing the same
    damaged vault reach the same result.
    """
    body = "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# Copy\n"
    indexes = build(
        {"content/Notes/B.md": body, "content/Notes/A.md": body}
    ).reindex(generated=EPOCH)
    by_path = {e["path"]: e for e in indexes["nodes"]["entries"]}
    assert by_path["Notes/A.md"]["id"] == "01jbq100000000000000000001"
    assert by_path["Notes/B.md"]["id"] is None
    assert "DUPLICATE_ID" in codes(indexes)


def test_invalid_id_is_an_error_and_the_node_is_unbound() -> None:
    indexes = build(
        {"content/a.md": "---\nbasalt:\n  id: not-a-ulid\n---\n# A\n"}
    ).reindex(generated=EPOCH)
    assert indexes["nodes"]["entries"][0]["errors"] == ["INVALID_ID"]
    assert indexes["nodes"]["entries"][0]["id"] is None


def test_asset_id_comes_from_the_entry_sidecar() -> None:
    """§4.2, §6.1 — an object that cannot carry frontmatter gets a sidecar id."""
    indexes = build(
        {
            "content/Assets/diagram.png": "binary",
            "meta/folders/Assets/entries.yaml": (
                "entries:\n"
                "  diagram.png:\n"
                "    id: 01jbq100000000000000000004\n"
                "    title: Column jointing\n"
            ),
        }
    ).reindex(generated=EPOCH)
    entry = indexes["nodes"]["entries"][0]
    assert entry["id"] == "01jbq100000000000000000004"
    assert entry["title"] == "Column jointing"
    assert entry["kind"] == "asset"


def test_orphan_sidecar_entry_is_reported() -> None:
    """§6.1 — an entry whose object is gone is pruned on the next write pass."""
    indexes = build(
        {
            "content/Assets/a.png": "x",
            "meta/folders/Assets/entries.yaml": (
                "entries:\n  gone.png:\n    id: 01jbq100000000000000000009\n"
            ),
        }
    ).reindex(generated=EPOCH)
    assert "ORPHAN_SIDECAR" in codes(indexes)


def test_ulid_is_well_formed_and_sorts_by_time() -> None:
    """§4.1 — 26 characters of lowercase Crockford base32."""
    first = ulid(1_700_000_000_000)
    second = ulid(1_700_000_001_000)
    assert len(first) == 26 and is_ulid(first)
    assert first[:10] < second[:10]
    assert "i" not in first and "l" not in first and "o" not in first
    assert "u" not in first


# -------------------------------------------------------------- integrity


def test_key_collision_is_an_error_not_a_silent_resolution() -> None:
    """§2.2 — a vault must survive a case-insensitive store without data loss."""
    indexes = build(
        {"content/Notes/Hexes.md": "# A\n", "content/Notes/hexes.md": "# B\n"}
    ).reindex(generated=EPOCH)
    entries = indexes["integrity"]["entries"]
    collision = next(e for e in entries if e["code"] == "KEY_COLLISION")
    assert collision["severity"] == "error"
    # Both files are still indexed: the condition is reported, not resolved.
    assert len(indexes["nodes"]["entries"]) == 2


def test_folder_case_divergence_is_a_warning_and_nothing_is_rewritten() -> None:
    """§2.2 — picking a winner would move a file the author did not ask to move."""
    vault = build({"content/Notes/a.md": "# A\n", "content/notes/b.md": "# B\n"})
    before = dict(vault.t.objects)  # type: ignore[attr-defined]
    indexes = vault.reindex(generated=EPOCH)
    entry = next(
        e for e in indexes["integrity"]["entries"] if e["code"] == "FOLDER_CASE_DIVERGENCE"
    )
    assert entry["severity"] == "warning"
    assert vault.t.objects == before  # type: ignore[attr-defined]


def test_malformed_frontmatter_never_fails_the_index_pass() -> None:
    """§5.2 — one malformed file must never cost a vault its index."""
    indexes = build(
        {
            "content/Bad.md": '---\ntitle: "unterminated\nbasalt: {id: [broken\n---\n# Body Survives\n',
            "content/Good.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# Good\n",
        }
    ).reindex(generated=EPOCH)
    by_path = {e["path"]: e for e in indexes["nodes"]["entries"]}
    assert by_path["Bad.md"]["title"] == "Body Survives"
    assert by_path["Bad.md"]["errors"] == ["FRONTMATTER_PARSE"]
    assert by_path["Good.md"]["id"] == "01jbq100000000000000000001"
    assert len(indexes["nodes"]["entries"]) == 2


def test_unresolvable_ace_subject_is_reported(tmp_path: Path) -> None:
    """§10.7 — index passes collect unresolvable ACE subjects."""
    indexes = build(
        {
            "content/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n",
            "meta/acl/acl.yaml": (
                "folder:\n  dacl:\n"
                "    - {type: allow, subject: 'g:typo', rights: [read]}\n"
            ),
        }
    ).reindex(generated=EPOCH)
    entry = next(
        e for e in indexes["integrity"]["entries"] if e["code"] == "UNRESOLVED_SUBJECT"
    )
    assert entry["severity"] == "error"
    assert entry["detail"] == "g:typo"


def test_undefined_role_in_an_ace_is_reported() -> None:
    """§7.4 — an ACE naming an undefined role is an integrity error."""
    indexes = build(
        {
            "content/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n",
            "meta/acl/acl.yaml": (
                "folder:\n  dacl:\n"
                "    - {type: allow, subject: everyone, rights: [raed]}\n"
            ),
        }
    ).reindex(generated=EPOCH)
    assert "UNRESOLVED_RIGHT" in codes(indexes)


# ------------------------------------------------------------------- links


def test_links_in_data_objects_scan_values_never_keys() -> None:
    """§9.4 — scanning keys would turn a dataset's column names into edges.

    The data object's id comes from the folder sidecar: §4.2 puts an id in
    frontmatter only for markdown, so a ``.json`` or ``.yaml`` content object
    is addressed through ``entries.yaml`` like any other non-note, and without
    an id it is unbound and contributes no edges (§4.3).
    """
    indexes = build(
        {
            "content/Notes/Hexes.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000002\n---\n# Hexagons\n"
            ),
            "content/data/refs.json": json.dumps(
                {
                    "Hexes": "not a link",
                    "see": "[[Hexes]]",
                    "url": "https://example.com/x",
                    "ref": "Notes/Hexes.md",
                }
            ),
            "meta/folders/data/entries.yaml": (
                "entries:\n  refs.json:\n    id: 01jbq100000000000000000003\n"
            ),
        }
    ).reindex(generated=EPOCH)
    edges = indexes["links"]["entries"]
    kinds = {(e["kind"], e["raw"]) for e in edges}
    assert ("wiki", "Hexes") in kinds
    assert ("external", "https://example.com/x") in kinds
    assert ("md", "Notes/Hexes.md") in kinds
    # The key "Hexes" is not an edge, and neither is its plain-string value.
    assert ("wiki", "not a link") not in kinds
    assert len([e for e in edges if e["raw"] == "Hexes"]) == 1


def test_ambiguous_link_is_flagged_with_every_candidate() -> None:
    """§9.2 — ambiguity is reported, never hidden, with a deterministic pick."""
    note = "---\nbasalt:\n  id: {id}\n---\n# N\n"
    indexes = build(
        {
            "content/Alpha/Shared.md": note.format(id="01jbq100000000000000000007"),
            "content/Beta/Shared.md": note.format(id="01jbq100000000000000000008"),
            "content/Zeta/Source.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000009\n---\n"
                "# S\n\nSee [[Shared]].\n"
            ),
        }
    ).reindex(generated=EPOCH)
    edge = next(e for e in indexes["links"]["entries"] if e["raw"] == "Shared")
    assert edge["ambiguous"] is True
    assert edge["to"] == "01jbq100000000000000000007"  # "Alpha/..." < "Beta/..."
    assert edge["candidates"] == [
        "01jbq100000000000000000007",
        "01jbq100000000000000000008",
    ]
    assert "AMBIGUOUS_LINK" in codes(indexes)


def test_anchor_failure_does_not_make_the_edge_unresolved() -> None:
    """§9.3 — the node resolved; only the fragment did not."""
    indexes = build(
        {
            "content/Target.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000002\n---\n# Target\n"
            ),
            "content/Source.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n"
                "# S\n\n[[Target#no-such-heading]]\n"
            ),
        }
    ).reindex(generated=EPOCH)
    edge = next(e for e in indexes["links"]["entries"] if e["raw"] == "Target")
    assert edge["to"] == "01jbq100000000000000000002"
    assert edge["anchor_resolved"] is False


def test_tag_closure_reaches_the_tags_index() -> None:
    """§9.6, §10.4 — querying ``#nested`` finds nodes tagged only ``#nested/tag``."""
    indexes = build(
        {
            "content/a.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000001\ntags: [top]\n---\n"
                "# A\n\nTagged #deep/nested/tag here.\n"
            )
        }
    ).reindex(generated=EPOCH)
    assert set(indexes["tags"]["entries"]) == {
        "top",
        "deep",
        "deep/nested",
        "deep/nested/tag",
    }


# -------------------------------------------------------------- security


PROTECTED_VAULT = {
    "content/Public/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n",
    "content/Secret/b.md": "---\nbasalt:\n  id: 01jbq100000000000000000002\n---\n# B\n",
    "principals/users.yaml": "users:\n  - {id: 'u:carter', status: active}\n  - {id: 'u:reader', status: active}\n",
    "meta/acl/acl.yaml": (
        "folder:\n  dacl:\n"
        "    - {type: allow, subject: everyone, rights: [read, list, traverse], "
        "flags: [oi, ci]}\n"
    ),
    "meta/acl/Secret/acl.yaml": (
        "folder:\n  protected: true\n  dacl:\n"
        "    - {type: allow, subject: 'u:carter', rights: [read, list, traverse], "
        "flags: [oi, ci]}\n"
    ),
}


def test_protected_folder_blocks_ancestor_grants() -> None:
    """§8.3 — evaluation at and below a protected folder sees no ancestor."""
    vault = build(PROTECTED_VAULT)
    vault.reindex(generated=EPOCH)
    assert vault.can("u:reader", "Public/a.md", ["read"]).allowed is True
    assert vault.can("u:reader", "Secret/b.md", ["read"]).allowed is False
    assert vault.can("u:carter", "Secret/b.md", ["read"]).allowed is True


def test_inline_frontmatter_acl_replaces_the_folder_entry() -> None:
    """§8.6 — the two are never merged; inline wins because it travels with content."""
    vault = build(
        {
            "content/Notes/a.md": (
                "---\n"
                "basalt:\n"
                "  id: 01jbq100000000000000000001\n"
                "  acl:\n"
                "    dacl:\n"
                "      - {type: deny, subject: 'u:reader', rights: [read], flags: []}\n"
                "---\n# A\n"
            ),
            "principals/users.yaml": "users:\n  - {id: 'u:reader', status: active}\n",
            "meta/acl/Notes/acl.yaml": (
                "entries:\n"
                "  a.md:\n"
                "    dacl:\n"
                "      - {type: allow, subject: 'u:reader', rights: [read], flags: []}\n"
            ),
        }
    )
    vault.reindex(generated=EPOCH)
    decision = vault.can("u:reader", "Notes/a.md", ["read"])
    assert decision.allowed is False, "the folder-file entry overrode the inline ACL"


def test_traverse_chain_is_required_unless_the_vault_opts_out() -> None:
    """§8.5 — the accidental lockout the spec warns about, and its escape hatch."""
    objects = {
        "content/Deep/Nest/a.md": (
            "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n"
        ),
        "principals/users.yaml": "users:\n  - {id: 'u:reader', status: active}\n",
        # `read` on the leaf, but no `traverse` anywhere.
        "meta/acl/Deep/Nest/acl.yaml": (
            "entries:\n  a.md:\n    dacl:\n"
            "      - {type: allow, subject: 'u:reader', rights: [read], flags: []}\n"
        ),
    }
    strict = build(
        objects,
        manifest=MANIFEST.replace("bypass_traverse: true", "bypass_traverse: false"),
    )
    strict.reindex(generated=EPOCH)
    denied = strict.can("u:reader", "Deep/Nest/a.md", ["read"])
    assert denied.allowed is False
    assert denied.failed_at == ""  # the root is where the chain first fails

    lenient = build(objects)  # bypass_traverse: true
    lenient.reindex(generated=EPOCH)
    assert lenient.can("u:reader", "Deep/Nest/a.md", ["read"]).allowed is True


def test_search_indexes_public_text_only() -> None:
    """§8.8 — the leak rule, from the other direction: a public node *is* indexed."""
    vault = build(
        {
            "content/Open.md": (
                "---\n"
                "basalt:\n"
                "  id: 01jbq100000000000000000001\n"
                "  acl:\n"
                "    dacl:\n"
                "      - {type: allow, subject: everyone, rights: [read, publish], "
                "flags: []}\n"
                "---\n# Open\n\nHexagonal cooling columns.\n"
            ),
            "content/Closed.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000002\n---\n"
                "# Closed\n\nAcquisition terms, draft.\n"
            ),
        }
    )
    indexes = vault.reindex(generated=EPOCH)
    terms = indexes["search"]["terms"]
    assert "hexagonal" in terms
    assert "acquisition" not in terms, "§8.8: private text reached search.json"
    assert all(
        p["node"] == "01jbq100000000000000000001"
        for postings in terms.values()
        for p in postings
    )


def test_anonymous_read_needs_publish_too() -> None:
    """§8.1 — "shared with all accounts" and "on the public internet" differ."""
    vault = build(
        {
            "content/ReadOnly.md": (
                "---\n"
                "basalt:\n"
                "  id: 01jbq100000000000000000001\n"
                "  acl:\n"
                "    dacl:\n"
                "      - {type: allow, subject: everyone, rights: [read], flags: []}\n"
                "---\n# R\n"
            )
        }
    )
    vault.reindex(generated=EPOCH)
    decision = vault.can("anonymous", "ReadOnly.md", ["read"])
    assert decision.allowed is False
    assert decision.decisions["read"]["by"] == "missing_publish"


# --------------------------------------------------------------- writing


def test_mint_writes_frontmatter_and_preserves_comments(tmp_path: Path) -> None:
    """§4.3 plus §13.4 — minting must not strip a human's comments."""
    root = tmp_path / "vault"
    (root / "content" / "Notes").mkdir(parents=True)
    (root / "basalt.yaml").write_text(MANIFEST, encoding="utf-8")
    note = (
        "---\n"
        "# the author's own note to themselves\n"
        'title: "Kept"\n'
        "tags: [a, b]\n"
        "---\n"
        "# Body\n"
    )
    (root / "content" / "Notes" / "A.md").write_text(note, encoding="utf-8")

    vault = Vault(LocalTransport(root))
    vault.load()
    minted = vault.mint_ids()
    assert len(minted) == 1 and minted[0]["where"] == "frontmatter"

    rewritten = (root / "content" / "Notes" / "A.md").read_text(encoding="utf-8")
    assert "# the author's own note to themselves" in rewritten
    assert 'title: "Kept"' in rewritten  # §13.4: existing quoting preserved
    assert "# Body" in rewritten
    assert is_ulid(vault.reindex(generated=EPOCH)["nodes"]["entries"][0]["id"])


def test_mint_writes_a_sidecar_for_an_asset(tmp_path: Path) -> None:
    root = tmp_path / "vault"
    (root / "content" / "Assets").mkdir(parents=True)
    (root / "basalt.yaml").write_text(MANIFEST, encoding="utf-8")
    (root / "content" / "Assets" / "d.png").write_bytes(b"png")

    vault = Vault(LocalTransport(root))
    vault.load()
    minted = vault.mint_ids()
    assert minted[0]["where"] == "sidecar"
    sidecar = (root / "meta" / "folders" / "Assets" / "entries.yaml").read_text()
    assert is_ulid(sidecar.split("id:")[1].strip())


def test_with_id_on_a_note_without_frontmatter() -> None:
    out = with_id("# Just a body\n", "01jbq100000000000000000001")
    assert out.startswith("---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n")
    assert out.endswith("# Just a body\n")


def test_refuses_to_replace_a_populated_index_with_an_empty_one() -> None:
    """A vault whose indexes went empty looks empty to every reader.

    The usual cause is a transport pointed at the wrong bucket or prefix
    (§3.1), not an emptied vault — and while this cannot lose content, since
    every index is derived (§0), it can make a live vault look dead.
    """
    vault = build(
        {"content/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n"}
    )
    vault.reindex(write=True)
    del vault.t.objects["content/a.md"]  # type: ignore[attr-defined]

    with pytest.raises(EmptyIndexRefused):
        vault.reindex(write=True)
    vault.reindex(write=True, force=True)  # explicit override is honored
    stored = json.loads(vault.t.objects["index/nodes.json"].decode())  # type: ignore[attr-defined]
    assert stored["entries"] == []


def test_written_indexes_are_canonical_bytes() -> None:
    vault = build(
        {"content/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n"}
    )
    indexes = vault.reindex(write=True, generated=EPOCH)
    stored = vault.t.objects["index/nodes.json"].decode("utf-8")  # type: ignore[attr-defined]
    assert stored == canonical_json(indexes["nodes"])
    assert stored.endswith("}\n")


# --------------------------------------------------------------- manifest


def test_refuses_a_spec_version_it_does_not_implement() -> None:
    """§3.1 — and §16: a reader must refuse a major it does not implement."""
    with pytest.raises(RuntimeError, match="unsupported spec version"):
        build({}, manifest="basalt: 2\nvault:\n  id: 01JBQ7X8Z4N3VYK9M2T5HRWC6P\n")


def test_refuses_a_directory_that_is_not_a_vault(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="not a Basalt vault"):
        Vault(LocalTransport(tmp_path)).load()


def test_tolerates_unknown_keys_within_a_version_it_implements() -> None:
    """§3.1, §2.3 — a v1 reader must operate on a v1.1 vault."""
    vault = build(
        {"content/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n"},
        manifest=MANIFEST + "future:\n  thing: 1\n",
    )
    assert len(vault.reindex(generated=EPOCH)["nodes"]["entries"]) == 1


def test_index_freshness_is_decided_by_digest_not_timestamps() -> None:
    """§10.6 — one `get`, never a timestamp comparison (§1 forbids relying on them)."""
    vault = build(
        {"content/a.md": "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n# A\n"}
    )
    vault.reindex(write=True)
    vault.load_indexes()
    assert vault.index_state().fresh is True

    vault.t.objects["content/a.md"] += b"\nchanged\n"  # type: ignore[attr-defined]
    state = vault.index_state()
    assert state.fresh is False
    assert state.label == "stale"


# ------------------------------------------------------- near-miss node ids


def test_a_short_ulid_says_why_it_was_rejected() -> None:
    """§4.1 — 26 characters. A 25-character id is the confusing failure.

    The object goes unbound (§4.3) and takes every inbound link with it, since
    §9.2 can only resolve to a node that has an id — so the report has to name
    the reason, not just the id.
    """
    indexes = build(
        {
            "content/Short.md": (
                "---\nbasalt:\n  id: 01jbq10000000000000000000\n---\n# Short\n"
            )
        }
    ).reindex(generated=EPOCH)
    entry = next(
        e for e in indexes["integrity"]["entries"] if e["code"] == "INVALID_ID"
    )
    assert entry["severity"] == "error"
    assert "25 characters; a ULID is 26" in entry["detail"]
    assert indexes["nodes"]["entries"][0]["id"] is None
    assert "UNBOUND_NODE" in codes(indexes)


def test_a_ulid_with_an_excluded_letter_says_which() -> None:
    """§4.1 — Crockford base32 omits i, l, o and u."""
    indexes = build(
        {
            "content/Oh.md": (
                "---\nbasalt:\n  id: o1jbq10000000000000000000l\n---\n# Oh\n"
            )
        }
    ).reindex(generated=EPOCH)
    detail = next(
        e["detail"] for e in indexes["integrity"]["entries"] if e["code"] == "INVALID_ID"
    )
    assert "illegal character(s)" in detail
    assert "i, l, o and u" in detail


def test_a_malformed_sidecar_id_is_as_loud_as_a_malformed_frontmatter_one() -> None:
    """§6.1 — an id that is present and wrong is not the same as one missing.

    Dropping it silently would report only UNBOUND_NODE, which reads as "this
    asset has no sidecar entry" when in fact it has one, off by a character.
    """
    indexes = build(
        {
            "content/Assets/d.png": "png",
            "meta/folders/Assets/entries.yaml": (
                "entries:\n  d.png:\n    id: 01jbq10000000000000000000\n"
            ),
        }
    ).reindex(generated=EPOCH)
    entry = next(
        e for e in indexes["integrity"]["entries"] if e["code"] == "INVALID_ID"
    )
    assert entry["path"] == "Assets/d.png"
    assert "25 characters" in entry["detail"]
    assert indexes["nodes"]["entries"][0]["errors"] == ["INVALID_ID"]


def test_an_embed_resolves_by_full_basename_not_only_the_stem() -> None:
    """§9.2 step 5 — otherwise every ``![[image.png]]`` in the vault dangles.

    The asset normally lives in a different folder from the note that embeds
    it, so steps 2 and 3 both miss and step 5 has to match ``diagram.png`` and
    not just ``diagram``.
    """
    indexes = build(
        {
            "content/Notes/Source.md": (
                "---\nbasalt:\n  id: 01jbq100000000000000000001\n---\n"
                "# S\n\nAn embed: ![[diagram.png]]\n"
            ),
            "content/Assets/diagram.png": "png",
            "meta/folders/Assets/entries.yaml": (
                "entries:\n  diagram.png:\n    id: 01jbq100000000000000000004\n"
            ),
        }
    ).reindex(generated=EPOCH)
    edge = next(e for e in indexes["links"]["entries"] if e["kind"] == "embed")
    assert edge["to"] == "01jbq100000000000000000004"
    assert edge["ambiguous"] is False
    assert "UNRESOLVED_LINK" not in codes(indexes)
