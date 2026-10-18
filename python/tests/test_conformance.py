"""Runs the language-neutral corpus for L0-L2, PROTOCOL §14.2.

Expectations live in ``conformance/``, never here: no implementation defines
its own answers for behavior the spec covers.
"""

from __future__ import annotations

from typing import Any

import pytest

from basalt.frontmatter import parse_note
from basalt.keys import (
    BasaltKeyError,
    find_collisions,
    find_folder_case_divergence,
    implied_folders,
    key_to_path,
    validate_key,
)
from basalt.links import (
    ResolverNode,
    anchor_resolves,
    build_resolver,
    extract_links,
    resolve_target,
    strip_anchor,
)

from .conftest import corpus

# ------------------------------------------------------------- L0: keys

_KEYS = corpus("cases/keys/validation.yaml")


@pytest.mark.parametrize("case", _KEYS["cases"], ids=lambda c: c["name"])
def test_key_validation(case: dict[str, Any]) -> None:
    if case["valid"]:
        validate_key(case["key"])  # must not raise
        return
    with pytest.raises(BasaltKeyError) as excinfo:
        validate_key(case["key"])
    assert excinfo.value.code == case["error"], (
        f"wrong error code for {case['key']!r}"
    )


# -------------------------------------------------------- L1: collisions

_COLLISIONS = corpus("cases/paths/collisions.yaml")


@pytest.mark.parametrize("case", _COLLISIONS["cases"], ids=lambda c: c["name"])
def test_collisions(case: dict[str, Any]) -> None:
    groups = find_collisions(case["keys"])
    if not case["collides"]:
        assert groups == [], f"{' vs '.join(case['keys'])} should not collide"
        return
    assert len(groups) == 1, "expected exactly one colliding group"
    # §2.2: the surviving key is deterministic, so a repair is reproducible.
    assert groups[0][0] == case["survivor"]


@pytest.mark.parametrize(
    "case",
    [c for c in _COLLISIONS["cases"] if c.get("folder_divergence")],
    ids=lambda c: c["name"],
)
def test_folder_case_divergence(case: dict[str, Any]) -> None:
    groups = find_folder_case_divergence(case["keys"])
    assert len(groups) == 1, "expected one diverging folder group"
    assert groups[0] == case["folder_divergence"]


_FOLDERS = corpus("cases/paths/folders.yaml")


@pytest.mark.parametrize("case", _FOLDERS["cases"], ids=lambda c: c["name"])
def test_implied_folders(case: dict[str, Any]) -> None:
    paths = [p for p in (key_to_path(k) for k in case["keys"]) if p]
    assert implied_folders(paths) == case["folders"]


# ------------------------------------------------------ L1: frontmatter

_FRONTMATTER = corpus("cases/frontmatter/parsing.yaml")


@pytest.mark.parametrize("case", _FRONTMATTER["cases"], ids=lambda c: c["name"])
def test_frontmatter(case: dict[str, Any]) -> None:
    # No path means the case is not exercising the filename-stem title
    # fallback, so pass "" rather than inventing a name to fall back to.
    got = parse_note(case["content"], case.get("path") or "")
    want = case["expect"]

    # §5.2: frontmatter `tags` merge with inline #tags from the body, which is
    # a property of the pair, so the runner merges them exactly as the indexer
    # does.
    merged_tags = list(dict.fromkeys([*got.tags, *extract_links(got.body).tags]))

    if "id" in want:
        assert got.id == want["id"], "id"
    if "title" in want:
        assert got.title == want["title"], "title"
    if "tags" in want:
        assert merged_tags == want["tags"], "tags"
    if "aliases" in want:
        assert got.aliases == want["aliases"], "aliases"
    if "publish" in want:
        assert got.publish == want["publish"], "publish"
    if "body_starts_line" in want:
        assert got.body_start_line == want["body_starts_line"], "body_start_line"
    if want.get("errors"):
        assert [
            {"severity": e["severity"], "code": e["code"]} for e in got.errors
        ] == want["errors"], "errors"


# --------------------------------------------------- L2: link extraction

_EXTRACTION = corpus("cases/links/extraction.yaml")


@pytest.mark.parametrize("case", _EXTRACTION["cases"], ids=lambda c: c["name"])
def test_link_extraction(case: dict[str, Any]) -> None:
    parsed = parse_note(case["content"], case.get("path") or "Notes/Source.md")
    got = extract_links(parsed.body)

    if case.get("edges") is not None:
        assert len(got.edges) == len(case["edges"]), (
            f"edge count: got {[e.raw for e in got.edges]}"
        )
        for i, want in enumerate(case["edges"]):
            edge = got.edges[i]
            assert edge.kind == want["kind"], f"edge {i} kind"
            assert edge.raw == want["raw"], f"edge {i} raw"
            assert edge.alias == want["alias"], f"edge {i} alias"
            assert edge.anchor == want["anchor"], f"edge {i} anchor"
            if "line" in want:
                assert edge.line == want["line"], f"edge {i} line"

    if case.get("tags") is not None:
        every = list(dict.fromkeys([*parsed.tags, *got.tags]))
        assert every == case["tags"], "tags"


# -------------------------------------------------- L2: link resolution

_RESOLUTION = corpus("cases/links/resolution.yaml")
_RESOLVER = build_resolver(
    [
        ResolverNode(id=n["id"], path=n["path"], aliases=n.get("aliases") or [])
        for n in _RESOLUTION["vault"]["nodes"]
    ]
)


@pytest.mark.parametrize("case", _RESOLUTION["cases"], ids=lambda c: c["name"])
def test_link_resolution(case: dict[str, Any]) -> None:
    got = resolve_target(_RESOLVER, case["from"], strip_anchor(case["target"]))
    assert (got.node.id if got.node else None) == case["resolves_to"], "resolved node"
    assert got.by == case["by"], "resolution step"
    if "ambiguous" in case:
        assert got.ambiguous == case["ambiguous"], "ambiguity flag"
    if case.get("candidates"):
        assert got.candidates == case["candidates"], "candidate order"
    if "anchor_resolved" in case:
        # §9.3: a bad fragment never makes the edge unresolved; only the
        # anchor fails. The fixture vault carries no heading data, so an
        # anchor that names anything cannot resolve.
        anchor = (
            case["target"].split("#", 1)[1] if "#" in case["target"] else None
        )
        assert anchor_resolves(anchor, [], []) == case["anchor_resolved"]
    if "raw" in case:
        assert case["raw"] == strip_anchor(case["target"]), "raw target preserved"


# ------------------------------------- interpretations the corpus leaves open


def test_a_rooted_target_does_not_fall_through_to_later_steps() -> None:
    """§9.2: a rooted target that misses at step 1 is unresolved.

    The step list says "resolve in this order and stop at the first hit" and
    never states that step 1 is terminal for a rooted target. The readings
    differ on ordinary content: resolving ``/columns`` relative to
    ``Notes/Source.md`` normalizes the leading separator away and would find
    ``Notes/columns.md`` at step 2. The corpus case
    ``case-sensitive-path-does-not-match`` does not discriminate, because its
    vault has no such file.

    Both this implementation and the TypeScript reference treat step 1 as
    terminal — a rooted path means "from the vault root", and quietly
    reinterpreting it as relative would make ``/x`` mean two different things
    depending on whether the root happens to hold an ``x``. This test pins
    that choice so a future change to it is a deliberate one.
    """
    resolver = build_resolver(
        [ResolverNode(id="01jbq000000000000000000001", path="Notes/columns.md", aliases=[])]
    )
    got = resolve_target(resolver, "Notes/Source.md", "/columns")
    assert got.node is None
    assert got.by == "unresolved"
