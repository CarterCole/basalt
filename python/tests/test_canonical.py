"""Canonical serialization, PROTOCOL §13.

Every rule in §13.1 is one an implementation can get subtly wrong and still
look right in a diff viewer, so each gets its own assertion.
"""

from __future__ import annotations

import json

import pytest

from basalt.canonical import ABSENT, canonical_bytes, canonical_json, comparable
from basalt.order import compare_utf8, fold_case, nfc, sort_utf8, utf8_key


def test_two_space_indent_one_element_per_line() -> None:
    assert canonical_json({"b": [1, 2], "a": {"x": True}}) == (
        "{\n"
        '  "a": {\n'
        '    "x": true\n'
        "  },\n"
        '  "b": [\n'
        "    1,\n"
        "    2\n"
        "  ]\n"
        "}\n"
    )


def test_exactly_one_trailing_newline_and_lf_endings() -> None:
    out = canonical_json({"a": 1})
    assert out.endswith("}\n")
    assert not out.endswith("\n\n")
    assert "\r" not in out


def test_no_trailing_whitespace_on_any_line() -> None:
    out = canonical_json({"a": [], "b": {}, "c": [1, {"d": "x"}]})
    for line in out.split("\n"):
        assert line == line.rstrip(), repr(line)


def test_empty_containers() -> None:
    assert canonical_json({"a": [], "b": {}}) == '{\n  "a": [],\n  "b": {}\n}\n'


def test_keys_sorted_by_utf8_bytes() -> None:
    # "Z" (0x5A) < "a" (0x61) < "é" (0xC3 0xA9): bytewise, not case-insensitive
    # and not locale collation (§13.3).
    out = canonical_json({"é": 1, "a": 2, "Z": 3})
    assert list(json.loads(out)) == ["Z", "a", "é"]
    assert out.index('"Z"') < out.index('"a"') < out.index('"é"')


def test_non_ascii_emitted_literally() -> None:
    """§13.1 — escape only what JSON requires, plus U+2028 and U+2029."""
    out = canonical_json({"t": "Café — 基盤 🪨"})
    assert "Café — 基盤 🪨" in out
    assert "\\u" not in out


def test_line_separators_are_escaped() -> None:
    """Legal JSON, but they break the bytes inside a <script> tag."""
    out = canonical_json({"t": "a\u2028b\u2029c"})
    assert "\\u2028" in out and "\\u2029" in out
    assert json.loads(out)["t"] == "a\u2028b\u2029c"


def test_required_json_escapes() -> None:
    out = canonical_json({"t": 'q"\\b\b\f\n\r\t\x00'})
    assert '\\"' in out and "\\\\" in out and "\\b" in out and "\\u0000" in out
    assert json.loads(out)["t"] == 'q"\\b\b\f\n\r\t\x00'


def test_integers_bare_and_floats_refused() -> None:
    """§13.1 bans non-integers outright, sidestepping float formatting."""
    assert canonical_json({"n": 4096}) == '{\n  "n": 4096\n}\n'
    with pytest.raises(TypeError, match="non-integer"):
        canonical_json({"n": 1.5})
    with pytest.raises(TypeError, match="non-integer"):
        canonical_json({"n": 1.0})


def test_bools_are_not_integers() -> None:
    """In Python ``bool`` subclasses ``int``; a naive writer emits ``1``."""
    assert canonical_json({"a": True, "b": False}) == (
        '{\n  "a": true,\n  "b": false\n}\n'
    )


def test_null_is_emitted_but_absent_is_dropped() -> None:
    """§13.1 has no "omit this key", so the two must be distinguishable."""
    assert canonical_json({"a": None, "b": ABSENT}) == '{\n  "a": null\n}\n'
    assert canonical_json({"b": ABSENT}) == "{}\n"


def test_unserializable_types_refused() -> None:
    with pytest.raises(TypeError, match="unserializable"):
        canonical_json({"a": object()})


def test_bytes_are_utf8_with_no_bom() -> None:
    data = canonical_bytes({"t": "é"})
    assert not data.startswith(b"\xef\xbb\xbf")
    assert data == '{\n  "t": "é"\n}\n'.encode()


def test_comparable_strips_only_the_excluded_fields() -> None:
    """§13.2 — ``generated`` and ``etag``, nothing else."""
    obj = {
        "generated": "2026-10-18T14:31:00Z",
        "kind": "nodes",
        "entries": [{"path": "a.md", "etag": '"x"', "content_hash": "sha256:1"}],
    }
    stripped = comparable(obj)
    assert "generated" not in stripped
    assert "etag" not in stripped["entries"][0]
    assert stripped["entries"][0]["content_hash"] == "sha256:1"
    assert stripped["kind"] == "nodes"
    # And the original is untouched.
    assert obj["generated"] == "2026-10-18T14:31:00Z"


# ------------------------------------------------------------- §13.3 order


def test_ordering_is_bytewise_not_case_insensitive() -> None:
    assert sort_utf8(["b", "A", "a", "B"]) == ["A", "B", "a", "b"]


def test_ordering_normalizes_to_nfc_first() -> None:
    nfd = "Cafe\u0301.md"  # Cafe + combining acute
    assert compare_utf8(nfd, "Café.md") == 0
    assert nfc(nfd) == "Café.md"


def test_prefix_sorts_before_its_extension() -> None:
    assert sort_utf8(["Notes/ab", "Notes/a"]) == ["Notes/a", "Notes/ab"]


def test_astral_plane_ordering_matches_code_points() -> None:
    """UTF-8 is order-preserving, so §13.3 and Python's own order agree.

    The ordering §13.3 rules out is UTF-16 code unit order, where the
    surrogate pair for U+10000 sorts *below* U+E000. An implementation in a
    UTF-16 language has to correct for that; this one sorts the encoded bytes,
    which is right by construction.
    """
    astral, private_use = "\U00010000", "\ue000"
    assert utf8_key(private_use) < utf8_key(astral)
    assert private_use < astral  # the same answer, here
    # The UTF-16 ordering a JavaScript implementation would get by default:
    assert private_use.encode("utf-16-be") > astral.encode("utf-16-be")


def test_fold_case_is_lowercase_not_full_casefold() -> None:
    """§2.2's fold must not be stricter than the filesystems it protects against.

    ``str.casefold()`` maps ``ß`` to ``ss``, which would make ``Strasse.md``
    and ``Straße.md`` collide. No store Basalt targets folds those together,
    so inventing a stricter fold would reject legal keys.
    """
    assert fold_case("Straße.md") == "straße.md"
    assert fold_case("HEXES.md") == fold_case("Hexes.md")


def test_utf8_key_survives_lone_surrogates() -> None:
    """Ordering must stay total even for a name no store should hold."""
    assert utf8_key("a\udcffb")  # does not raise
