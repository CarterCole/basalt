"""YAML reading and writing, PROTOCOL §13.4.

Human-authored YAML (§3) is read permissively — any valid YAML 1.2 — but when
an implementation *writes* it, §13.4 constrains the output: block style,
two-space indents, unquoted keys where legal, double quotes when quoting is
needed, no anchors or aliases, existing key order preserved with new keys
appended at the end.

The rules there are about not making a mess, not about determinism, and the
load-bearing one is the last paragraph: comments MUST be preserved when an
implementation edits a YAML file it did not author, and an implementation that
cannot preserve them MUST refuse to rewrite the file and report it rather than
silently stripping them. That is why this module is built on ruamel.yaml's
round-trip mode rather than the simpler safe loader: a round-trip load carries
the comments and the key order through the edit.
"""

from __future__ import annotations

import io
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.constructor import SafeConstructor

_MERGE_TAG = "tag:yaml.org,2002:merge"
_STR_TAG = "tag:yaml.org,2002:str"


class _PlainMergeKeys(SafeConstructor):
    """The safe constructor, reading ``<<`` as the key it is.

    A merge key is a YAML 1.1 type. §13.4 reads YAML 1.2, which has none, and
    the TypeScript and Rust readers take ``<<`` for an ordinary key. Applying
    it here made this the one reader that saw ``basalt: {<<: *x}`` as carrying
    whatever ``x`` held: a note stored through another implementation, whose
    store had seen no ``basalt.acl`` in it and so asked for no ``write_acl``,
    arrived here with an ACL. Readers that disagree about what a file says
    disagree about who may read it, so this one says what the others say.
    It also takes away the merge's cost, which nested merges made exponential.
    """

    def flatten_mapping(self, node: Any) -> Any:
        for key_node, _value_node in node.value:
            if key_node.tag == _MERGE_TAG:
                key_node.tag = _STR_TAG


class CommentsWouldBeLost(RuntimeError):
    """Raised instead of rewriting a YAML file whose comments cannot survive.

    §13.4: "An implementation that cannot preserve comments MUST refuse to
    rewrite the file and MUST report it, rather than silently stripping them."
    """


def _reader() -> YAML:
    y = YAML(typ="safe")
    y.Constructor = _PlainMergeKeys
    y.allow_duplicate_keys = True  # read permissively (§13.4)
    return y


def _round_tripper() -> YAML:
    y = YAML()  # typ="rt": retains comments, key order and layout
    y.preserve_quotes = True
    y.allow_duplicate_keys = True
    y.indent(mapping=2, sequence=4, offset=2)
    y.width = 4096  # never reflow a human's long line into a folded scalar
    return y


def load(text: str, fallback: Any = None) -> Any:
    """Parse YAML into plain Python data, returning ``fallback`` on failure.

    Used wherever a malformed file must not take the whole pass down with it:
    the manifest, principals, folder records and ACL files are all read this
    way, exactly as §5.2 requires of frontmatter.
    """
    try:
        value = _reader().load(text)
    except Exception:
        # Not YAMLError alone. The constructor lets a ValueError out for a
        # date that is no date (`2024-13-45`), `!!int abc` or an integer of
        # 5,000 digits, and the parser a RecursionError for nesting deeper
        # than the interpreter's stack. Whatever one file's content can raise
        # is that file being malformed, never a failed pass (§5.2).
        return fallback
    return fallback if value is None else value


def load_preserving(text: str) -> Any:
    """Round-trip parse, retaining comments and key order for a later edit."""
    return _round_tripper().load(text)


def dump(data: Any) -> str:
    """Serialize per §13.4: block style, two-space indents, no anchors.

    Accepts either plain data or a round-trip document from
    :func:`load_preserving`; in the latter case the comments and key order of
    the original survive.
    """
    y = _round_tripper()
    y.default_flow_style = False  # §13.4: block style
    buf = io.StringIO()
    y.dump(data, buf)
    return buf.getvalue()


def edit(text: str, mutate: Any) -> str:
    """Apply ``mutate`` to a round-tripped document and re-serialize it.

    ``mutate`` receives the parsed document and may return a replacement or
    mutate in place. If the round trip cannot be performed the file is left
    alone and :class:`CommentsWouldBeLost` is raised, per §13.4.
    """
    try:
        doc = load_preserving(text)
    except Exception as err:
        # As in load(): the round-trip parser raises more than YAMLError on
        # the same content, and a caller must get the one refusal it handles.
        raise CommentsWouldBeLost(f"cannot round-trip this YAML: {err}") from err
    result = mutate(doc)
    return dump(result if result is not None else doc)
