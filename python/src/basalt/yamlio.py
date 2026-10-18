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
from ruamel.yaml.error import YAMLError


class CommentsWouldBeLost(RuntimeError):
    """Raised instead of rewriting a YAML file whose comments cannot survive.

    §13.4: "An implementation that cannot preserve comments MUST refuse to
    rewrite the file and MUST report it, rather than silently stripping them."
    """


def _reader() -> YAML:
    y = YAML(typ="safe")
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
    except YAMLError:
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
    except YAMLError as err:
        raise CommentsWouldBeLost(f"cannot round-trip this YAML: {err}") from err
    result = mutate(doc)
    return dump(result if result is not None else doc)
