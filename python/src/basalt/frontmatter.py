"""Frontmatter parsing, PROTOCOL §5.

The governing rule of §5.2: one malformed file must never cost the vault its
index. Every failure here is collected as a per-node error and the body is
indexed anyway.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import yamlio
from .keys import basename, extname, nfc, stem

DELIM = "---"
BOM = "﻿"

# Kind from the key alone (§5.1) — never from sniffing bytes.
NOTE_EXT = frozenset({".md", ".markdown"})
DATA_EXT = frozenset({".yaml", ".yml", ".json"})
ASSET_EXT = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".bmp", ".ico",
        ".pdf", ".mp3", ".wav", ".flac", ".ogg", ".m4a",
        ".mp4", ".webm", ".mov", ".avi", ".mkv",
        ".woff", ".woff2", ".ttf", ".otf",
        ".txt", ".csv", ".tsv",
    }
)  # fmt: skip


def kind_for(path: str) -> str:
    """One of ``note``, ``data``, ``asset``, ``opaque`` (§5.1).

    A function of the key alone, so kind is computable from a ``list`` result
    without fetching anything.
    """
    ext = extname(path)
    if ext in NOTE_EXT:
        return "note"
    if ext in DATA_EXT:
        return "data"
    if ext in ASSET_EXT:
        return "asset"
    return "opaque"


@dataclass(frozen=True)
class Split:
    raw: str | None
    body: str
    body_start_line: int


def split_frontmatter(text: str) -> Split:
    """Split a note into its frontmatter block and body.

    §5.2 is strict about the opening delimiter: it must be the very first
    line, with no BOM and no leading blank line. Both near-misses are common
    enough (editors add BOMs, authors add blank lines) that silently accepting
    them would make two implementations disagree about whether a file has
    frontmatter at all.
    """
    if text.startswith(BOM):
        return Split(None, text, 1)
    lines = text.split("\n")
    if lines[0].rstrip() != DELIM:
        return Split(None, text, 1)
    for i in range(1, len(lines)):
        if lines[i].rstrip() == DELIM:
            return Split("\n".join(lines[1:i]), "\n".join(lines[i + 1 :]), i + 2)
    # Unterminated block: no frontmatter, the whole file is body.
    return Split(None, text, 1)


_ULID_RE = re.compile(r"^[0-9a-hjkmnp-tv-z]{26}$")


def is_ulid(value: object) -> bool:
    """True for a well-formed Crockford base32 ULID (§4.1)."""
    return isinstance(value, str) and _ULID_RE.match(value.lower()) is not None


def _scalar(value: Any) -> str:
    """Render a YAML scalar the way the reference implementation's ``String()`` does.

    Only booleans differ between the two languages' default stringification,
    and a vault with ``title: true`` is odd but legal, so they are spelled out
    rather than left to ``str()``.
    """
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def normalize_tags(value: Any) -> list[str]:
    """Normalize a ``tags`` value: a list, or a comma-separated scalar (§5.2)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        raw: list[Any] = list(value)
    elif isinstance(value, str):
        raw = value.split(",")
    else:
        raw = [value]
    out: list[str] = []
    for item in raw:
        if item is None:
            continue
        s = nfc(_scalar(item)).strip()
        if s.startswith("#"):
            s = s[1:]
        if s:
            out.append(s)
    return out


@dataclass
class Note:
    id: str | None = None
    title: str | None = None
    tags: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    publish: bool = True
    acl: Any = None
    created: Any = None
    updated: Any = None
    frontmatter: Any = None
    has_frontmatter: bool = False
    body: str = ""
    body_start_line: int = 1
    errors: list[dict[str, str]] = field(default_factory=list)


def parse_note(text: str, path: str = "") -> Note:
    """Parse a note. Returns metadata plus ``errors``, never raising on bad YAML.

    ``path`` is used only for the filename-stem title fallback; a caller with
    no path (the conformance runner, for instance) passes ``""`` and gets a
    ``None`` title rather than an invented one.
    """
    errors: list[dict[str, str]] = []
    split = split_frontmatter(text)

    fm: Any = None
    if split.raw is not None:
        sentinel: Any = object()
        parsed = yamlio.load(split.raw, sentinel)
        if parsed is sentinel:
            errors.append(
                {
                    "severity": "warning",
                    "code": "FRONTMATTER_PARSE",
                    "detail": "frontmatter is not valid YAML",
                }
            )
            fm = None
        elif isinstance(parsed, dict):
            fm = parsed
        else:
            # A scalar or a sequence where a mapping belongs: there are no
            # protocol keys to find, so treat it as having none.
            fm = None

    basalt_block = fm.get("basalt") if isinstance(fm, dict) else None
    b: dict[str, Any] = basalt_block if isinstance(basalt_block, dict) else {}

    node_id = None
    if b.get("id") is not None:
        candidate = _scalar(b["id"]).lower()
        if is_ulid(candidate):
            node_id = candidate
        else:
            errors.append(
                {"severity": "error", "code": "INVALID_ID", "detail": _scalar(b["id"])}
            )

    # Title: frontmatter, then the first H1, then the filename stem (§5.2).
    title: str | None = None
    fm_title = fm.get("title") if isinstance(fm, dict) else None
    if fm_title is not None and _scalar(fm_title).strip():
        title = nfc(_scalar(fm_title).strip())
    else:
        h1 = first_h1(split.body)
        if h1:
            title = h1
        elif path:
            title = nfc(stem(basename(path)))

    raw_aliases = b.get("aliases")
    aliases = [
        nfc(_scalar(a).strip())
        for a in (raw_aliases if isinstance(raw_aliases, (list, tuple)) else [])
        if a is not None and nfc(_scalar(a).strip())
    ]

    return Note(
        id=node_id,
        title=title,
        tags=normalize_tags(fm.get("tags") if isinstance(fm, dict) else None),
        aliases=aliases,
        publish=b.get("publish") is not False,
        acl=b.get("acl"),
        created=b.get("created"),
        updated=b.get("updated"),
        frontmatter=fm,
        has_frontmatter=split.raw is not None,
        body=split.body,
        body_start_line=split.body_start_line,
        errors=errors,
    )


_FENCE_RE = re.compile(r"^(`{3,}|~{3,})")
_H1_RE = re.compile(r"^#\s+(.+?)\s*#*\s*$")


def first_h1(body: str) -> str | None:
    """The first ATX H1 outside fenced code, or ``None``."""
    fence: str | None = None
    for line in body.split("\n"):
        t = line.lstrip()
        f = _FENCE_RE.match(t)
        if f:
            if fence is None:
                fence = f.group(1)[0]
            elif t.startswith(fence * 3):
                fence = None
            continue
        if fence is not None:
            continue
        m = _H1_RE.match(t)
        if m:
            return nfc(m.group(1).strip())
    return None


def with_id(text: str, node_id: str) -> str:
    """Write a node id into a note's frontmatter, preserving comments (§13.4).

    Used by the minting pass (§4.3). A note with no frontmatter gains a
    minimal block; a note that has one keeps its comments, quoting and key
    order, with ``basalt.id`` set in place.
    """
    split = split_frontmatter(text)
    if split.raw is None:
        return f"---\nbasalt:\n  id: {node_id}\n---\n{text}"

    def mutate(doc: Any) -> Any:
        if isinstance(doc, dict):
            block = doc.get("basalt")
            if isinstance(block, dict):
                block["id"] = node_id
            else:
                doc["basalt"] = {"id": node_id}
            return doc
        # Frontmatter that is not a mapping cannot carry protocol keys; put the
        # block in front of whatever was there rather than discarding it.
        return {"basalt": {"id": node_id}}

    rewritten = yamlio.edit(split.raw, mutate).rstrip("\n")
    return f"---\n{rewritten}\n---\n{split.body}"
