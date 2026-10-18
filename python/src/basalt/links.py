"""Link extraction and resolution, PROTOCOL §9.

The link graph is the reason a vault is more than a folder, so §9 specifies
extraction and resolution exactly: "which note does ``[[Hexes]]`` mean" must
not be answered differently by two implementations of the same vault.

Unicode property classes (``\\p{L}``, ``\\p{N}``) appear in §9.6's inline-tag
grammar and in §10.5's tokenizer. Python's :mod:`re` does not implement them,
so this module uses :mod:`regex`, which does. Approximating them with ``\\w``
would silently change which strings are tags: ``\\w`` includes the underscore
and, under :mod:`re`'s Unicode default, also matches characters §9.6 does not
list, so two implementations would disagree about a vault's tag set.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any

import regex as re2

from .keys import (
    basename,
    fold_case,
    nfc,
    parent_folder,
    resolve_relative,
    resolve_rooted,
    sort_utf8,
    stem,
)

#: §9.2 steps 1-3 try the target as written, then with each of these appended.
LINK_EXTENSIONS = ("", ".md", ".markdown")

Range = tuple[int, int]


# --------------------------------------------------------------- extraction


_FENCE_LINE = re2.compile(r"^\s{0,3}(`{3,}|~{3,})")


def exclusion_ranges(text: str) -> list[Range]:
    """Character ranges link syntax must be ignored inside (§9.1).

    Fenced code blocks, inline code spans, math blocks and HTML comments. This
    is computed as a mask over the whole text rather than line by line because
    three of the four constructs span lines. Getting it wrong is not a corner
    case: this protocol's own documentation is full of ``[[Example]]`` inside
    fences, and indexing those would pollute the graph of any vault that
    documents itself.
    """
    ranges: list[Range] = []
    n = len(text)

    # Fenced blocks: a line whose first non-space run is 3+ backticks or
    # tildes, closed by a line opening with at least as many of the same
    # character.
    lines: list[tuple[str, int]] = []
    off = 0
    for line in text.split("\n"):
        lines.append((line, off))
        off += len(line) + 1

    fence: tuple[str, int, int] | None = None  # (char, length, start offset)
    for line, start in lines:
        m = _FENCE_LINE.match(line)
        if fence is None:
            if m:
                fence = (m.group(1)[0], len(m.group(1)), start)
        elif m and m.group(1)[0] == fence[0] and len(m.group(1)) >= fence[1]:
            ranges.append((fence[2], start + len(line)))
            fence = None
    if fence is not None:
        ranges.append((fence[2], n))  # unterminated fence runs to end of file

    def masked(i: int) -> bool:
        return any(a <= i < b for a, b in ranges)

    # Inline code spans: matched runs of backticks on one line. `masked` sees
    # the ranges accumulated so far, so a backtick already inside a fence or
    # an earlier span cannot open a new one.
    i = 0
    while i < n:
        if text[i] != "`" or masked(i):
            i += 1
            continue
        run = 0
        while i + run < n and text[i + run] == "`":
            run += 1
        close = text.find("`" * run, i + run)
        if close == -1:
            i += run
            continue
        nl = text.find("\n", i)
        if nl != -1 and nl < close:
            i += run  # a code span does not span lines
            continue
        ranges.append((i, close + run))
        i = close + run

    # HTML comments and math blocks.
    for open_tok, close_tok in (("<!--", "-->"), ("$$", "$$")):
        i = 0
        while True:
            i = text.find(open_tok, i)
            if i == -1:
                break
            if masked(i):
                i += len(open_tok)
                continue
            end = text.find(close_tok, i + len(open_tok))
            if end == -1:
                ranges.append((i, n))
                break
            ranges.append((i, end + len(close_tok)))
            i = end + len(close_tok)

    ranges.sort(key=lambda r: r[0])
    return ranges


def _offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    line = 1
    last = 0
    for i in range(offset):
        if text[i] == "\n":
            line += 1
            last = i + 1
    return line, offset - last + 1


# [[target|alias]] / ![[target]] — the leading ! marks an embed.
_WIKI_RE = re2.compile(r"(!?)\[\[([^\[\]]*?)\]\]")
# [text](target) — the target stops at whitespace or the closing paren.
_MD_RE = re2.compile(r"\[([^\]]*)\]\(\s*<?([^()<>\s]+)>?(?:\s+\"[^\"]*\")?\s*\)")
# #tag, #nested/tag (§9.6). Not a tag when preceded by a word character, so
# `C#` and a URL fragment are both safe.
_TAG_RE = re2.compile(
    r"(^|[^\p{L}\p{N}_/#])#([\p{L}\p{N}_-]+(?:/[\p{L}\p{N}_-]+)*)"
)
_ALL_DIGITS_RE = re2.compile(r"^\p{N}+$")
_SCHEME_RE = re2.compile(r"^[a-z][a-z0-9+.-]*://", re2.IGNORECASE)


@dataclass
class RawEdge:
    kind: str
    raw: str
    alias: str | None
    anchor: str | None
    offset: int
    line: int = 0
    col: int = 0


def _parse_wiki_body(body: str) -> tuple[str, str | None, str | None]:
    """Split a raw wikilink body into target, alias and anchor."""
    rest = body
    alias: str | None = None
    pipe = rest.find("|")
    if pipe != -1:
        alias = nfc(rest[pipe + 1 :].strip()) or None
        rest = rest[:pipe]
    anchor: str | None = None
    hash_at = rest.find("#")
    if hash_at != -1:
        anchor = nfc(rest[hash_at + 1 :].strip()) or None
        rest = rest[:hash_at]
    return nfc(rest.strip()), alias, anchor


def _unquote(value: str) -> str:
    try:
        return urllib.parse.unquote(value, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return value


@dataclass
class Extracted:
    edges: list[RawEdge]
    tags: list[str]


def extract_links(text: str) -> Extracted:
    """Extract every edge and tag from note text.

    Edges come back in document order, which §10.2 requires.
    """
    ranges = exclusion_ranges(text)

    def excluded(i: int) -> bool:
        return any(a <= i < b for a, b in ranges)

    edges: list[RawEdge] = []

    for m in _WIKI_RE.finditer(text):
        if excluded(m.start()):
            continue
        target, alias, anchor = _parse_wiki_body(m.group(2))
        if not target:
            continue  # §9.1: an empty or whitespace target is skipped silently
        edges.append(
            RawEdge(
                kind="embed" if m.group(1) == "!" else "wiki",
                raw=target,
                alias=alias,
                anchor=anchor,
                offset=m.start(),
            )
        )

    for m in _MD_RE.finditer(text):
        if excluded(m.start()):
            continue
        href = m.group(2).strip()
        if not href or href.startswith("#"):
            continue
        is_external = bool(_SCHEME_RE.match(href)) or href.startswith("mailto:")
        target, anchor = href, None
        if not is_external:
            hash_at = href.find("#")
            if hash_at != -1:
                anchor = nfc(_unquote(href[hash_at + 1 :])) or None
                target = href[:hash_at]
            target = _unquote(target)
        if not target:
            continue
        edges.append(
            RawEdge(
                kind="external" if is_external else "md",
                raw=nfc(target),
                alias=nfc(m.group(1).strip()) or None,
                anchor=anchor,
                offset=m.start(),
            )
        )

    edges.sort(key=lambda e: e.offset)
    for e in edges:
        e.line, e.col = _offset_to_line_col(text, e.offset)

    return Extracted(edges=edges, tags=_extract_tags(text, excluded))


def _extract_tags(text: str, excluded: Any) -> list[str]:
    """Inline tags (§9.6), including the implied-parent closure.

    The index records the first-seen casing as the display form, so the map is
    keyed by the folded tag and holds the spelling that appeared first.
    """
    seen: dict[str, str] = {}
    for m in _TAG_RE.finditer(text):
        at = m.start() + len(m.group(1))
        if excluded(at):
            continue
        tag = nfc(m.group(2))
        if _ALL_DIGITS_RE.match(tag):
            continue  # §9.6: `#1` is not a tag
        for t in tag_closure(tag):
            seen.setdefault(fold_case(t), t)
    return list(seen.values())


def tag_closure(tag: str) -> list[str]:
    """``"a/b/c"`` -> ``["a", "a/b", "a/b/c"]`` (§9.6 implied parents)."""
    parts = tag.split("/")
    return ["/".join(parts[: i + 1]) for i in range(len(parts))]


_WS_RUN = re2.compile(r"\s+")
_NOT_SLUG = re2.compile(r"[^a-z0-9\-_]")


def slugify(text: str) -> str:
    """Slugify a heading for anchor comparison (§9.3)."""
    s = _WS_RUN.sub("-", nfc(text).lower().strip())
    return _NOT_SLUG.sub("", s)


_HEADING_RE = re2.compile(r"^(#{1,6})\s+(.+?)\s*#*\s*$")
_BLOCK_ID_RE = re2.compile(r"(?:^|\s)\^([\p{L}\p{N}-]+)\s*$", re2.MULTILINE)


@dataclass(frozen=True)
class Heading:
    level: int
    text: str
    slug: str

    def as_entry(self) -> dict[str, Any]:
        return {"level": self.level, "text": self.text, "slug": self.slug}


def extract_headings(text: str) -> list[Heading]:
    """Headings with slugs, skipping fenced code."""
    ranges = exclusion_ranges(text)

    def excluded(i: int) -> bool:
        return any(a <= i < b for a, b in ranges)

    out: list[Heading] = []
    off = 0
    for line in text.split("\n"):
        m = _HEADING_RE.match(line)
        if m and not excluded(off):
            t = nfc(m.group(2).strip())
            out.append(Heading(level=len(m.group(1)), text=t, slug=slugify(t)))
        off += len(line) + 1
    return out


def extract_block_ids(text: str) -> list[str]:
    """Block ids (``^abc123`` at the end of a line), for ``#^`` anchors."""
    return [m.group(1) for m in _BLOCK_ID_RE.finditer(text)]


# --------------------------------------------------------------- resolution


@dataclass
class ResolverNode:
    id: str | None
    path: str
    aliases: list[str]


class Resolver:
    """The lookup tables §9.2 resolution needs."""

    def __init__(self, nodes: list[Any]) -> None:
        self.nodes = nodes
        self.by_path: dict[str, Any] = {}
        self.by_alias: dict[str, list[Any]] = {}
        self.by_stem: dict[str, list[Any]] = {}

        for n in nodes:
            self.by_path[nfc(n.path)] = n
            for a in getattr(n, "aliases", None) or []:
                self.by_alias.setdefault(fold_case(a), []).append(n)
            # §9.2 step 5 matches the stem *and* the full basename, so that
            # both `[[Hexes]]` and `![[diagram.png]]` resolve. A node whose
            # name has no extension yields the same string twice, hence the
            # dedupe.
            name = basename(n.path)
            for key in dict.fromkeys([fold_case(stem(name)), fold_case(name)]):
                self.by_stem.setdefault(key, []).append(n)

        for table in (self.by_alias, self.by_stem):
            for key, bucket in table.items():
                table[key] = sorted(bucket, key=lambda n: n.path)

    def _try_path(self, candidate: str | None) -> Any | None:
        if not candidate:
            return None
        for ext in LINK_EXTENSIONS:
            hit = self.by_path.get(nfc(candidate + ext))
            if hit is not None:
                return hit
        return None


def build_resolver(nodes: list[Any]) -> Resolver:
    """Build the resolution tables from an iterable of node-like objects."""
    return Resolver(nodes)


@dataclass
class Resolution:
    node: Any | None
    by: str
    ambiguous: bool
    candidates: list[str]


def _pick(hits: list[Any], by: str) -> Resolution:
    """Choose among multiple name matches.

    §9.2 requires a deterministic tiebreak — the bytewise-first path — and
    requires the ambiguity be reported rather than hidden, so the author can
    fix the real problem.
    """
    ordered = sort_utf8(hits, lambda n: n.path)
    multiple = len(ordered) > 1
    return Resolution(
        node=ordered[0],
        by=by,
        ambiguous=multiple,
        candidates=[n.id for n in ordered] if multiple else [],
    )


def resolve_target(resolver: Resolver, from_path: str, raw_target: str) -> Resolution:
    """Resolve one target (§9.2), stopping at the first hit.

    The step order is the whole point: rooted paths beat relative ones,
    relative beat vault-root, and only then do the forgiving name-based steps
    run. Steps 1-3 are case-sensitive and 4-5 are not, because a path-shaped
    target means exactly what it says while a name-shaped one is how people
    type.
    """
    target = nfc(raw_target)

    # 1. Rooted path.
    if target.startswith("/"):
        hit = resolver._try_path(resolve_rooted(target))
        if hit is not None:
            return Resolution(hit, "rooted-path", False, [])
        # A rooted target is path-shaped and case-sensitive: it does not fall
        # through to the forgiving name steps, because `/columns` asks for a
        # path and `Columns.md` is not it.
        return Resolution(None, "unresolved", False, [])

    # 2. Exact relative path.
    rel_hit = resolver._try_path(resolve_relative(from_path, target))
    if rel_hit is not None:
        return Resolution(rel_hit, "relative-path", False, [])

    # 3. Exact vault-root path.
    root_hit = resolver._try_path(resolve_rooted(target))
    if root_hit is not None:
        return Resolution(root_hit, "vault-root-path", False, [])

    # 4. Alias, case-insensitive.
    alias_hits = resolver.by_alias.get(fold_case(target))
    if alias_hits:
        return _pick(alias_hits, "alias")

    # 5. Unique basename, case-insensitive.
    stem_hits = resolver.by_stem.get(fold_case(target))
    if stem_hits:
        return _pick(stem_hits, "unique-basename")

    # 6. Unresolved.
    return Resolution(None, "unresolved", False, [])


def anchor_resolves(
    anchor: str | None,
    headings: list[Heading] | None = None,
    block_ids: list[str] | None = None,
) -> bool:
    """True when an anchor resolves against a node's headings or block ids (§9.3).

    A heading anchor that matches nothing does not make the *edge* unresolved
    — the node resolved; only the fragment did not.
    """
    if not anchor:
        return True
    if anchor.startswith("^"):
        return anchor[1:] in (block_ids or [])
    want = slugify(anchor)
    return any(h.slug == want for h in (headings or []))


def strip_anchor(target: str) -> str:
    """Drop a ``#anchor`` suffix; anchors never affect which node resolves (§9.3)."""
    i = target.find("#")
    return target if i == -1 else target[:i]


__all__ = [
    "LINK_EXTENSIONS",
    "Extracted",
    "Heading",
    "RawEdge",
    "Resolution",
    "Resolver",
    "ResolverNode",
    "anchor_resolves",
    "build_resolver",
    "exclusion_ranges",
    "extract_block_ids",
    "extract_headings",
    "extract_links",
    "parent_folder",
    "resolve_target",
    "slugify",
    "strip_anchor",
    "tag_closure",
]
