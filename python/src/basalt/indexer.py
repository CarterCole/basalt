"""Index generation, PROTOCOL §10.

Everything here is derived: delete every index and these functions rebuild all
of them from content alone, byte for byte (§0). That property is what makes
the conformance suite checkable, so the only inputs allowed are content bytes
and keys — never listing order, never mtimes.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

import regex as re2

from . import yamlio
from .canonical import ABSENT
from .frontmatter import Note, kind_for, parse_note, ulid_problem
from .keys import (
    basename,
    compare_utf8,
    find_collisions,
    find_folder_case_divergence,
    fold_case,
    implied_folders,
    key_to_path,
    nfc,
    parent_folder,
    sort_utf8,
    stem,
)
from .links import (
    Heading,
    RawEdge,
    anchor_resolves,
    build_resolver,
    extract_block_ids,
    extract_headings,
    extract_links,
    resolve_target,
    tag_closure,
)

SPEC = 1

#: The sentinel `generated` value used when output is being compared rather
#: than published. §13.2 excludes the field from comparison, so pinning it
#: keeps a regenerated fixture from differing on every run.
EPOCH = "1970-01-01T00:00:00Z"


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _hex(digest: bytes) -> str:
    return "sha256:" + digest.hex()


def content_hash(data: bytes) -> str:
    """The ``sha256:`` hash over an object's raw bytes (§10.1).

    Authoritative, unlike ``etag``: etags differ between S3 implementations
    for multipart uploads and are useless for cross-store comparison, so the
    protocol keeps both and trusts the hash.
    """
    return _hex(_sha256(data))


@dataclass
class ScannedObject:
    """One content object as read from a transport."""

    key: str
    path: str
    data: bytes
    size: int | None = None
    etag: str | None = None


@dataclass
class DigestResult:
    root: str
    count: int
    tree: dict[str, str]


def compute_digest(entries: list[tuple[str, str]]) -> DigestResult:
    """The merkle root over ``content/`` (§10.6).

    ``entries`` is a list of ``(path, content_hash)`` pairs.

    1. For each content key, take ``sha256(path_bytes || 0x00 || content_hash)``.
    2. Sort those leaf hashes bytewise ascending.
    3. Fold them: ``root = sha256(concat(sorted_leaves))``.
    4. The empty content tree has root ``sha256("")``.

    Sorting the *hashes* rather than the paths makes the root independent of
    traversal order, so a store whose ``list`` is unordered (§1) cannot change
    the result.
    """

    def leaf(path: str, chash: str) -> bytes:
        return _sha256(
            nfc(path).encode("utf-8"),
            b"\x00",
            bytes.fromhex(chash.removeprefix("sha256:")),
        )

    leaves = sorted(leaf(p, c) for p, c in entries)
    root = _sha256(b"".join(leaves)) if leaves else _sha256(b"")

    # Per-folder subtree hashes let an incremental pass skip untouched folders.
    by_folder: dict[str, list[bytes]] = {}
    for path, chash in entries:
        for folder in _folders_of(path):
            by_folder.setdefault(folder, []).append(leaf(path, chash))

    tree: dict[str, str] = {}
    for folder, hashes in by_folder.items():
        tree[folder] = _hex(_sha256(b"".join(sorted(hashes))))
    for path, chash in entries:
        tree[path] = chash

    return DigestResult(root=_hex(root), count=len(entries), tree=tree)


def _folders_of(path: str) -> list[str]:
    out: list[str] = []
    acc = ""
    for seg in path.split("/")[:-1]:
        acc += seg + "/"
        out.append(acc)
    return out


def _now_iso() -> str:
    return (
        dt.datetime.now(dt.UTC)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def envelope(
    kind: str,
    vault_id: str,
    source_digest: str,
    extra: dict[str, Any],
    generated: str | None = None,
) -> dict[str, Any]:
    """The envelope every index object shares (§10).

    ``source_digest`` is the merkle root (§10.6) of the content tree the index
    was built from. It is how a reader decides, in **one** ``get``, whether an
    index can be trusted — not by comparing timestamps, which §1 forbids
    relying on.
    """
    return {
        "basalt": SPEC,
        "kind": kind,
        "vault": vault_id,
        "generated": generated if generated is not None else _now_iso(),
        "source_digest": source_digest,
        **extra,
    }


@dataclass
class IndexedNode:
    """A content object with everything the index needs, pre-serialization."""

    path: str
    kind: str
    content_hash: str
    size: int
    etag: str | None = None
    id: str | None = None
    title: str | None = None
    tags: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    publish: bool = True
    headings: list[Heading] = field(default_factory=list)
    block_ids: list[str] = field(default_factory=list)
    acl: Any = None
    errors: list[dict[str, str]] = field(default_factory=list)
    text: str | None = None
    body: str | None = None
    body_start_line: int = 1


@dataclass
class BuiltIndexes:
    nodes: dict[str, Any]
    links: dict[str, Any]
    backlinks: dict[str, Any]
    tags: dict[str, Any]
    digest: dict[str, Any]
    integrity: dict[str, Any]
    search: dict[str, Any] | None = None
    node_records: list[IndexedNode] = field(default_factory=list)
    folder_records: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    digest_result: DigestResult | None = None

    def as_dict(self) -> dict[str, dict[str, Any]]:
        out = {
            "nodes": self.nodes,
            "links": self.links,
            "backlinks": self.backlinks,
            "tags": self.tags,
            "digest": self.digest,
            "integrity": self.integrity,
        }
        if self.search is not None:
            out["search"] = self.search
        return out


def _integrity_entry(
    severity: str, code: str, path: str | None = None, detail: str | None = None
) -> dict[str, Any]:
    """One integrity condition (§10.7).

    Absent fields are the :data:`basalt.canonical.ABSENT` sentinel rather than
    ``None``: §13.1 has no way to say "omit this key", so the serializer drops
    sentinel values while still emitting a genuine JSON ``null``.
    """
    return {
        "severity": severity,
        "code": code,
        "path": path if path is not None else ABSENT,
        "detail": detail if detail is not None else ABSENT,
    }


def build_indexes(
    *,
    scanned: list[ScannedObject],
    vault_id: str,
    sidecars: dict[str, Any] | None = None,
    folder_records: dict[str, Any] | None = None,
    generated: str | None = None,
    integrity_hook: Any = None,
) -> BuiltIndexes:
    """Build every index from a scan of content.

    Returns the index objects plus the integrity report, ready to be
    canonically serialized (§13.1).

    ``integrity_hook`` is called with the parsed node list once identities are
    settled and may return further §10.7 conditions. It exists so the caller
    can contribute the ones that need the principal directory — membership
    cycles (§7.2) and unresolvable ACE subjects (§8.4) — which this module has
    no business knowing about but which §10.7 requires be collected in the
    same report.
    """
    sidecars = sidecars or {}
    folder_records = folder_records or {}
    integrity: list[dict[str, Any]] = []

    # ---- pass 1: parse every object, collect identities -------------------
    nodes: list[IndexedNode] = []
    for item in sort_utf8(scanned, lambda s: s.path):
        path = item.path
        kind = kind_for(path)
        folder = parent_folder(path)
        sidecar = _sidecar_entry(sidecars, folder, basename(path))

        node = IndexedNode(
            path=path,
            kind=kind,
            content_hash=content_hash(item.data),
            size=item.size if item.size is not None else len(item.data),
            etag=item.etag,
        )

        if kind == "note":
            text = item.data.decode("utf-8", errors="replace")
            parsed: Note = parse_note(text, path)
            node.id = parsed.id
            node.title = parsed.title
            node.tags = parsed.tags
            node.aliases = parsed.aliases
            node.publish = parsed.publish
            node.acl = parsed.acl
            node.headings = extract_headings(parsed.body)
            node.block_ids = extract_block_ids(parsed.body)
            node.text = text
            node.body = parsed.body
            node.body_start_line = parsed.body_start_line
            node.errors = parsed.errors
        else:
            # §4.2: an object that cannot carry frontmatter gets its id from
            # the folder's entry sidecar, so the id still survives a rename
            # performed by a tool that has never heard of this protocol.
            sidecar_id = sidecar.get("id") if sidecar else None
            if sidecar_id is not None:
                problem = ulid_problem(str(sidecar_id).lower())
                if problem is None:
                    node.id = str(sidecar_id).lower()
                else:
                    # A malformed sidecar id must be as loud as a malformed
                    # frontmatter one. Dropping it silently would leave the
                    # object reported only as UNBOUND_NODE, which says a
                    # sidecar entry is missing — not that one is present and
                    # wrong by a character.
                    node.errors.append(
                        {
                            "severity": "error",
                            "code": "INVALID_ID",
                            "detail": f"{sidecar_id}: {problem}",
                        }
                    )
            sidecar_title = sidecar.get("title") if sidecar else None
            node.title = sidecar_title if sidecar_title is not None else stem(basename(path))
            if kind == "data":
                node.text = item.data.decode("utf-8", errors="replace")

        for err in node.errors:
            integrity.append(
                _integrity_entry(err["severity"], err["code"], path, err.get("detail"))
            )
        nodes.append(node)

    # ---- integrity: key collisions and folder-case divergence -------------
    all_keys = [s.key for s in scanned]
    for group in find_collisions(all_keys):
        integrity.append(
            _integrity_entry(
                "error",
                "KEY_COLLISION",
                key_to_path(group[0]) or group[0],
                f"collides with {', '.join(group[1:])}",
            )
        )

    for group in find_folder_case_divergence(all_keys):
        integrity.append(
            _integrity_entry(
                "warning",
                "FOLDER_CASE_DIVERGENCE",
                key_to_path(group[0]) or group[0],
                f"also spelled {', '.join(group[1:])}",
            )
        )

    # §4.3: the bytewise-first path keeps a duplicated id; every other
    # claimant is treated as unbound, so two implementations repairing the
    # same damaged vault reach the same result.
    by_id: dict[str, IndexedNode] = {}
    for node in nodes:
        if not node.id:
            continue
        keeper = by_id.get(node.id)
        if keeper is None:
            by_id[node.id] = node
            continue
        loser = node if compare_utf8(keeper.path, node.path) <= 0 else keeper
        if loser is keeper:
            by_id[node.id] = node
        integrity.append(
            _integrity_entry(
                "warning",
                "DUPLICATE_ID",
                loser.path,
                f"id {loser.id} also claimed by {by_id[node.id].path}",
            )
        )
        loser.id = None

    for node in nodes:
        if not node.id:
            integrity.append(_integrity_entry("warning", "UNBOUND_NODE", node.path))

    # ---- folder nodes ------------------------------------------------------
    folders = implied_folders([n.path for n in nodes])
    folder_nodes: list[dict[str, Any]] = []
    for f in folders:
        record = folder_records.get(f) or {}
        basalt_block = record.get("basalt") if isinstance(record, dict) else None
        folder_nodes.append(
            {
                "path": f,
                "kind": "folder",
                "id": (basalt_block or {}).get("id") if isinstance(basalt_block, dict) else None,
                "title": record.get("title") or (basename(f.rstrip("/")) or None),
                "publish": record.get("publish") is not False,
            }
        )

    # §6.1: a sidecar entry whose object is gone is pruned on the next
    # write-capable pass; here it is reported.
    paths = {n.path for n in nodes}
    for folder, sidecar in sidecars.items():
        entries = sidecar.get("entries") if isinstance(sidecar, dict) else None
        for name in (entries or {}):
            if folder + str(name) not in paths:
                integrity.append(
                    _integrity_entry(
                        "warning",
                        "ORPHAN_SIDECAR",
                        folder + str(name),
                        "sidecar entry has no object",
                    )
                )

    # ---- pass 2: resolve links --------------------------------------------
    resolver = build_resolver([n for n in nodes if n.id])
    by_path = {n.path: n for n in nodes}
    edges: list[dict[str, Any]] = []

    for node in nodes:
        if not node.id:
            continue
        if node.kind not in ("note", "data"):
            continue

        if node.kind == "note":
            found = extract_links(node.body or "")
            found_edges, found_tags = found.edges, found.tags
        else:
            found_edges = extract_data_links(node.text or "", node.path)
            found_tags = []

        # Merge frontmatter tags with inline tags, keeping the closure (§9.6).
        tag_display: dict[str, str] = {}
        for t in [*node.tags, *found_tags]:
            for c in tag_closure(t):
                tag_display.setdefault(fold_case(c), c)
        node.tags = list(tag_display.values())

        line_offset = node.body_start_line - 1 if node.kind == "note" else 0

        for e in found_edges:
            if e.kind == "external":
                edges.append(
                    {
                        "from": node.id,
                        "to": None,
                        "kind": "external",
                        "raw": e.raw,
                        "alias": e.alias,
                        "anchor": None,
                        "anchor_resolved": True,
                        "ambiguous": False,
                        "candidates": [],
                        "line": e.line + line_offset,
                        "col": e.col,
                    }
                )
                continue

            resolution = resolve_target(resolver, node.path, e.raw)
            target = by_path.get(resolution.node.path) if resolution.node else None
            if resolution.ambiguous:
                integrity.append(
                    _integrity_entry(
                        "warning",
                        "AMBIGUOUS_LINK",
                        node.path,
                        f'"{e.raw}" matches {len(resolution.candidates)} nodes',
                    )
                )
            if resolution.node is None:
                integrity.append(
                    _integrity_entry(
                        "warning", "UNRESOLVED_LINK", node.path, f'"{e.raw}"'
                    )
                )

            edges.append(
                {
                    "from": node.id,
                    "to": resolution.node.id if resolution.node else None,
                    "kind": e.kind,
                    "raw": e.raw,
                    "alias": e.alias,
                    "anchor": e.anchor,
                    # §9.3: a heading anchor that matches nothing does not make
                    # the edge unresolved — the node resolved; the fragment
                    # did not.
                    "anchor_resolved": (
                        anchor_resolves(e.anchor, target.headings, target.block_ids)
                        if target
                        else not e.anchor
                    ),
                    "ambiguous": resolution.ambiguous,
                    "candidates": resolution.candidates,
                    "line": e.line + line_offset,
                    "col": e.col,
                }
            )

    # §10.7: conditions that need the principal directory — membership cycles
    # and unresolvable ACE subjects — are contributed by the caller.
    if integrity_hook is not None:
        integrity.extend(integrity_hook(nodes))

    # ---- assemble ---------------------------------------------------------
    digest = compute_digest([(n.path, n.content_hash) for n in nodes])

    nodes_index = envelope(
        "nodes",
        vault_id,
        digest.root,
        {
            "entries": [
                {
                    "id": n.id,
                    "path": n.path,
                    "kind": n.kind,
                    "title": n.title,
                    "size": n.size,
                    "etag": n.etag,
                    "content_hash": n.content_hash,
                    "tags": sort_utf8(n.tags),
                    "aliases": n.aliases,
                    "headings": [h.as_entry() for h in n.headings],
                    "publish": n.publish,
                    "errors": [e["code"] for e in n.errors],
                }
                for n in nodes
            ]
        },
        generated,
    )

    links_index = envelope("links", vault_id, digest.root, {"entries": edges}, generated)

    backlinks: dict[str, list[str]] = {}
    for e in edges:
        if not e["to"]:
            continue
        backlinks.setdefault(e["to"], []).append(e["from"])
    backlinks = {
        target: sort_utf8(dict.fromkeys(sources))
        for target, sources in backlinks.items()
    }
    backlinks_index = envelope(
        "backlinks", vault_id, digest.root, {"entries": backlinks}, generated
    )

    tag_map: dict[str, list[str]] = {}
    for node in nodes:
        if not node.id:
            continue
        for t in node.tags:
            tag_map.setdefault(t, []).append(node.id)
    tag_map = {t: sort_utf8(dict.fromkeys(ids)) for t, ids in tag_map.items()}
    tags_index = envelope("tags", vault_id, digest.root, {"entries": tag_map}, generated)

    digest_index = envelope(
        "digest",
        vault_id,
        digest.root,
        {"root": digest.root, "count": digest.count, "tree": digest.tree},
        generated,
    )

    integrity_index = envelope(
        "integrity",
        vault_id,
        digest.root,
        {"entries": sort_utf8(integrity, _integrity_sort_key)},
        generated,
    )

    return BuiltIndexes(
        nodes=nodes_index,
        links=links_index,
        backlinks=backlinks_index,
        tags=tags_index,
        digest=digest_index,
        integrity=integrity_index,
        node_records=nodes,
        folder_records=folder_nodes,
        edges=edges,
        digest_result=digest,
    )


def _integrity_sort_key(entry: dict[str, Any]) -> str:
    path = entry.get("path")
    detail = entry.get("detail")
    path_s = "" if path is ABSENT or path is None else str(path)
    detail_s = "" if detail is ABSENT or detail is None else str(detail)
    return f"{path_s}\x00{entry['code']}\x00{detail_s}"


def _sidecar_entry(
    sidecars: dict[str, Any], folder: str, name: str
) -> dict[str, Any] | None:
    sidecar = sidecars.get(folder)
    if not isinstance(sidecar, dict):
        return None
    entries = sidecar.get("entries")
    if not isinstance(entries, dict):
        return None
    found = entries.get(name)
    return found if isinstance(found, dict) else None


_LINK_KEYS = frozenset({"link", "links", "ref", "refs", "href", "url"})
_DATA_WIKI_RE = re2.compile(r"^!?\[\[([^\[\]]+)\]\]$")
_DATA_SCHEME_RE = re2.compile(r"^[a-z][a-z0-9+.-]*://", re2.IGNORECASE)


def extract_data_links(text: str, path: str) -> list[RawEdge]:
    """Links inside data objects (§9.4).

    Any string *value* whose entire content matches a wikilink form is an
    edge, and so is any string under a key named ``link``, ``links``, ``ref``,
    ``refs``, ``href`` or ``url``. Keys are never scanned, only values:
    scanning keys would turn a dataset's column names into edges.
    """
    doc: Any = None
    if path.endswith(".json"):
        try:
            doc = json.loads(text)
        except ValueError:
            return []
    else:
        sentinel: Any = object()
        doc = yamlio.load(text, sentinel)
        if doc is sentinel:
            return []

    out: list[RawEdge] = []

    def walk(value: Any, key_name: str | None) -> None:
        if isinstance(value, str):
            wiki = _DATA_WIKI_RE.match(value)
            if wiki:
                raw = nfc(wiki.group(1).split("|")[0].split("#")[0].strip())
                out.append(
                    RawEdge(
                        kind="wiki", raw=raw, alias=None, anchor=None, offset=0,
                        line=1, col=1,
                    )
                )
            elif key_name in _LINK_KEYS:
                external = bool(_DATA_SCHEME_RE.match(value))
                out.append(
                    RawEdge(
                        kind="external" if external else "md",
                        raw=nfc(value),
                        alias=None,
                        anchor=None,
                        offset=0,
                        line=1,
                        col=1,
                    )
                )
            return
        if isinstance(value, (list, tuple)):
            for v in value:
                walk(v, key_name)
            return
        if isinstance(value, dict):
            for k, v in value.items():
                walk(v, str(k))

    walk(doc, None)
    return out


#: The ``basalt-en-v1`` stopword list named in §10.5.
STOPWORDS = frozenset(
    {
        "a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from",
        "has", "have", "he", "in", "is", "it", "its", "of", "on", "or", "that",
        "the", "their", "then", "there", "they", "this", "to", "was", "were",
        "will", "with",
    }
)  # fmt: skip

_TOKEN_RE = re2.compile(r"[\p{L}\p{N}_]+")


def build_search_index(
    *,
    nodes: list[IndexedNode],
    vault_id: str,
    source_digest: str,
    is_public: Any,
    generated: str | None = None,
) -> dict[str, Any]:
    """Build term postings, honoring the leak rule in §8.8.

    §8.8 is normative, not advisory: ``search.json`` MUST NOT contain text
    extracted from a node unless that node grants ``read`` to ``everyone`` or
    the index is itself access-controlled. The indexes know everything,
    because the link graph must be complete to be correct, which makes them
    the attack surface §15 names.
    """
    terms: dict[str, list[dict[str, Any]]] = {}
    for n in nodes:
        if not n.id or n.text is None:
            continue
        if not is_public(n):
            continue
        counts: dict[str, int] = {}
        for m in _TOKEN_RE.finditer((n.body if n.body is not None else n.text).lower()):
            t = nfc(m.group(0))
            if len(t) < 2 or t in STOPWORDS:
                continue
            counts[t] = counts.get(t, 0) + 1
        for t, tf in counts.items():
            terms.setdefault(t, []).append({"node": n.id, "tf": tf})

    terms = {t: sort_utf8(postings, lambda p: p["node"]) for t, postings in terms.items()}

    return envelope(
        "search",
        vault_id,
        source_digest,
        {"terms": terms, "stopwords": "basalt-en-v1", "stemmer": "none"},
        generated,
    )


__all__ = [
    "EPOCH",
    "SPEC",
    "STOPWORDS",
    "BuiltIndexes",
    "DigestResult",
    "IndexedNode",
    "ScannedObject",
    "build_indexes",
    "build_search_index",
    "compute_digest",
    "content_hash",
    "envelope",
    "extract_data_links",
]
