"""The Vault facade, PROTOCOL §3 — loading, scanning, indexing, reading."""

from __future__ import annotations

import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from . import yamlio
from .acl import Principals
from .canonical import ABSENT, canonical_bytes
from .frontmatter import kind_for, parse_note, with_id
from .indexer import (
    BuiltIndexes,
    IndexedNode,
    ScannedObject,
    build_indexes,
    build_search_index,
    compute_digest,
    content_hash,
)
from .keys import (
    CONTENT,
    INDEX,
    MANIFEST,
    META,
    PRINCIPALS,
    basename,
    implied_folders,
    is_valid_key,
    key_to_path,
    parent_folder,
    path_to_key,
    sort_utf8,
)
from .links import Resolver  # noqa: F401  (re-exported for callers)
from .security import DescriptorStore, check_access, effective_rights
from .transport import Transport

#: The key each index object lives at (§3).
INDEX_KEYS: dict[str, str] = {
    "nodes": f"{INDEX}nodes.json",
    "links": f"{INDEX}links.json",
    "backlinks": f"{INDEX}backlinks.json",
    "tags": f"{INDEX}tags.json",
    "search": f"{INDEX}search.json",
    "digest": f"{INDEX}digest.json",
    "integrity": f"{INDEX}integrity.json",
}

#: Index kinds in the order the CLI and the conformance runner report them.
INDEX_KINDS = ("nodes", "links", "backlinks", "tags", "search", "digest", "integrity")


class EmptyIndexRefused(RuntimeError):
    """Refusing to replace a non-empty stored index with an empty one.

    This cannot lose content — indexes are derived (§0) — but a vault whose
    indexes went empty looks empty to every reader, and the usual cause is a
    transport pointed at the wrong bucket, prefix or addressing style (§3.1)
    rather than an emptied vault.
    """

    code = "EMPTY_INDEX_REFUSED"


@dataclass
class IndexState:
    current: str
    stored: str | None
    fresh: bool

    @property
    def label(self) -> str:
        """The value of ``X-Basalt-Index-State`` (§12.3)."""
        if self.stored is None:
            return "stale"
        return "fresh" if self.fresh else "stale"


@dataclass
class ReadResult:
    status: int
    node: dict[str, Any] | None = None
    data: bytes | None = None
    text: str | None = None
    decisions: dict[str, Any] = field(default_factory=dict)


class Vault:
    """A Basalt vault over a transport."""

    def __init__(self, transport: Transport) -> None:
        self.t = transport
        self.manifest: dict[str, Any] | None = None
        self.principals: Principals | None = None
        self.descriptors = DescriptorStore()
        self.indexes: dict[str, Any] | None = None
        self.built: BuiltIndexes | None = None
        self.folder_acls: dict[str, Any] = {}
        self.folder_records: dict[str, Any] = {}
        self.sidecars: dict[str, Any] = {}
        self.loaded = False

    # ---------------------------------------------------------- loading

    def _text(self, key: str) -> str | None:
        data = self.t.get(key)
        return None if data is None else data.decode("utf-8", errors="replace")

    def _yaml(self, key: str, fallback: Any = None) -> Any:
        text = self._text(key)
        return fallback if text is None else yamlio.load(text, fallback)

    def load(self) -> Vault:
        """Load the manifest, principals, folder records and ACLs."""
        manifest = self._yaml(MANIFEST)
        if not isinstance(manifest, dict):
            raise RuntimeError(f"not a Basalt vault: {MANIFEST} is missing")
        if manifest.get("basalt") != 1:
            # §3.1: a reader MUST refuse a vault whose `basalt` value it does
            # not implement.
            raise RuntimeError(f"unsupported spec version: basalt={manifest.get('basalt')}")
        self.manifest = manifest

        users = self._yaml(f"{PRINCIPALS}users.yaml", {}) or {}
        groups = self._yaml(f"{PRINCIPALS}groups.yaml", {}) or {}
        roles = self._yaml(f"{PRINCIPALS}roles.yaml", {}) or {}
        self.principals = Principals(
            users=users.get("users") or [],
            groups=groups.get("groups") or [],
            roles=roles.get("roles") or {},
        )

        self._load_meta()
        self.loaded = True
        return self

    def _load_meta(self) -> None:
        keys = self.t.list(META).keys
        folder_acls: dict[str, Any] = {}
        self.folder_records = {}
        self.sidecars = {}

        acl_prefix = f"{META}acl/"
        folders_prefix = f"{META}folders/"

        for key in keys:
            if key.startswith(acl_prefix) and key.endswith("acl.yaml"):
                folder = key[len(acl_prefix) : -len("acl.yaml")]
                folder_acls[folder] = self._yaml(key, {})
            elif key.startswith(folders_prefix):
                rest = key[len(folders_prefix) :]
                if rest.endswith("/folder.yaml"):
                    self.folder_records[rest[: -len("folder.yaml")]] = self._yaml(key, {})
                elif rest.endswith("/entries.yaml"):
                    self.sidecars[rest[: -len("entries.yaml")]] = self._yaml(
                        key, {"entries": {}}
                    )

        self.folder_acls = folder_acls
        self.descriptors = DescriptorStore(folder_acls=folder_acls, inline_acls={})

    # --------------------------------------------------------- scanning

    def scan(self) -> list[ScannedObject]:
        """Read every content object.

        Invalid keys (§1.1) are skipped rather than fatal: a vault that
        acquired one through some other tool must still be indexable.
        """
        keys = self.t.list(CONTENT).keys
        content = [k for k in keys if k.startswith(CONTENT) and is_valid_key(k)]
        out: list[ScannedObject] = []
        for key in sort_utf8(content):
            data = self.t.get(key)
            if data is None:
                continue  # raced with a delete
            stat = self.t.stat(key)
            path = key_to_path(key)
            assert path is not None
            out.append(
                ScannedObject(
                    key=key,
                    path=path,
                    data=data,
                    size=stat.size if stat else len(data),
                    etag=stat.etag if stat else None,
                )
            )
        return out

    def _opts(self) -> dict[str, Any]:
        manifest = self.manifest or {}
        publish = manifest.get("publish") or {}
        security = manifest.get("security") or {}
        return {
            "audience": publish.get("audience") or "gated",
            "bypass_traverse": bool(security.get("bypass_traverse", False)),
            "deny_unresolved": security.get("deny_unresolved", True) is not False,
        }

    def _descriptor_integrity(self, nodes: list[IndexedNode]) -> list[dict[str, Any]]:
        """§10.7 conditions that need the principal directory.

        Membership cycles and reserved principal ids come from the directory
        itself (§7.2, §7.3); unresolvable ACE subjects and undefined roles
        (§8.4, §7.4) come from walking every descriptor the vault carries.
        """
        from .acl import RIGHTS, WELL_KNOWN
        from .canonical import ABSENT as _ABSENT

        principals = self.principals
        assert principals is not None
        out: list[dict[str, Any]] = []

        for item in principals.integrity:
            out.append(
                {
                    "severity": item["severity"],
                    "code": item["code"],
                    "path": _ABSENT,
                    "detail": item.get("subject", _ABSENT),
                }
            )

        def check(descriptor: Any, where: str) -> None:
            if not isinstance(descriptor, dict):
                return
            for ace in descriptor.get("dacl") or []:
                if not isinstance(ace, dict):
                    continue
                subject = ace.get("subject")
                if not principals.exists(subject):
                    out.append(
                        {
                            "severity": "error",
                            "code": "UNRESOLVED_SUBJECT",
                            "path": where,
                            "detail": str(subject),
                        }
                    )
                for right in ace.get("rights") or []:
                    if (
                        isinstance(right, str)
                        and right != "full_control"
                        and right not in RIGHTS
                        and right not in principals.roles
                    ):
                        out.append(
                            {
                                "severity": "error",
                                "code": "UNRESOLVED_RIGHT",
                                "path": where,
                                "detail": right,
                            }
                        )
            owner = descriptor.get("owner")
            if owner is not None and not principals.exists(owner) and owner not in WELL_KNOWN:
                out.append(
                    {
                        "severity": "error",
                        "code": "UNRESOLVED_SUBJECT",
                        "path": where,
                        "detail": str(owner),
                    }
                )

        for folder, acl in self.folder_acls.items():
            if not isinstance(acl, dict):
                continue
            check(acl.get("folder"), folder or "/")
            entries = acl.get("entries")
            if isinstance(entries, dict):
                for name, descriptor in entries.items():
                    check(descriptor, folder + str(name))

        for node in nodes:
            if node.acl:
                check(node.acl, node.path)

        return out

    def reindex(
        self,
        *,
        write: bool = False,
        force: bool = False,
        generated: str | None = None,
    ) -> dict[str, Any]:
        """Rebuild every index from content alone (§0).

        Returns the index objects; pass ``write=True`` to persist them.
        """
        if not self.loaded:
            self.load()
        manifest = self.manifest or {}
        vault_id = (manifest.get("vault") or {}).get("id") or ""

        scanned = self.scan()
        built = build_indexes(
            scanned=scanned,
            vault_id=vault_id,
            sidecars=self.sidecars,
            folder_records=self.folder_records,
            generated=generated,
            integrity_hook=self._descriptor_integrity,
        )

        # Inline frontmatter ACLs replace a node's entry in the folder file
        # (§8.6) — the two are never merged, because merging two hand-edited
        # sources would make the effective ACL depend on load order.
        inline = {n.path: n.acl for n in built.node_records if n.acl}
        self.descriptors = DescriptorStore(
            folder_acls=self.folder_acls, inline_acls=inline
        )

        # §8.8: search text comes only from nodes readable by `everyone`.
        built.search = build_search_index(
            nodes=built.node_records,
            vault_id=vault_id,
            source_digest=built.digest["source_digest"],
            is_public=lambda n: self._readable_by_everyone(n.path),
            generated=generated,
        )

        self.built = built
        self.indexes = built.as_dict()

        if write:
            self._write_indexes(built, force=force)
        return self.indexes

    def _write_indexes(self, built: BuiltIndexes, *, force: bool) -> None:
        # §10.7: refuse to replace a non-empty stored index with an empty one.
        if not force and not built.node_records:
            prior = self._text(INDEX_KEYS["nodes"])
            prior_count = 0
            if prior is not None:
                try:
                    prior_count = len(json.loads(prior).get("entries") or [])
                except ValueError:
                    prior_count = 0
            if prior_count > 0:
                raise EmptyIndexRefused(
                    f"refusing to write an empty index: 0 nodes found, "
                    f"{prior_count} previously indexed. Check the transport is "
                    f"pointed at the right bucket and prefix, then pass force "
                    f"to override."
                )
        for name, key in INDEX_KEYS.items():
            obj = built.as_dict().get(name)
            if obj is not None:
                self.t.put(key, canonical_bytes(obj), content_type="application/json")

    def _readable_by_everyone(self, path: str) -> bool:
        """Would an anonymous reader of a public vault be allowed to read this?

        §8.8's leak rule is about the *node*, not about this vault's audience,
        so the check runs with ``audience: public`` — otherwise a gated
        vault's ceiling would answer the question instead of its ACLs, and the
        rule would be vacuous. §8.1's publish requirement still applies, so
        ``read`` alone does not qualify a node.
        """
        opts = self._opts()
        result = self._check(
            principal_id="anonymous",
            path=path,
            rights=["read"],
            audience="public",
            bypass_traverse=opts["bypass_traverse"],
            deny_unresolved=opts["deny_unresolved"],
        )
        return result.allowed

    def _check(self, **kwargs: Any) -> Any:
        assert self.principals is not None
        return check_access(
            store=self.descriptors, principals=self.principals, **kwargs
        )

    def load_indexes(self) -> dict[str, Any] | None:
        """Load indexes from the store without rebuilding."""
        out: dict[str, Any] = {}
        for name, key in INDEX_KEYS.items():
            text = self._text(key)
            if text is None:
                continue
            try:
                out[name] = json.loads(text)
            except ValueError:
                continue  # corrupt; a rebuild will replace it
        self.indexes = out or None
        return self.indexes

    def index_state(self) -> IndexState:
        """Index freshness (§10.6).

        One digest comparison, never timestamps — §1 forbids relying on those,
        and §10.6 makes the digest the single ``get`` that answers the
        question.
        """
        scanned = self.scan()
        current = compute_digest([(s.path, content_hash(s.data)) for s in scanned])
        stored = ((self.indexes or {}).get("nodes") or {}).get("source_digest")
        return IndexState(
            current=current.root,
            stored=stored,
            fresh=stored is not None and stored == current.root,
        )

    # ---------------------------------------------------------- reading

    def can(self, principal_id: str, path: str, rights: list[str]) -> Any:
        """Check access for a principal on a path (§8)."""
        return self._check(
            principal_id=principal_id, path=path, rights=rights, **self._opts()
        )

    def effective(self, principal_id: str, path: str) -> Any:
        """Effective rights with the deciding ACE per right (§8.7)."""
        assert self.principals is not None
        return effective_rights(
            store=self.descriptors,
            principals=self.principals,
            principal_id=principal_id,
            path=path,
            **self._opts(),
        )

    def _node_entry(self, path: str) -> dict[str, Any] | None:
        entries = ((self.indexes or {}).get("nodes") or {}).get("entries") or []
        for e in entries:
            if e.get("path") == path:
                return e
        return None

    def read_node(self, principal_id: str, path: str) -> ReadResult:
        """Read a node for a principal.

        §12.3: the 404/403 split is an information-leak boundary. A 403 on a
        path the requester was not allowed to discover confirms that path
        exists, so "cannot know it exists" must be indistinguishable from
        "does not exist".
        """
        node = self._node_entry(path)
        decision = self.can(principal_id, path, ["read"])

        if node is None:
            return ReadResult(status=404)
        if not decision.allowed:
            discoverable = self.can(principal_id, parent_folder(path), ["list"]).allowed
            return ReadResult(
                status=403 if discoverable else 404, decisions=decision.decisions
            )
        data = self.t.get(path_to_key(path))
        if data is None:
            return ReadResult(status=404)
        text = (
            data.decode("utf-8", errors="replace")
            if node.get("kind") in ("note", "data")
            else None
        )
        return ReadResult(status=200, node=node, data=data, text=text)

    def list_folder(self, principal_id: str, folder: str) -> dict[str, Any]:
        """Direct entries of a folder, filtered to those the principal may see."""
        if not self.can(principal_id, folder, ["list"]).allowed:
            parent_visible = (
                False
                if folder == ""
                else self.can(
                    principal_id, parent_folder(folder.rstrip("/")), ["list"]
                ).allowed
            )
            return {"status": 403 if parent_visible else 404}

        entries_index = ((self.indexes or {}).get("nodes") or {}).get("entries") or []
        entries = []
        for e in entries_index:
            if parent_folder(e.get("path", "")) != folder:
                continue
            if not self.can(principal_id, e["path"], ["read"]).allowed:
                continue
            entries.append(
                {
                    "path": e["path"],
                    "kind": e.get("kind"),
                    "title": e.get("title"),
                    "id": e.get("id"),
                }
            )

        subfolders = []
        for f in implied_folders([e.get("path", "") for e in entries_index]):
            if parent_folder(f.rstrip("/")) != folder:
                continue
            if not self.can(principal_id, f, ["list"]).allowed:
                continue
            subfolders.append(f)

        return {
            "status": 200,
            "entries": sort_utf8(entries, lambda e: e["path"]),
            "folders": sort_utf8(subfolders),
        }

    def links(self, principal_id: str, path: str) -> dict[str, Any]:
        """Out-edges and backlinks for a node, redacted per §9.5.

        A redacted edge is returned with its target replaced rather than
        removed: dropping it would make the graph silently wrong, and a reader
        could not tell a redacted link from a dangling one.
        """
        node = self._node_entry(path)
        if node is None:
            return {"status": 404}
        if not self.can(principal_id, path, ["read"]).allowed:
            return {"status": 403}

        manifest = self.manifest or {}
        redact_titles = (manifest.get("security") or {}).get("redact_titles") is not False
        entries_index = ((self.indexes or {}).get("nodes") or {}).get("entries") or []
        by_id = {e.get("id"): e for e in entries_index if e.get("id")}

        def visible(node_id: str) -> bool:
            target = by_id.get(node_id)
            return bool(target) and self.can(principal_id, target["path"], ["read"]).allowed

        def shape(edge: dict[str, Any], other_id: str) -> dict[str, Any]:
            other = by_id.get(other_id)
            if other is None:
                return {**edge, "target": None}
            if visible(other_id):
                return {
                    **edge,
                    "target": {
                        "id": other.get("id"),
                        "path": other.get("path"),
                        "title": other.get("title"),
                    },
                }
            return {
                **edge,
                "to": "redacted",
                "target": {
                    "id": "redacted",
                    "path": None,
                    "title": None if redact_titles else other.get("title"),
                },
            }

        link_entries = ((self.indexes or {}).get("links") or {}).get("entries") or []
        out = [
            shape(e, e["to"]) if e.get("to") else e
            for e in link_entries
            if e.get("from") == node.get("id")
        ]

        backlink_index = ((self.indexes or {}).get("backlinks") or {}).get("entries") or {}
        back = []
        for src_id in backlink_index.get(node.get("id")) or []:
            src = by_id.get(src_id)
            if src is None:
                continue
            if visible(src_id):
                back.append(
                    {"id": src.get("id"), "path": src.get("path"), "title": src.get("title")}
                )
            else:
                back.append(
                    {
                        "id": "redacted",
                        "path": None,
                        "title": None if redact_titles else src.get("title"),
                    }
                )

        return {"status": 200, "out": out, "backlinks": back}

    def search(self, principal_id: str, query: str) -> dict[str, Any]:
        """Search, filtered to readable nodes (§12.5)."""
        from .indexer import _TOKEN_RE

        terms = ((self.indexes or {}).get("search") or {}).get("terms") or {}
        entries_index = ((self.indexes or {}).get("nodes") or {}).get("entries") or []
        by_id = {e.get("id"): e for e in entries_index if e.get("id")}

        scores: dict[str, int] = {}
        for m in _TOKEN_RE.finditer(query.lower()):
            for posting in terms.get(m.group(0)) or []:
                node = by_id.get(posting.get("node"))
                if node is None:
                    continue
                if not self.can(principal_id, node["path"], ["read"]).allowed:
                    continue
                scores[posting["node"]] = scores.get(posting["node"], 0) + posting.get(
                    "tf", 0
                )

        hits = [{"score": score, **by_id[nid]} for nid, score in scores.items()]
        hits.sort(key=lambda h: (-h["score"], h["path"].encode("utf-8")))
        return {"status": 200, "hits": hits}

    def tree(self, principal_id: str) -> dict[str, Any]:
        """The navigable tree, pruned to what the principal may see (§12.3)."""
        manifest = self.manifest or {}

        def build(folder: str) -> dict[str, Any] | None:
            listing = self.list_folder(principal_id, folder)
            if listing["status"] != 200:
                return None
            record = self.folder_records.get(folder) or {}
            title = record.get("title") or (
                basename(folder.rstrip("/")) or (manifest.get("vault") or {}).get("title")
            )
            children = [build(f) for f in listing["folders"]]
            return {
                "folder": folder,
                "title": title,
                "entries": listing["entries"],
                "folders": [c for c in children if c],
            }

        return {"status": 200, "tree": build("")}

    # ---------------------------------------------------------- writing

    def mint_ids(self) -> list[dict[str, str]]:
        """Mint ids for unbound objects and persist them (§4.3).

        Frontmatter for notes, the folder's entry sidecar otherwise. A
        read-only implementation would instead surface them with ``id: null``
        and MUST NOT invent ephemeral ids, because a transient id would attach
        ACLs and links to something that ceases to exist.
        """
        minted: list[dict[str, str]] = []
        for item in self.scan():
            kind = kind_for(item.path)
            if kind == "note":
                text = item.data.decode("utf-8", errors="replace")
                if parse_note(text, item.path).id:
                    continue
                node_id = ulid()
                self.t.put(item.key, with_id(text, node_id).encode("utf-8"))
                minted.append({"path": item.path, "id": node_id, "where": "frontmatter"})
            else:
                folder = parent_folder(item.path)
                name = basename(item.path)
                sidecar = self.sidecars.get(folder)
                if not isinstance(sidecar, dict):
                    sidecar = {"entries": {}}
                entries = sidecar.get("entries")
                if not isinstance(entries, dict):
                    entries = {}
                    sidecar["entries"] = entries
                existing = entries.get(name)
                if isinstance(existing, dict) and existing.get("id"):
                    continue
                node_id = ulid()
                entry = dict(existing) if isinstance(existing, dict) else {}
                entry["id"] = node_id
                entries[name] = entry
                self.sidecars[folder] = sidecar
                key = f"{META}folders/{folder}entries.yaml"
                self.t.put(key, self._rewrite_sidecar(key, sidecar).encode("utf-8"))
                minted.append({"path": item.path, "id": node_id, "where": "sidecar"})
        return minted

    def _rewrite_sidecar(self, key: str, sidecar: dict[str, Any]) -> str:
        """Serialize a sidecar, preserving the comments of an existing file (§13.4)."""
        existing = self._text(key)
        if existing is None:
            return yamlio.dump(sidecar)

        def mutate(doc: Any) -> Any:
            if not isinstance(doc, dict):
                return sidecar
            entries = doc.get("entries")
            if not isinstance(entries, dict):
                doc["entries"] = sidecar.get("entries", {})
                return doc
            for name, entry in (sidecar.get("entries") or {}).items():
                current = entries.get(name)
                if isinstance(current, dict):
                    for k, v in entry.items():
                        current[k] = v
                else:
                    entries[name] = entry
            return doc

        return yamlio.edit(existing, mutate)


#: Crockford base32, lowercase (§4.1).
_B32 = "0123456789abcdefghjkmnpqrstvwxyz"


def ulid(now_ms: int | None = None) -> str:
    """A ULID (§4.1): 48-bit timestamp, 80 bits of randomness, Crockford base32.

    Node ids are opaque: §4.1 forbids parsing meaning out of them beyond the
    timestamp prefix and forbids assuming they sort in creation order across
    machines.
    """
    ms = int(time.time() * 1000) if now_ms is None else now_ms
    out = []
    t = ms
    for _ in range(10):
        out.append(_B32[t % 32])
        t //= 32
    time_part = "".join(reversed(out))
    rand = "".join(_B32[b % 32] for b in os.urandom(16))
    return (time_part + rand)[:26]


def random_ulid() -> str:
    """A ULID whose randomness comes from :mod:`secrets`."""
    ms = int(time.time() * 1000)
    out = []
    t = ms
    for _ in range(10):
        out.append(_B32[t % 32])
        t //= 32
    time_part = "".join(reversed(out))
    rand = "".join(_B32[secrets.randbelow(32)] for _ in range(16))
    return (time_part + rand)[:26]


__all__ = [
    "ABSENT",
    "INDEX_KEYS",
    "INDEX_KINDS",
    "EmptyIndexRefused",
    "IndexState",
    "ReadResult",
    "Vault",
    "random_ulid",
    "ulid",
]
