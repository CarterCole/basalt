"""Creating objects, PROTOCOL §12.7 — storing a note, an image or any other file.

Create-only on purpose. Replacing or deleting an object destroys work, and
§11 (history) is what makes that recoverable; until a vault has history, the
only write that cannot lose anything is one that refuses to touch an object
that already exists.

What a store has to get right, in the order it happens:

1. The path must be one a reader can address: a valid key (§1.1), not a name
   the filesystem transport skips, not under a withheld tree (§12.4), and not
   colliding with anything already there (§2.2).
2. The principal needs ``create_child`` on the folder (§8.1). A note carrying
   its own inline ACL also needs ``write_acl``, because an inline ACL replaces
   the folder file's entry (§8.6).
3. The object gets an identity at birth (§4.3): a frontmatter id for a note,
   an entry sidecar (§6.1) for anything else. The same place records who
   stored it (``created_by``).
4. The indexes are rebuilt and persisted, so the vault is exactly as fresh
   after a store as before it.

The conformance corpus holds the cases (``cases/store/creation.yaml``); the
TypeScript and Rust implementations run the same file.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any

from ruamel.yaml.comments import CommentedMap

from . import yamlio
from .frontmatter import kind_for, parse_note, split_frontmatter
from .keys import (
    CONTENT,
    META,
    KeyError_,
    basename,
    find_collisions,
    find_folder_case_divergence,
    parent_folder,
    path_to_key,
    validate_key,
)
from .transport import PreconditionFailed

#: The largest object a store accepts: a bound, not a recommendation.
MAX_STORE_BYTES = 25 * 1024 * 1024

_MAX_LABEL = 1000
_MAX_SEGMENT_BYTES = 255
_MAX_CLIENT_FIELD = 100
_MAX_CALLER_IN = 2048
_MAX_CALLER = 512

#: Names the filesystem transport's listing skips: stored, they would vanish.
_INVISIBLE = frozenset({".git", ".DS_Store"})
#: Trees no surface serves (§12.4).
WITHHELD = ("meta/", "index/", "principals/", "history/", "basalt.yaml")

_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}")
_CALLER = re.compile(r"[A-Za-z0-9+=,._/:-]+")
_CONTROL = re.compile("[\u0000-\u001f\u007f-\u009f\u2028\u2029]")

_MEDIA = {
    ".md": "text/markdown; charset=utf-8",
    ".markdown": "text/markdown; charset=utf-8",
    ".json": "application/json",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8",
}


def media_for(path: str) -> str:
    name = basename(path)
    i = name.rfind(".")
    return _MEDIA.get(name[i:].lower() if i > 0 else "", "application/octet-stream")


class StoreFault(Exception):
    """A refusal, with the fault code and HTTP status the other surfaces use."""

    def __init__(self, code: str, status: int, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.status = status
        self.detail = detail


def _bad(detail: str) -> StoreFault:
    return StoreFault("bad_request", 400, detail)


def _conflict(detail: str) -> StoreFault:
    return StoreFault("conflict", 409, detail)


@dataclass
class Provenance:
    """Who is behind a write (§12.7 item 5).

    ``agent`` and ``account`` are the operator's labels; ``caller`` is what the
    store named for the credentials; ``client`` is the connection's own
    ``{"name", "version"}`` claim. None of them comes from the request's
    arguments or content.
    """

    agent: str | None = None
    account: str | None = None
    caller: str | None = None
    client: dict[str, Any] | None = None


def check_provenance_label(name: str, value: Any) -> str | None:
    """An operator's name for an agent or account: ``claude-code``, ``work``.

    No ``@``, so an email address cannot be pasted into a file that may be
    shared or published.
    """
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise _bad(
            f'{name} must be a short label such as "work" or "claude-code" '
            "(letters, digits and . _ : / -, at most 64), not an email address or a token"
        )
    return value


def normalize_caller(value: Any) -> str | None:
    """The store's name for the credentials behind a write, fit to keep.

    Any ``/``- or ``:``-separated segment holding an ``@`` becomes ``sha256:``
    and the first 16 hex digits of the hash of the lowercased segment;
    anything left outside the ARN alphabet is refused.
    """
    if value is None or value == "":
        return None
    if not isinstance(value, str) or len(value) > _MAX_CALLER_IN:
        raise _bad("caller must be a store identity such as an AWS ARN")

    def hide(m: re.Match[str]) -> str:
        seg = m.group(0)
        if "@" not in seg:
            return seg
        return "sha256:" + hashlib.sha256(seg.lower().encode("utf-8")).hexdigest()[:16]

    out = re.sub(r"[^/:]+", hide, value)
    if not _CALLER.fullmatch(out) or len(out) > _MAX_CALLER:
        raise _bad(
            "caller must be a store identity such as an AWS ARN "
            "(letters, digits and + = , . _ / : -, at most 512)"
        )
    return out


def clean_client_field(value: Any) -> str | None:
    """A client-reported string, made safe to keep: printable, one line, bounded."""
    if not isinstance(value, str):
        return None
    s = " ".join(_CONTROL.sub(" ", value).split())[:_MAX_CLIENT_FIELD].strip()
    return s or None


def now_seconds() -> str:
    """RFC 3339 UTC to the second, the form ``created_by.at`` takes."""
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_created_by(principal: str | None, p: Provenance, at: str | None = None) -> dict[str, Any]:
    """The ``created_by`` record (§12.7), as the ordered mapping that is written."""
    by: dict[str, Any] = {}
    if principal:
        by["principal"] = principal
    agent = check_provenance_label("agent", p.agent)
    if agent:
        by["agent"] = agent
    account = check_provenance_label("account", p.account)
    if account:
        by["account"] = account
    caller = normalize_caller(p.caller)
    if caller:
        by["caller"] = caller
    client = p.client or {}
    name = clean_client_field(client.get("name"))
    if name:
        version = clean_client_field(client.get("version"))
        by["client"] = {"name": name, **({"version": version} if version else {})}
    by["at"] = at or now_seconds()
    return by


def commit_trailers(principal: str | None, p: Provenance | None) -> dict[str, str]:
    """Git trailers naming who stored an object, from the same labels."""
    t: dict[str, str] = {}
    if principal:
        t["Basalt-Principal"] = principal

    def label(name: str, v: Any) -> str | None:
        try:
            return check_provenance_label(name, v)
        except StoreFault:
            return None

    if p is None:
        return t
    agent = label("agent", p.agent)
    if agent:
        t["Basalt-Agent"] = agent
    account = label("account", p.account)
    if account:
        t["Basalt-Account"] = account
    client = p.client or {}
    name = clean_client_field(client.get("name"))
    if name:
        version = clean_client_field(client.get("version"))
        t["Basalt-Client"] = f"{name} {version}" if version else name
    return t


@dataclass
class Stored:
    path: str
    id: str
    kind: str
    media_type: str
    size: int
    content_hash: str
    created: bool = True
    created_by: dict[str, Any] | None = field(default=None)

    def as_dict(self) -> dict[str, Any]:
        out = {
            "path": self.path,
            "id": self.id,
            "kind": self.kind,
            "media_type": self.media_type,
            "size": self.size,
            "content_hash": self.content_hash,
            "created": True,
        }
        if self.created_by is not None:
            out["created_by"] = self.created_by
        return out


def _check_path(path: Any) -> str:
    if not isinstance(path, str) or path == "":
        raise _bad("path is required")
    key = path_to_key(path)
    try:
        validate_key(key)
    except KeyError_ as err:
        raise _bad(f"not a valid path: {err.code}") from err
    for seg in path.split("/"):
        if seg in _INVISIBLE or seg.endswith(".tmp"):
            raise _bad(f'"{seg}" is a name the filesystem transport skips when listing')
        if len(seg.encode("utf-8")) > _MAX_SEGMENT_BYTES:
            raise _bad(f"a path segment is longer than {_MAX_SEGMENT_BYTES} bytes")
    if any(path == p or path.startswith(p) for p in WITHHELD):
        raise _bad("that path is under a tree no surface serves (§12.4)")
    return key


def _check_label(name: str, value: Any) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise _bad(f"{name} must be a string")
    if len(value) > _MAX_LABEL:
        raise _bad(f"{name} is longer than {_MAX_LABEL} characters")
    return value.strip() or None


def _authorize(vault: Any, principal: str, folder: str, rights: list[str], what: str) -> None:
    """§12.3's rule for a write: undiscoverable is not found, else forbidden."""
    if vault.can(principal, folder, rights).allowed:
        return
    if vault.can(principal, folder, ["list"]).allowed:
        raise StoreFault("forbidden", 403, what)
    raise StoreFault("not_found", 404)


def stamp_note(text: str, node_id: str, *, title: str | None, created_by: dict[str, Any] | None) -> str:
    """Set ``basalt.id`` (and ``basalt.created_by``) and fill in ``title``.

    An ``id`` or ``created_by`` already in the block is replaced, never kept:
    a supplied one would attach another node's identity or let a writer name
    its own author. ``title`` is the author's key, so it is only ever added.
    Comments and key order survive (§13.4).
    """
    split = split_frontmatter(text)
    if split.raw is None:
        doc: dict[str, Any] = {"basalt": {"id": node_id}}
        if created_by:
            doc["basalt"]["created_by"] = created_by
        if title:
            doc["title"] = title
        return f"---\n{yamlio.dump(doc).rstrip()}\n---\n{text}"

    def mutate(doc: Any) -> Any:
        if not isinstance(doc, dict):
            raise _bad("the frontmatter is not a YAML mapping")
        block = doc.get("basalt")
        if not isinstance(block, dict):
            block = CommentedMap()
            if isinstance(doc, CommentedMap):
                doc.insert(0, "basalt", block)
            else:
                doc["basalt"] = block
        if hasattr(block, "fa"):
            block.fa.set_block_style()
        block["id"] = node_id
        if created_by:
            block["created_by"] = created_by
        if title and "title" not in doc:
            doc["title"] = title
        return doc

    try:
        rewritten = yamlio.edit(split.raw, mutate).rstrip("\n")
    except yamlio.CommentsWouldBeLost as err:
        raise _bad(f"the frontmatter is not valid YAML: {err}") from err
    return f"---\n{rewritten}\n---\n{split.body}"


def _add_sidecar_entry(vault: Any, folder: str, name: str, entry: dict[str, Any]) -> None:
    """Read-modify-write one folder's entry sidecar, conditional on its etag.

    This file is shared by every asset in the folder, and last-write-wins on
    it would silently unbind somebody else's object (§11.3).
    """
    key = f"{META}folders/{folder}entries.yaml"
    for _ in range(4):
        st = vault.t.stat(key)
        data = vault.t.get(key) if st else None
        if data is None:
            text = yamlio.dump({"entries": {name: entry}})
        else:

            def mutate(doc: Any) -> Any:
                if doc is None:
                    doc = CommentedMap()
                if not isinstance(doc, dict):
                    raise StoreFault(
                        "internal", 500, f"{key} is not a valid entries file; fix or remove it"
                    )
                entries = doc.get("entries")
                if not isinstance(entries, dict):
                    entries = CommentedMap()
                    doc["entries"] = entries
                elif not entries and hasattr(entries, "fa"):
                    # A hand-written `entries: {}` is a flow map; open it up so
                    # what is added does not print as one unbroken line.
                    entries.fa.set_block_style()
                # An entry already named here belongs to an object that is gone
                # (the caller checked); §6.1 prunes those. Replace it.
                if name in entries:
                    del entries[name]
                entries[name] = entry
                return doc

            try:
                text = yamlio.edit(data.decode("utf-8"), mutate)
            except (UnicodeDecodeError, yamlio.CommentsWouldBeLost) as err:
                raise StoreFault(
                    "internal", 500, f"{key} is not a valid entries file; fix or remove it"
                ) from err
        try:
            vault.t.put(
                key,
                text.encode("utf-8"),
                if_match=st.etag if st else None,
                content_type="text/yaml",
            )
        except PreconditionFailed:
            continue
        return
    raise _conflict(f"{key} kept changing underneath this store; try again")


_LOCKS: weakref.WeakKeyDictionary[Any, threading.RLock] = weakref.WeakKeyDictionary()
_LOCKS_GUARD = threading.Lock()


def _lock_for(vault: Any) -> threading.RLock:
    with _LOCKS_GUARD:
        lock = _LOCKS.get(vault)
        if lock is None:
            lock = _LOCKS[vault] = threading.RLock()
        return lock


def store_object(
    vault: Any,
    *,
    path: Any,
    data: Any,
    principal: str | None = None,
    title: Any = None,
    alt: Any = None,
    provenance: Provenance | None = None,
    reindex: bool = True,
    max_bytes: int = MAX_STORE_BYTES,
) -> Stored:
    """Store one new object.

    ``principal=None`` is the operator, who holds the vault's credentials and
    is not subject to §8. ``provenance`` given (even empty) stamps the object
    ``created_by``. On a store that keeps history (git) the object, its
    sidecar and the refreshed indexes are one commit.
    """
    message = f"Add {path if isinstance(path, str) else 'an object'}"
    with _lock_for(vault), vault.batch(message=message, trailers=commit_trailers(principal, provenance)):
        return _store(vault, path, data, principal, title, alt, provenance, reindex, max_bytes)


def _store(
    vault: Any,
    path: Any,
    data: Any,
    principal: str | None,
    title: Any,
    alt: Any,
    provenance: Provenance | None,
    reindex: bool,
    max_bytes: int,
) -> Stored:
    # Principals, ACLs and sidecars are re-read on every write: a long-lived
    # process must not honour a grant revoked since it started (item 3).
    vault.reload()
    key = _check_path(path)
    kind = kind_for(path)
    folder = parent_folder(path)
    name = basename(path)
    title = _check_label("title", title)
    alt = _check_label("alt", alt)
    created_by = build_created_by(principal, provenance) if provenance is not None else None

    if not isinstance(data, (bytes, bytearray)):
        raise _bad("content is required")
    data = bytes(data)
    if len(data) > max_bytes:
        raise StoreFault("too_large", 413, f"{len(data)} bytes is over the {max_bytes} byte limit")
    if kind != "note" and folder == "":
        raise _bad('files other than notes must live in a folder, e.g. "Assets/"')

    text: str | None = None
    if kind in ("note", "data"):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as err:
            raise _bad(
                f"{name} must be valid UTF-8 text; store binary data under another extension"
            ) from err

    # --- authorization (§8)
    if principal is not None:
        _authorize(vault, principal, folder, ["create_child"], "create_child is required")
        if kind == "note" and parse_note(text or "", path).acl is not None:
            _authorize(
                vault, principal, folder, ["write_acl"],
                "frontmatter sets basalt.acl, which needs write_acl",
            )

    # --- collisions (§2.2)
    existing = [k for k in vault.t.list(CONTENT).keys if k.startswith(CONTENT)]
    if key in existing:
        raise _conflict(f"{path} already exists; stores never overwrite")
    for group in find_collisions([*existing, key]):
        if key in group:
            other = next(k for k in group if k != key)
            raise _conflict(
                f"{path} collides with {other[len(CONTENT):]} once case and "
                "Unicode normalization are folded (§2.2)"
            )
    segments = key.split("/")
    present = set(existing)
    for i in range(2, len(segments)):
        prefix = "/".join(segments[:i])
        if prefix in present:
            raise _conflict(f"{prefix[len(CONTENT):]} is a file, so it cannot also be a folder")
    if any(k.startswith(key + "/") for k in existing):
        raise _conflict(f"{path} is a folder")
    if find_folder_case_divergence(existing) != find_folder_case_divergence([*existing, key]):
        raise _conflict(f"a folder in {path} differs only in case from an existing one (§2.2)")

    # --- identity (§4.3)
    from .vault import ulid  # here, not at the top: vault imports this module

    node_id = ulid()
    content = data
    if kind == "note":
        content = stamp_note(text or "", node_id, title=title, created_by=created_by).encode("utf-8")

    # --- write: content first, then the sidecar, then the indexes (item 7)
    try:
        vault.t.put(key, content, if_match=None, content_type=media_for(path))
    except PreconditionFailed as err:
        raise _conflict(f"{path} was created by someone else just now") from err

    if kind != "note":
        entry: dict[str, Any] = {"id": node_id}
        if title:
            entry["title"] = title
        if alt:
            entry["alt"] = alt
        if created_by:
            entry["created_by"] = created_by
        try:
            _add_sidecar_entry(vault, folder, name, entry)
        except StoreFault as err:
            hint = f"{path} was stored but is unbound; run `basalt mint`"
            raise StoreFault(err.code, err.status, f"{err.detail} ({hint})" if err.detail else hint) from err
        vault.reload()

    if reindex:
        try:
            vault.reindex(write=True)
        except Exception as err:
            raise StoreFault(
                "internal", 500,
                f"{path} was stored, but refreshing the indexes failed: {err}. "
                "Run `basalt index --write`.",
            ) from err

    return Stored(
        path=path,
        id=node_id,
        kind=kind,
        media_type=media_for(path),
        size=len(content),
        content_hash="sha256:" + hashlib.sha256(content).hexdigest(),
        created_by=created_by,
    )


__all__ = [
    "MAX_STORE_BYTES",
    "Provenance",
    "StoreFault",
    "Stored",
    "build_created_by",
    "check_provenance_label",
    "clean_client_field",
    "commit_trailers",
    "media_for",
    "normalize_caller",
    "stamp_note",
    "store_object",
]
