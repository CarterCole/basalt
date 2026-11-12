"""Moving folders to and from GitHub gists: ``basalt gist export`` and
``basalt gist import``.

These are copies between a vault, in whatever store it lives, and one gist.
They are not sync: nothing is merged, and an import never overwrites.

- **export** reads a folder of the vault and writes its text files to a gist.
  A gist is flat, so a file's path inside the folder becomes one file name
  (:func:`~basalt.transport.gist.encode_name`). Anything a gist cannot hold, a
  binary file or an empty one, is left out and reported by name, never dropped
  silently.
- **import** reads every file of a gist and stores each as a NEW object under a
  folder of the vault (§12.7): it gets an id, and is refused, not replaced, if
  the path is taken. Notes keep their text, and take a new id.

Exporting sends notes to GitHub. A secret gist is unlisted, not private: anyone
with its URL can read it, and ``audience: private`` in ``basalt.yaml`` is
enforced by a basalt server, not by GitHub. So secret is the default, public
has to be asked for, and ``dry_run`` says what would be sent before it is.

The TypeScript reference's ``gist.mjs``, ported.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .keys import CONTENT, is_valid_key, key_to_path, sort_utf8
from .store import Provenance, Stored, store_object
from .transport.gist import (
    MAX_GIST_FILES,
    GistApi,
    GistError,
    decode_name,
    encode_name,
    why_not_text,
)

_MAX_NAME_BYTES = 255
DEFAULT_DESCRIPTION = "Exported from a Basalt vault"


def folder_path(value: str | None) -> str:
    """``Notes`` → ``Notes/``; ``/`` or ``""`` → ``""`` (the whole vault)."""
    f = (value or "").lstrip("/")
    return f if f == "" or f.endswith("/") else f + "/"


@dataclass
class PickedFile:
    name: str
    path: str
    data: bytes


@dataclass
class Picked:
    #: In name order.
    files: list[PickedFile] = field(default_factory=list)
    #: The ones a gist cannot hold, as ``{"path", "reason"}`` with a reason of
    #: ``empty``, ``not_text``, ``name_too_long`` or ``invalid_key``.
    skipped: list[dict[str, str]] = field(default_factory=list)
    #: How many a principal may not read (not named, since naming them would tell).
    withheld: int = 0


def collect(vault: Any, *, folder: str = "", whole: bool = False, principal: str | None = None) -> Picked:
    """What a folder (or, with ``whole``, every key) would send."""
    prefix = "" if whole else CONTENT + folder
    out = Picked()
    for key in sort_utf8([k for k in vault.t.list(prefix).keys if k.startswith(prefix)]):
        path = key if whole else key_to_path(key)
        assert path is not None
        # A key §1.1 forbids (a decomposed macOS file name, say) is not an object
        # of the vault: it is in no index. Say so, rather than send or lose it.
        if not is_valid_key(key):
            out.skipped.append({"path": path, "reason": "invalid_key"})
            continue
        if principal is not None and not vault.can(principal, key_to_path(key) or key, ["read"]).allowed:
            out.withheld += 1
            continue
        data = vault.t.get(key)
        if data is None:
            continue  # raced with a delete
        why = why_not_text(data)
        if why:
            out.skipped.append({"path": path, "reason": why})
            continue
        name = encode_name(key if whole else path[len(folder) :])
        if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
            out.skipped.append({"path": path, "reason": "name_too_long"})
            continue
        out.files.append(PickedFile(name=name, path=path, data=bytes(data)))
    return out


@dataclass
class ExportResult:
    count: int = 0
    skipped: list[dict[str, str]] = field(default_factory=list)
    withheld: int = 0
    names: list[str] = field(default_factory=list)
    bytes: int = 0
    public: bool = False
    dry_run: bool = False
    id: str | None = None
    url: str | None = None
    #: A new gist was made.
    created: bool = False
    #: An existing gist was written to, and something changed.
    updated: bool = False
    written: int = 0
    removed: int = 0
    unchanged: int = 0
    #: The gist's files the export does not have, and ``--prune`` did not remove.
    left: list[str] = field(default_factory=list)


def export_to_gist(
    vault: Any,
    *,
    api: GistApi,
    folder: str = "",
    whole: bool = False,
    update: str | None = None,
    prune: bool = False,
    public: bool = False,
    description: str | None = None,
    principal: str | None = None,
    dry_run: bool = False,
) -> ExportResult:
    """Send a folder (or, with ``whole``, every key of the vault, which makes a
    gist that ``--gist ID`` can open as a vault) to a gist.

    ``update`` writes into an existing gist rather than a new one; ``prune``
    then also removes the gist's files the export does not have. ``public``
    chooses the visibility of a NEW gist: GitHub does not let a gist change
    sides. ``principal`` sends only what that principal may read. ``dry_run``
    works out what would go and sends nothing."""
    if whole and principal is not None:
        raise RuntimeError(
            "--whole copies the vault as it is, ACLs and all; it is for the operator, "
            "so it does not take --principal"
        )
    if update and public:
        raise RuntimeError(
            "--public chooses the visibility of a NEW gist; a gist cannot change sides, "
            "so it does not go with --update"
        )
    if prune and not update:
        raise RuntimeError("--prune is for --update")

    picked = collect(vault, folder=folder, whole=whole, principal=principal)
    base = ExportResult(
        count=len(picked.files),
        skipped=picked.skipped,
        withheld=picked.withheld,
        names=[f.name for f in picked.files],
        bytes=sum(len(f.data) for f in picked.files),
    )
    if not picked.files:
        what = "the vault" if whole or folder == "" else folder
        raise RuntimeError(
            f"nothing to export from {what}"
            + (f" ({len(picked.skipped)} file(s) are not text a gist can hold)" if picked.skipped else "")
        )
    if len(picked.files) > MAX_GIST_FILES:
        raise RuntimeError(
            f"{len(picked.files)} files is more than a gist shows ({MAX_GIST_FILES}); "
            "export a smaller folder"
        )
    if dry_run:
        base.dry_run = True
        base.public = bool(public)
        return base

    text = {f.name: f.data.decode("utf-8") for f in picked.files}

    if not update:
        g = api.create(
            files=text,
            description=DEFAULT_DESCRIPTION if description is None else description,
            public=public,
        )
        base.id, base.url, base.public, base.created = g.id, g.url, g.public, True
        return base

    g = api.get(update)
    if g.truncated:
        raise GistError(
            "too_big",
            f"gist {update} has more than {MAX_GIST_FILES} files, "
            "which the API will not list, so it cannot be updated safely",
        )
    changes: dict[str, str | None] = {}
    unchanged = 0
    for name, content in text.items():
        had = g.files.get(name)
        if had is not None and had.content is not None and had.content.decode("utf-8") == content:
            unchanged += 1
        else:
            changes[name] = content
    extra = [n for n in g.files if n not in text]
    if prune:
        for n in extra:
            changes[n] = None
    written = sum(1 for c in changes.values() if c is not None)
    removed = sum(1 for c in changes.values() if c is None)
    base.id, base.url, base.public = g.id, g.url, g.public
    base.written, base.removed, base.unchanged = written, removed, unchanged
    base.left = [] if prune else extra
    if not written and not removed and description is None:
        return base
    after = api.update(update, files=changes, description=description)
    base.updated = True
    base.url = after.url or g.url
    return base


@dataclass
class ImportResult:
    gist: dict[str, Any]
    stored: list[Stored] = field(default_factory=list)
    refused: list[dict[str, str]] = field(default_factory=list)


def import_from_gist(
    vault: Any,
    *,
    api: GistApi,
    id: str,
    to: str,
    principal: str | None = None,
    provenance: Provenance | None = None,
    log: Callable[[Stored, str], None] | None = None,
) -> ImportResult:
    """Store every file of a gist as a new object under ``to``.

    One file that cannot be stored (a taken path, a name that is not a valid
    path, a principal without ``create_child``) is reported and the rest still
    go. On a git store the whole import is one commit."""
    g = api.get(id)
    if g.truncated:
        raise GistError(
            "too_big",
            f"gist {id} has more than {MAX_GIST_FILES} files, which the API will not list; "
            "clone it with git and add the files instead",
        )
    out = ImportResult(
        gist={"id": g.id, "url": g.url, "public": g.public, "description": g.description}
    )
    names = sort_utf8(list(g.files))
    if not names:
        return out

    def message(_keys: list[str]) -> str:
        n = len(out.stored)
        return f"Import {n} file{'' if n == 1 else 's'} from gist {g.id}"

    trailers = {"Basalt-Source": f"gist:{g.id}"}
    if principal:
        trailers = {"Basalt-Principal": principal, **trailers}
    with vault.batch(message=message, trailers=trailers):
        for name in names:
            rel = unicodedata.normalize("NFC", decode_name(name))
            try:
                data = api.content(g.files[name])
                r = store_object(
                    vault, path=to + rel, data=data, principal=principal,
                    provenance=provenance, reindex=False,
                )
                out.stored.append(r)
                if log:
                    log(r, name)
            except Exception as err:
                out.refused.append({"name": name, "error": str(err)})
        if out.stored:
            vault.reindex(write=True)
    return out


__all__ = [
    "DEFAULT_DESCRIPTION",
    "ExportResult",
    "ImportResult",
    "Picked",
    "PickedFile",
    "collect",
    "export_to_gist",
    "folder_path",
    "import_from_gist",
]
