"""Local filesystem transport, PROTOCOL §1.

A vault on disk is a plain folder: ``content/`` is openable in Obsidian, a
text editor, ripgrep or git with no knowledge of this protocol (§3). A
filesystem satisfies all five operations trivially.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
from pathlib import Path
from typing import Any

from ..keys import validate_key
from . import UNSET, Listing, PreconditionFailed, Stat, Transport

#: Names skipped when listing: in-flight writes and editor/VCS droppings that
#: are not part of the vault.
_SKIP_NAMES = frozenset({".DS_Store", ".git"})


class LocalTransport(Transport):
    """A vault rooted at a local directory."""

    capabilities = frozenset({"conditional_put", "range_get", "batch_delete"})

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root).resolve()

    def _resolve(self, key: str) -> Path:
        """Map a key to an absolute path, refusing anything that escapes the root.

        :func:`validate_key` already rejects ``..`` segments, but a transport
        is the last line of defense and a path-traversal bug here reads the
        whole disk.
        """
        p = (self.root / key).resolve()
        if p != self.root and self.root not in p.parents:
            raise ValueError(f"key escapes vault root: {key!r}")
        return p

    # ------------------------------------------------------------- reads

    def get(self, key: str) -> bytes | None:
        try:
            return self._resolve(key).read_bytes()
        except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
            return None

    def stat(self, key: str) -> Stat | None:
        try:
            p = self._resolve(key)
            st = p.stat()
        except (FileNotFoundError, NotADirectoryError):
            return None
        if not p.is_file():
            return None
        # No cheap server-side etag on a filesystem, so hash the bytes. §10.1
        # treats content_hash as authoritative precisely because etags are not
        # comparable across stores.
        digest = hashlib.md5(p.read_bytes(), usedforsecurity=False).hexdigest()
        mtime = dt.datetime.fromtimestamp(st.st_mtime, dt.UTC)
        return Stat(
            size=st.st_size,
            etag=f'"{digest}"',
            mtime=mtime.isoformat().replace("+00:00", "Z"),
        )

    def list(
        self,
        prefix: str = "",
        *,
        delimiter: str | None = None,
        cursor: str | None = None,
    ) -> Listing:
        keys: list[str] = []
        prefixes: dict[str, None] = {}

        def walk(rel: str) -> None:
            abs_dir = self._resolve(rel) if rel else self.root
            try:
                entries = sorted(os.scandir(abs_dir), key=lambda e: e.name)
            except (FileNotFoundError, NotADirectoryError):
                return
            for entry in entries:
                if entry.name.endswith(".tmp") or entry.name in _SKIP_NAMES:
                    continue
                key = f"{rel}/{entry.name}" if rel else entry.name
                if entry.is_dir():
                    # Prune subtrees that cannot contain the prefix.
                    if not (key + "/").startswith(prefix) and not prefix.startswith(
                        key + "/"
                    ):
                        continue
                    walk(key)
                elif entry.is_file() and key.startswith(prefix):
                    if delimiter:
                        rest = key[len(prefix) :]
                        i = rest.find(delimiter)
                        if i != -1:
                            prefixes[prefix + rest[: i + 1]] = None
                            continue
                    keys.append(key)

        walk("")
        return Listing(keys=keys, prefixes=list(prefixes))

    # ------------------------------------------------------------ writes

    def put(
        self,
        key: str,
        data: bytes,
        *,
        if_match: Any = UNSET,
        content_type: str | None = None,
    ) -> Stat:
        validate_key(key)
        p = self._resolve(key)
        if if_match is not UNSET:
            current = self.stat(key)
            if if_match != (current.etag if current else None):
                raise PreconditionFailed(f"precondition failed for {key!r}")
        p.parent.mkdir(parents=True, exist_ok=True)
        # Write to a temp file and rename, so a reader never sees a
        # half-written object — §1 promises read-after-write for a single key.
        tmp = p.with_name(f"{p.name}.{os.getpid()}.{os.urandom(4).hex()}.tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)
        stat = self.stat(key)
        assert stat is not None  # just written
        return stat

    def delete(self, key: str) -> None:
        """Remove one key, reporting nothing about whether it was there (§1.2).

        A filesystem *can* answer cheaply — ``unlink`` raises
        ``FileNotFoundError`` and the boolean is right there — and §1.2 names
        that as exactly the trap. Returning it here would make this transport
        disagree with the S3 one on the same call, so the information is
        discarded deliberately rather than for want of access to it.
        """
        try:
            self._resolve(key).unlink()
        except (FileNotFoundError, NotADirectoryError):
            # Both mean there is no object at this key, which is a successful
            # delete under §1.2's idempotence.
            return


__all__ = ["LocalTransport"]
