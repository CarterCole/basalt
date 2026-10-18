"""In-memory transport, PROTOCOL §1.

Useful for tests and for building an export (§12.6) before deciding where to
put it. §1 names a zip file, a Postgres large-object table and an IPFS pin
set as equally valid substrates; a dict is the smallest of them.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from typing import Any

from ..keys import validate_key
from . import UNSET, Listing, PreconditionFailed, Stat, Transport


class MemoryTransport(Transport):
    """A vault held in a dict."""

    capabilities = frozenset({"conditional_put", "range_get", "batch_delete"})

    def __init__(self, objects: dict[str, bytes] | None = None) -> None:
        self.objects: dict[str, bytes] = dict(objects or {})
        self.mtimes: dict[str, str] = {}
        now = _now()
        for key in self.objects:
            self.mtimes[key] = now

    def get(self, key: str) -> bytes | None:
        return self.objects.get(key)

    def stat(self, key: str) -> Stat | None:
        data = self.objects.get(key)
        if data is None:
            return None
        digest = hashlib.md5(data, usedforsecurity=False).hexdigest()
        return Stat(size=len(data), etag=f'"{digest}"', mtime=self.mtimes.get(key))

    def put(
        self,
        key: str,
        data: bytes,
        *,
        if_match: Any = UNSET,
        content_type: str | None = None,
    ) -> Stat:
        validate_key(key)
        if if_match is not UNSET:
            current = self.stat(key)
            if if_match != (current.etag if current else None):
                raise PreconditionFailed(f"precondition failed for {key!r}")
        self.objects[key] = bytes(data)
        self.mtimes[key] = _now()
        stat = self.stat(key)
        assert stat is not None
        return stat

    def delete(self, key: str) -> None:
        """Remove one key, reporting nothing about whether it was there (§1.2)."""
        self.mtimes.pop(key, None)
        self.objects.pop(key, None)

    def list(
        self,
        prefix: str = "",
        *,
        delimiter: str | None = None,
        cursor: str | None = None,
    ) -> Listing:
        keys: list[str] = []
        prefixes: dict[str, None] = {}
        for key in self.objects:
            if not key.startswith(prefix):
                continue
            if delimiter:
                rest = key[len(prefix) :]
                i = rest.find(delimiter)
                if i != -1:
                    prefixes[prefix + rest[: i + 1]] = None
                    continue
            keys.append(key)
        return Listing(keys=keys, prefixes=list(prefixes))


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


__all__ = ["MemoryTransport"]
