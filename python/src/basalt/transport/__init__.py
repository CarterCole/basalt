"""The substrate, PROTOCOL §1.

A transport is an adapter over a flat key-value blob namespace. It MUST
provide exactly these five operations — ``get``, ``put``, ``delete``,
``list``, ``stat`` — and MAY provide the optional capabilities it declares.

What a transport is explicitly *not* asked for (§1): server-side ACLs,
directories, atomic multi-key transactions, sorted range scans beyond prefix
matching, or per-object metadata beyond the three ``stat`` fields. Those are
the capabilities S3-like stores disagree about, so the protocol builds over
the intersection, not the union.

**Consistency.** The protocol assumes only read-after-write for a single key
and eventual consistency for ``list``. An implementation MUST NOT depend on
``list`` reflecting a ``put`` that has just returned, which is why index
freshness is established by digest (§10.6) and never by listing order or
timestamps.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, Final

#: Sentinel distinguishing "no precondition" from ``if_match=None``, which
#: §11.3 uses to mean if-none-match (create only).
UNSET: Final[Any] = object()

#: The optional capabilities a transport may declare (§1).
CAPABILITIES = frozenset(
    {"presign", "conditional_put", "range_get", "versioning", "batch_delete"}
)


class PreconditionFailed(RuntimeError):
    """A conditional put whose etag precondition did not hold (§11.3).

    §11.3: a failed condition MUST surface as a conflict rather than being
    retried blindly — last-write-wins on a knowledge vault silently destroys
    work.
    """

    code = "PRECONDITION_FAILED"


@dataclass(frozen=True)
class Stat:
    """Metadata without the body: the only three fields §1 permits."""

    size: int
    etag: str | None = None
    mtime: str | None = None


@dataclass(frozen=True)
class Listing:
    """The result of ``list``: keys, common prefixes, and a pagination cursor."""

    keys: list[str] = field(default_factory=list)
    prefixes: list[str] = field(default_factory=list)
    cursor: str | None = None


class Transport(abc.ABC):
    """The five-operation contract of §1."""

    #: Optional capabilities this transport provides, declared in the
    #: manifest under ``transport.capabilities`` (§3.1).
    capabilities: frozenset[str] = frozenset()

    @abc.abstractmethod
    def get(self, key: str) -> bytes | None:
        """Whole-object read. ``None`` when the key does not exist."""

    @abc.abstractmethod
    def put(
        self,
        key: str,
        data: bytes,
        *,
        if_match: Any = UNSET,
        content_type: str | None = None,
    ) -> Stat:
        """Create or replace, atomic per key.

        ``if_match`` requires the ``conditional_put`` capability: an etag
        string demands that etag, and ``None`` demands the key not exist.
        """

    @abc.abstractmethod
    def delete(self, key: str) -> None:
        """Remove one key. Idempotent, and it tells you nothing (§1.2).

        §1.2 is explicit: ``delete`` returns no information about whether the
        key existed, implementations MUST NOT report prior existence from it,
        and callers MUST NOT branch on anything it returns. S3's
        ``DeleteObject`` answers 204 whether or not the key was there and
        MinIO and R2 match it, so a boolean would mean one thing on a
        filesystem and another in a bucket — the trap §1.2 names, since an
        implementation developed only against a filesystem exposes a boolean
        that silently becomes wrong the day the vault moves to a bucket.

        To learn whether a key exists, call :meth:`stat` and accept that the
        answer is already stale.
        """

    @abc.abstractmethod
    def list(
        self, prefix: str = "", *, delimiter: str | None = None, cursor: str | None = None
    ) -> Listing:
        """Enumerate keys under a prefix. Paginated."""

    @abc.abstractmethod
    def stat(self, key: str) -> Stat | None:
        """Metadata without the body. ``None`` when the key does not exist."""

    # ---------------------------------------------------------- optional

    def presign(self, key: str, *, ttl_seconds: int = 300) -> str:
        """Mint a time-limited direct read URL (§12.4). Optional capability."""
        raise NotImplementedError(f"{type(self).__name__} does not support presign")


__all__ = [
    "CAPABILITIES",
    "UNSET",
    "Listing",
    "PreconditionFailed",
    "Stat",
    "Transport",
]
