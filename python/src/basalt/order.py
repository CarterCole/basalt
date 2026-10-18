"""Canonical ordering and comparison, PROTOCOL §13.3.

All sorting in Basalt is by UTF-8 code unit sequence, bytewise ascending,
after NFC normalization. This is NOT what Python's ``<`` does: ``<`` compares
code points, which disagrees with UTF-8 byte order for the astral planes — a
character above U+FFFF sorts above U+E000-U+FFFF by code point but its UTF-8
encoding begins with 0xF0, which sorts *below* the 0xEE-0xEF that U+E000 and
up encode to. Two implementations that sort differently emit different index
bytes and fail conformance (§13), so this one function is the only place
ordering is decided.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Callable, Iterable
from typing import TypeVar

T = TypeVar("T")

_Key = Callable[[T], str]


def nfc(value: str) -> str:
    """NFC-normalize. Every key, path, id, tag and term passes through here."""
    return unicodedata.normalize("NFC", value) if isinstance(value, str) else value


def utf8_key(value: str) -> bytes:
    """The sort key §13.3 mandates: NFC, then raw UTF-8 bytes.

    UTF-8 is order-preserving, so for any string Python can encode this agrees
    with ``str`` comparison — the orderings that *do* differ are UTF-16 code
    unit order (where a surrogate pair sorts below U+E000-U+FFFF) and locale
    collation, both of which §13.3 rules out. The encode stays because §13.3
    specifies bytes, and because sorting on bytes cannot drift if a future
    reader mistakes one of those other orderings for the default.

    ``surrogatepass`` keeps this total: a path read from a filesystem with an
    invalid byte sequence in it decodes to lone surrogates, which plain UTF-8
    cannot encode. Such a key is not a key at all under §1.1 and
    :func:`basalt.keys.validate_key` rejects it, but ordering must not raise
    while an implementation is still working out what it has.
    """
    return nfc(value).encode("utf-8", errors="surrogatepass")


def compare_utf8(a: str, b: str) -> int:
    """Compare two strings as UTF-8 byte sequences, ascending."""
    x, y = utf8_key(a), utf8_key(b)
    if x < y:
        return -1
    return 0 if x == y else 1


def sort_utf8(items: Iterable[T], key: _Key | None = None) -> list[T]:
    """Sort a copy of ``items`` by §13.3, optionally through a key function."""
    if key is None:
        return sorted(items, key=lambda v: utf8_key(v))  # type: ignore[arg-type]
    return sorted(items, key=lambda v: utf8_key(key(v)))


def fold_case(value: str) -> str:
    """Unicode case-fold for the collision rule (§2.2) and name matching (§9.2).

    ``str.lower()`` after NFC is the practical fold, and is what the reference
    implementation uses. Python's ``str.casefold()`` is a *stricter* fold (it
    maps ``ß`` to ``ss``), and inventing a stricter fold than the filesystems
    §2.2 protects against would reject legal keys and disagree with the
    reference implementation on which keys collide.
    """
    return nfc(value).lower()
