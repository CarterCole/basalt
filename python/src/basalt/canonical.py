"""Canonical JSON serialization, PROTOCOL §13.1.

Index objects must be byte-identical across implementations, so this does not
use :func:`json.dumps`. Its defaults are wrong for §13.1 in four separate
ways, each of which alone breaks byte-equality:

- ``sort_keys=True`` sorts by code point, not by the UTF-8 byte sequence
  §13.3 requires;
- ``ensure_ascii=True`` emits ``\\uXXXX`` for every non-ASCII character, which
  §13.1 forbids;
- the default separators put a space after ``:`` only when ``indent`` is set,
  and render empty containers as ``{}``/``[]`` inconsistently across versions;
- U+2028 and U+2029 are left literal, which is legal JSON but breaks the
  bytes the moment they are embedded in a ``<script>`` tag.

So the writer is spelled out here, and it is the only place index bytes are
decided.
"""

from __future__ import annotations

import copy
from typing import Any

from .order import utf8_key

#: Sentinel for "this key is absent", so a caller can distinguish a field that
#: should not be emitted at all from one whose value is JSON ``null``.
ABSENT: Any = object()

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _quote(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
            continue
        cp = ord(ch)
        # Escape C0 controls (JSON requires it) plus the two line separators
        # that are legal in JSON but illegal in JavaScript string literals.
        if cp < 0x20 or cp in (0x2028, 0x2029):
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)  # §13.1: non-ASCII emitted literally, never escaped.
    out.append('"')
    return "".join(out)


def _write(value: Any, indent: str, depth: int) -> str:
    pad = indent * depth
    pad_in = indent * (depth + 1)

    if value is None:
        return "null"
    # bool before int: in Python ``bool`` is a subclass of ``int``, so an
    # ``isinstance(value, int)`` test would render True as 1.
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        # §13.1 bans non-integers from index objects outright, which sidesteps
        # every float-formatting disagreement between languages.
        raise TypeError(f"canonical JSON: non-integer number {value!r}")
    if isinstance(value, str):
        return _quote(value)

    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        items = [pad_in + _write(v, indent, depth + 1) for v in value]
        return "[\n" + ",\n".join(items) + "\n" + pad + "]"

    if isinstance(value, dict):
        keys = [k for k in value if value[k] is not ABSENT]
        if not keys:
            return "{}"
        keys.sort(key=utf8_key)  # §13.1: keys sorted by §13.3
        items = [
            pad_in + _quote(k) + ": " + _write(value[k], indent, depth + 1) for k in keys
        ]
        return "{\n" + ",\n".join(items) + "\n" + pad + "}"

    raise TypeError(f"canonical JSON: unserializable {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Serialize to canonical JSON: 2-space indent, LF, one trailing newline."""
    return _write(value, "  ", 0) + "\n"


def canonical_bytes(value: Any) -> bytes:
    """Serialize and encode to UTF-8 bytes, ready for a transport put."""
    return canonical_json(value).encode("utf-8")


def comparable(obj: dict[str, Any]) -> dict[str, Any]:
    """Strip the fields §13.2 excludes from cross-implementation comparison.

    ``generated`` legitimately differs between two runs and ``etag`` between
    two stores, so neither participates in equality. Everything else must
    match byte for byte.
    """
    clone = copy.deepcopy(obj)
    clone.pop("generated", None)
    entries = clone.get("entries")
    if isinstance(entries, list):
        for e in entries:
            if isinstance(e, dict):
                e.pop("etag", None)
    return clone
