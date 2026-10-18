"""Key validation and path algebra, PROTOCOL §1.1 and §2."""

from __future__ import annotations

from collections.abc import Iterable

from .order import compare_utf8, fold_case, nfc, sort_utf8

MAX_KEY_BYTES = 1024

CONTENT = "content/"
META = "meta/"
INDEX = "index/"
PRINCIPALS = "principals/"
HISTORY = "history/"
MANIFEST = "basalt.yaml"

#: Prefixes this spec reserves (§2.3).
RESERVED = (CONTENT, META, INDEX, PRINCIPALS, HISTORY)


class KeyError_(ValueError):
    """An invalid key (§1.1), carrying the error code the corpus pins."""

    def __init__(self, code: str, key: object, detail: str | None = None) -> None:
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {key!r}{suffix}")
        self.code = code
        self.key = key


# Exported under the protocol-facing name; shadowing the builtin inside this
# module would be a hazard, so the class is defined with a trailing underscore
# and aliased here.
BasaltKeyError = KeyError_


def validate_key(key: object) -> str:
    """Validate a key for writing (§1.1).

    Returns the key unchanged, or raises :class:`BasaltKeyError` with the code
    the conformance corpus expects. The check order matters: the corpus pins
    which error a given key produces, and several of these conditions overlap
    (``content/a/`` has both a trailing slash and an empty final segment).
    """
    if not isinstance(key, str) or key == "":
        raise BasaltKeyError("KEY_EMPTY", key)

    try:
        encoded = key.encode("utf-8")
    except UnicodeEncodeError as err:
        # §1.1: "a key is an opaque, non-empty UTF-8 string". A Python str
        # holding lone surrogates — what decoding an invalid filesystem name
        # produces — is not one, so it is rejected rather than silently
        # re-encoded into bytes no other implementation would produce.
        raise BasaltKeyError("KEY_NOT_UTF8", key, str(err)) from err

    size = len(encoded)
    if size > MAX_KEY_BYTES:
        raise BasaltKeyError("KEY_TOO_LONG", key, f"{size} > {MAX_KEY_BYTES}")

    for ch in key:
        cp = ord(ch)
        # C0 (including NUL) and C1 control ranges.
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            raise BasaltKeyError("KEY_CONTROL_CHAR", key, f"U+{cp:04X}")

    if key.startswith("/"):
        raise BasaltKeyError("KEY_LEADING_SLASH", key)
    if key.endswith("/"):
        raise BasaltKeyError("KEY_TRAILING_SLASH", key)

    for seg in key.split("/"):
        if seg == "":
            raise BasaltKeyError("KEY_EMPTY_SEGMENT", key)
        if seg in (".", ".."):
            raise BasaltKeyError("KEY_DOT_SEGMENT", key, seg)

    # NFC last: the checks above give more specific errors for the same input.
    if nfc(key) != key:
        raise BasaltKeyError("KEY_NOT_NFC", key)
    return key


def is_valid_key(key: object) -> bool:
    """True when the key is valid, without raising."""
    try:
        validate_key(key)
    except BasaltKeyError:
        return False
    return True


def find_collisions(keys: Iterable[str]) -> list[list[str]]:
    """Detect colliding keys (§2.2) — distinct keys equal under NFC + case-fold.

    Returns groups of two or more keys, each group ordered by §13.3 so the
    survivor (the first) is deterministic and a repair is reproducible.
    """
    buckets: dict[str, list[str]] = {}
    for k in keys:
        buckets.setdefault(fold_case(k), []).append(k)
    groups = [sort_utf8(g) for g in buckets.values() if len(g) > 1]
    return sort_utf8(groups, lambda g: g[0])


def find_folder_case_divergence(keys: Iterable[str]) -> list[list[str]]:
    """Folder-case divergence (§2.2).

    Distinct keys whose *folder* segments fold together. Weaker than a
    collision — both files survive a round trip — but the folders merge on a
    case-insensitive store, moving one file and breaking every path-shaped
    link to it (§9.2 steps 1-3).

    Returns groups of the differently-cased folder spellings found, each
    ordered by §13.3.
    """
    spellings: dict[str, dict[str, None]] = {}
    for k in keys:
        segs = k.split("/")[:-1]
        acc = ""
        for seg in segs:
            acc += seg + "/"
            spellings.setdefault(fold_case(acc), {})[acc] = None
    groups = [sort_utf8(list(s)) for s in spellings.values() if len(s) > 1]
    return sort_utf8(groups, lambda g: g[0])


def key_to_path(key: str) -> str | None:
    """``content/Notes/A.md`` -> ``Notes/A.md``; ``None`` outside ``content/``."""
    return key[len(CONTENT) :] if key.startswith(CONTENT) else None


def path_to_key(path: str) -> str:
    """``Notes/A.md`` -> ``content/Notes/A.md``"""
    return CONTENT + path


def parent_folder(path: str) -> str:
    """``Notes/Ideas/A.md`` -> ``Notes/Ideas/``; a root-level path -> ``""``."""
    i = path.rfind("/")
    return "" if i == -1 else path[: i + 1]


def ancestor_folders(path: str) -> list[str]:
    """``Notes/Ideas/A.md`` -> ``["", "Notes/", "Notes/Ideas/"]``, root-first."""
    out = [""]
    acc = ""
    for seg in path.split("/")[:-1]:  # drop the entry name
        acc += seg + "/"
        out.append(acc)
    return out


def basename(path: str) -> str:
    """``Notes/A.md`` -> ``A.md``"""
    i = path.rfind("/")
    return path if i == -1 else path[i + 1 :]


def stem(name: str) -> str:
    """``A.md`` -> ``A``; ``A.tar.gz`` -> ``A.tar`` (last extension only)."""
    i = name.rfind(".")
    return name if i <= 0 else name[:i]


def extname(name: str) -> str:
    """``A.md`` -> ``.md`` (lowercased); no extension -> ``""``."""
    i = name.rfind(".")
    return "" if i <= 0 else name[i:].lower()


def is_folder(path: str) -> bool:
    """True when ``path`` is a folder path (ends in ``/``, or is the root)."""
    return path == "" or path.endswith("/")


def implied_folders(paths: Iterable[str]) -> list[str]:
    """The set of folders implied by a set of content paths (§2.1).

    Folders are never stored; they exist exactly as long as something lives
    beneath them, so this is a function of the path set and nothing else.
    """
    seen: set[str] = set()
    for p in paths:
        for f in ancestor_folders(p):
            if f != "":
                seen.add(f)
    return sort_utf8(seen)


def resolve_relative(from_path: str, target: str) -> str | None:
    """Resolve ``target`` against the folder of ``from_path``, applying . and ..

    Returns ``None`` if the result escapes the vault root — a link must not be
    able to address outside the vault.
    """
    segs = (parent_folder(from_path) + target).split("/")
    out: list[str] = []
    for seg in segs:
        if seg in ("", "."):
            continue
        if seg == "..":
            if not out:
                return None
            out.pop()
            continue
        out.append(seg)
    return "/".join(out) if out else None


def resolve_rooted(target: str) -> str | None:
    """Normalize a rooted target (``/a/../b`` -> ``b``), or ``None`` if it escapes."""
    out: list[str] = []
    for seg in target.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not out:
                return None
            out.pop()
            continue
        out.append(seg)
    return "/".join(out) if out else None


__all__ = [
    "CONTENT",
    "HISTORY",
    "INDEX",
    "MANIFEST",
    "MAX_KEY_BYTES",
    "META",
    "PRINCIPALS",
    "RESERVED",
    "BasaltKeyError",
    "ancestor_folders",
    "basename",
    "compare_utf8",
    "extname",
    "find_collisions",
    "find_folder_case_divergence",
    "fold_case",
    "implied_folders",
    "is_folder",
    "is_valid_key",
    "key_to_path",
    "nfc",
    "parent_folder",
    "path_to_key",
    "resolve_relative",
    "resolve_rooted",
    "sort_utf8",
    "stem",
    "validate_key",
]
