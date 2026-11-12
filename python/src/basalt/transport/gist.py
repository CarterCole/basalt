"""GitHub gist transport, PROTOCOL §1, plus the small GitHub client the gist
commands share.

A gist is a flat set of non-empty text files, and a vault is a tree of
arbitrary blobs. The five operations still fit, as long as the mapping is
honest about what a gist cannot hold:

- **Names are flat.** A key becomes one file name by escaping ``%`` as ``%25``
  and ``/`` as ``%2F`` (``conformance/cases/gist/mapping.yaml``), so
  ``content/Notes/A.md`` is the file ``content%2FNotes%2FA.md``. Reversible, and
  a gist someone made by hand with plain names reads back as it looks.
- **Content is text.** The API carries it as a JSON string, so a put of bytes
  that are not UTF-8, or an empty file, is refused rather than mangled.
- **It is small.** The API returns at most 300 files per gist, so a vault in a
  gist is for notes, not for a library.
- **Writes are not atomic.** A PATCH carries no precondition, so ``if_match`` is
  checked against a fresh read and two writers can still pass the check
  together. The ``conditional_put`` capability is therefore not claimed.

Writes made inside a batch (:meth:`GistTransport.batch`) are held back and sent
as ONE PATCH, so ``basalt add`` is one gist revision, not one per file. That is
the same place the git store makes its commit.

The token is read from the environment and sent only to the API host, over
https (or to a loopback address, for tests). It is never accepted on the
command line, where it would land in shell history and ``ps``.

The TypeScript reference's gist transport, ported, with the standard library
only (``urllib``).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import quote, urlparse

from ..keys import validate_key
from . import UNSET, Listing, PreconditionFailed, Stat, Transport

DEFAULT_API: Final = "https://api.github.com"
#: The API shows no more than this many files of one gist.
MAX_GIST_FILES: Final = 300
_MAX_NAME_BYTES = 255
_USER_AGENT = "basalt-vault"

# ------------------------------------------------------------------- names


def encode_name(path: str) -> str:
    """A vault path (or key) as a gist file name."""
    return re.sub(r"[%/]", lambda m: "%25" if m.group() == "%" else "%2F", path)


def decode_name(name: str) -> str:
    """A gist file name as a vault path. Only ``%2F`` and ``%25`` mean anything."""
    return re.sub(r"%(2[Ff]|25)", lambda m: "%" if m.group(1) == "25" else "/", name)


_ID = re.compile(r"[0-9a-fA-F]{5,64}")


def parse_gist_id(value: object) -> str | None:
    """The gist id in whatever a person pasted: the id, the page URL, a clone
    URL. ``None`` when there is none. A raw-file URL ends in a file name, which
    is not an id, so it is refused rather than guessed at."""
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    s = re.sub(r"[#?].*$", "", s)
    if "://" in s:
        try:
            s = urlparse(s).path
        except ValueError:
            return None
    else:
        scp = re.fullmatch(r"[^/@]+@[^:/]+:(.+)", s)
        if scp:
            s = scp.group(1)
    s = s.rstrip("/")
    last = s[s.rfind("/") + 1 :]
    last = re.sub(r"\.git$", "", last)
    return last.lower() if _ID.fullmatch(last) else None


#: What JavaScript's ``String.prototype.trim`` strips, so "blank" means the
#: same thing in every implementation (Python's ``str.strip`` differs at the
#: edges: it strips U+001C-U+001F and U+0085, and not U+FEFF).
_JS_WHITESPACE = "".join(
    chr(c)
    for c in (
        *range(0x09, 0x0E),  # tab, line feed, vertical tab, form feed, carriage return
        0x20, 0xA0, 0x1680,
        *range(0x2000, 0x200B),
        0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
    )
)


def why_not_text(data: bytes | bytearray) -> str | None:
    """Whether these bytes can be a gist file: non-blank UTF-8 with no NUL.

    ``None`` when they can, otherwise why not (``empty`` or ``not_text``)."""
    raw = bytes(data)
    if b"\0" in raw:
        return "not_text"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "not_text"
    return "empty" if text.strip(_JS_WHITESPACE) == "" else None


# --------------------------------------------------------------------- API


class GistError(RuntimeError):
    """A refusal or failure from GitHub, or from what a gist cannot hold.

    ``code`` is one of: ``no_token``, ``insecure_api``, ``network``,
    ``not_found``, ``unauthorized``, ``rate_limited``, ``forbidden``,
    ``http``, ``bad_id``, ``too_big``, ``unsupported``."""

    def __init__(self, code: str, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status


def _is_loopback(host: str) -> bool:
    return host in ("localhost", "127.0.0.1", "::1", "[::1]") or host.endswith(".localhost")


def find_token(env: Mapping[str, str] | None = None, *, gh: bool = True) -> str | None:
    """The token to authenticate with: ``GITHUB_TOKEN``, then ``GH_TOKEN``, then
    whatever the GitHub CLI has signed in (``gh auth token``), which is where a
    keyring login lives. ``None`` when there is none: reading a gist works
    without one, writing does not."""
    environ = os.environ if env is None else env
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        v = environ.get(name)
        if isinstance(v, str) and v.strip():
            return v.strip()
    if not gh:
        return None
    try:
        out = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            timeout=5,
            env=dict(environ),
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout.strip() or None) if out.returncode == 0 else None


@dataclass
class GistFile:
    """One file of a gist as the listing shows it."""

    size: int
    truncated: bool
    raw_url: str | None
    #: The bytes, when the listing carried them; ``None`` for a truncated file.
    content: bytes | None


@dataclass
class Gist:
    id: str
    url: str | None
    public: bool
    description: str
    updated_at: str | None
    truncated: bool
    files: dict[str, GistFile] = field(default_factory=dict)


def _shape(g: dict[str, Any]) -> Gist:
    files: dict[str, GistFile] = {}
    for name, f in (g.get("files") or {}).items():
        if not f:
            continue
        inline = not f.get("truncated") and isinstance(f.get("content"), str)
        size = f.get("size")
        if size is None:
            size = len(f["content"].encode("utf-8")) if isinstance(f.get("content"), str) else 0
        files[name] = GistFile(
            size=size,
            truncated=bool(f.get("truncated")),
            raw_url=f.get("raw_url"),
            content=f["content"].encode("utf-8") if inline else None,
        )
    return Gist(
        id=g.get("id") or "",
        url=g.get("html_url"),
        public=bool(g.get("public")),
        description=g.get("description") or "",
        updated_at=g.get("updated_at"),
        truncated=bool(g.get("truncated")),
        files=files,
    )


class _NoToken:
    """Distinguishes "look the token up" from ``token=None`` ("there is none")."""


_LOOKUP: Final = _NoToken()


class GistApi:
    """The GitHub gist API: just what basalt uses.

    ``token`` left out is looked up (:func:`find_token`) on first use; ``None``
    means there is none. ``api_url`` is for GitHub Enterprise or a test server.
    """

    def __init__(
        self,
        *,
        token: str | _NoToken | None = _LOOKUP,
        api_url: str | None = None,
        env: Mapping[str, str] | None = None,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self.env: Mapping[str, str] = os.environ if env is None else env
        self.api_url = str(api_url or self.env.get("GITHUB_API_URL") or DEFAULT_API).rstrip("/")
        self._token: str | _NoToken | None = token
        u = urlparse(self.api_url)
        host = u.hostname or ""
        self.secure_enough = u.scheme == "https" or _is_loopback(host)
        if opener is not None:
            self._opener = opener
        elif _is_loopback(host):
            # A local server is never reached through a proxy.
            self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        else:
            self._opener = urllib.request.build_opener()

    def _get_token(self) -> str | None:
        if isinstance(self._token, _NoToken):
            self._token = find_token(self.env)
        return self._token

    def can_write(self) -> bool:
        """Whether a write could be signed. Cheap after the first call."""
        return bool(self._get_token()) and self.secure_enough

    def _call(self, method: str, pathname: str, body: Any = None, *, write: bool = False) -> Any:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": _USER_AGENT,
        }
        token = self._get_token()
        if write and not token:
            raise GistError(
                "no_token",
                "writing a gist needs a GitHub token with the gist scope: set GITHUB_TOKEN "
                "(or GH_TOKEN), or sign in with `gh auth login`",
            )
        if token:
            if not self.secure_enough:
                if write:
                    raise GistError(
                        "insecure_api", f"{self.api_url} is not https, so the token will not be sent to it"
                    )
                # A read of a public or secret gist needs no token; leave it off.
            else:
                headers["Authorization"] = f"Bearer {token}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(self.api_url + pathname, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=30) as res:
                raw = res.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            raise self._http_error(err, token=token, write=write) from None
        except (urllib.error.URLError, OSError) as err:
            reason = getattr(err, "reason", None) or err
            raise GistError("network", f"could not reach {self.api_url}: {reason}") from None

    @staticmethod
    def _http_error(err: urllib.error.HTTPError, *, token: str | None, write: bool) -> GistError:
        detail = ""
        try:
            parsed = json.loads(err.read() or b"null")
            if isinstance(parsed, dict):
                detail = str(parsed.get("message") or "")
        except (ValueError, OSError):
            pass
        status = err.code
        limited = err.headers.get("x-ratelimit-remaining") == "0"
        if status == 404:
            return GistError(
                "not_found",
                "gist not found (or this token has no access to it)"
                if token
                else "gist not found (or it is private to an account: set GITHUB_TOKEN)",
                404,
            )
        if status == 401:
            return GistError("unauthorized", f"GitHub rejected the token{f': {detail}' if detail else ''}", 401)
        if status == 429 or (status == 403 and limited):
            reset = err.headers.get("x-ratelimit-reset")
            when = ""
            if reset and reset.isdigit() and int(reset):
                when = "; resets " + dt.datetime.fromtimestamp(int(reset), dt.UTC).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            return GistError(
                "rate_limited",
                "GitHub rate limit reached"
                + when
                + ("" if token else " (unauthenticated requests get far fewer: set GITHUB_TOKEN)"),
                status,
            )
        if status == 403:
            return GistError(
                "forbidden",
                f"GitHub refused: {detail or 'forbidden'}" + (" (the token needs the gist scope)" if write else ""),
                403,
            )
        return GistError("http", f"GitHub answered {status}{f': {detail}' if detail else ''}", status)

    def get(self, gist_id: str) -> Gist:
        """One gist, with the files it shows inline."""
        if not re.fullmatch(r"[0-9a-f]{5,64}", str(gist_id)):
            raise GistError("bad_id", f"not a gist id: {gist_id}")
        return _shape(self._call("GET", f"/gists/{quote(str(gist_id), safe='')}"))

    def create(
        self, *, files: Mapping[str, str], description: str = "", public: bool = False
    ) -> Gist:
        """Create a gist. ``files`` maps a file name to its text. Secret unless ``public``."""
        body = {
            "description": description,
            "public": bool(public),
            "files": {name: {"content": content} for name, content in files.items()},
        }
        return _shape(self._call("POST", "/gists", body, write=True))

    def update(
        self,
        gist_id: str,
        *,
        files: Mapping[str, str | None] | None = None,
        description: str | None = None,
    ) -> Gist:
        """Change a gist: a file name mapped to text sets it, mapped to ``None``
        removes it. One request, so one revision."""
        body: dict[str, Any] = {}
        if description is not None:
            body["description"] = description
        if files is not None:
            body["files"] = {
                name: None if content is None else {"content": content} for name, content in files.items()
            }
        return _shape(self._call("PATCH", f"/gists/{quote(str(gist_id), safe='')}", body, write=True))

    def raw(self, url: str) -> bytes:
        """A file the listing cut short (over about 1 MB). The raw host is not
        the API host, so the token is not sent there: a secret gist is readable
        by anyone holding its URL, and a token has no business on another origin."""
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        try:
            with self._opener.open(req, timeout=60) as res:
                return bytes(res.read())
        except urllib.error.HTTPError as err:
            raise GistError("http", f"fetching {url} answered {err.code}", err.code) from None
        except (urllib.error.URLError, OSError) as err:
            reason = getattr(err, "reason", None) or err
            raise GistError("network", f"could not fetch {url}: {reason}") from None

    def content(self, file: GistFile) -> bytes:
        """A file's full bytes: inline when the listing had them, else fetched."""
        if file.content is not None:
            return file.content
        if not file.raw_url:
            raise GistError("http", "the gist did not say where to fetch a truncated file")
        return self.raw(file.raw_url)


# --------------------------------------------------------------- transport


def _md5(data: bytes) -> str:
    return f'"{hashlib.md5(data, usedforsecurity=False).hexdigest()}"'


class GistTransport(Transport):
    """A vault held in one gist."""

    # Nothing a gist offers maps to a capability of §3.1: no presign, no
    # conditional put (see the module docstring), no ranges, no batch delete.
    capabilities = frozenset()

    def __init__(self, id: str, *, api: GistApi | None = None, ttl: float = 30.0) -> None:
        """``ttl`` is how long (seconds) a read of the gist is reused. Reads cost
        API calls (60 an hour without a token), and a batch always reads fresh,
        so this only bounds how stale a long-lived reader may be."""
        parsed = parse_gist_id(id)
        if not parsed:
            raise ValueError(f"not a gist id or URL: {id}")
        self.id = parsed
        self.api = api or GistApi()
        self.ttl = ttl
        self._gist: Gist | None = None
        self._fetched_at = 0.0
        self._pending: dict[str, bytes | None] | None = None
        self._serial = threading.RLock()

    @property
    def url(self) -> str:
        return (self._gist.url if self._gist else None) or f"https://gist.github.com/{self.id}"

    def ready(self) -> None:
        """Read the gist now, and refuse one too big for the API to show whole."""
        with self._serial:
            self._refresh()

    def _refresh(self) -> Gist:
        g = self.api.get(self.id)
        if g.truncated:
            raise GistError(
                "too_big",
                f"gist {self.id} has more than {MAX_GIST_FILES} files, which the API will not list; "
                "clone it with git instead, or split it",
            )
        self._gist = g
        self._fetched_at = time.monotonic()
        return g

    def _view(self) -> Gist:
        if self._gist is None or time.monotonic() - self._fetched_at > self.ttl:
            self._refresh()
        assert self._gist is not None
        return self._gist

    def _overlay(self) -> tuple[Gist, dict[str, GistFile | bytes]]:
        """The gist as it will be once the held-back writes land."""
        g = self._view()
        names: dict[str, GistFile | bytes] = {decode_name(n): f for n, f in g.files.items()}
        for key, v in (self._pending or {}).items():
            if v is None:
                names.pop(key, None)
            else:
                names[key] = v
        return g, names

    def _bytes(self, entry: GistFile | bytes) -> bytes:
        return entry if isinstance(entry, bytes) else self.api.content(entry)

    # ------------------------------------------------------------- reads

    def get(self, key: str) -> bytes | None:
        with self._serial:
            _, names = self._overlay()
            e = names.get(key)
            return None if e is None else self._bytes(e)

    def stat(self, key: str) -> Stat | None:
        with self._serial:
            g, names = self._overlay()
            e = names.get(key)
            if e is None:
                return None
            data = self._bytes(e)
            return Stat(size=len(data), etag=_md5(data), mtime=g.updated_at)

    def list(
        self, prefix: str = "", *, delimiter: str | None = None, cursor: str | None = None
    ) -> Listing:
        with self._serial:
            _, names = self._overlay()
            keys: list[str] = []
            prefixes: dict[str, None] = {}
            for key in names:
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
        buf = bytes(data)
        why = why_not_text(buf)
        if why:
            raise GistError(
                "unsupported",
                f"a gist holds non-empty text files only; {key} is "
                f"{'empty' if why == 'empty' else 'not UTF-8 text'}. Keep it in a folder or git store.",
            )
        name = encode_name(key)
        if len(name.encode("utf-8")) > _MAX_NAME_BYTES:
            raise GistError(
                "unsupported", f"{key} makes a gist file name longer than {_MAX_NAME_BYTES} bytes"
            )
        with self._serial:
            if if_match is not UNSET:
                # Fresh outside a batch (a batch read fresh when it began): the
                # check is only as good as that read, and a gist has no way to
                # make it atomic.
                if self._pending is None:
                    self._refresh()
                cur = self.stat(key)
                if if_match != (cur.etag if cur else None):
                    raise PreconditionFailed(f"precondition failed for {key!r}")
            if self._pending is not None:
                self._pending[key] = buf
                return Stat(
                    size=len(buf),
                    etag=_md5(buf),
                    mtime=dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
                )
            self._send({key: buf})
            stat = self.stat(key)
            assert stat is not None
            return stat

    def delete(self, key: str) -> None:
        with self._serial:
            if self._pending is not None:
                self._pending[key] = None
                return
            self._send({key: None})

    @contextlib.contextmanager
    def batch(self, *, message: Any = None, trailers: dict[str, str] | None = None) -> Iterator[None]:
        """Group writes into one PATCH, one revision of the gist. Nested
        batches join the outer one; the writes go out when the outermost ends,
        even if the work in it failed part-way, because what was written is
        still wanted. A gist has no commit message, so ``message`` and
        ``trailers`` are not used."""
        with self._serial:
            if self._pending is not None:
                yield
                return
            self._refresh()
            self._pending = {}
            failure: BaseException | None = None
            try:
                yield
            except BaseException as err:
                failure = err
            held = self._pending
            self._pending = None
            try:
                self._send(held)
            except Exception as err:
                if failure is not None:
                    print(f"basalt: could not write the gist: {err}", file=sys.stderr)
                else:
                    failure = err
            if failure is not None:
                raise failure

    def _send(self, writes: Mapping[str, bytes | None]) -> None:
        """Send held writes as one PATCH, leaving out what would change nothing."""
        if not writes:
            return
        g = self._gist or self._refresh()
        by_key = {decode_name(n): (n, f) for n, f in g.files.items()}
        files: dict[str, str | None] = {}
        for key, v in writes.items():
            had = by_key.get(key)
            if v is None:
                if had:
                    files[had[0]] = None
                continue
            if had and had[1].content is not None and had[1].content == v:
                continue
            # Reuse the name the gist already has, so a file written by hand
            # under an odd spelling is updated and not duplicated beside it.
            files[had[0] if had else encode_name(key)] = v.decode("utf-8")
        if not files:
            return
        added = sum(1 for n, c in files.items() if c is not None and n not in g.files)
        removed = sum(1 for c in files.values() if c is None)
        after = len(g.files) + added - removed
        if after > MAX_GIST_FILES:
            raise GistError(
                "too_big", f"that would make {after} files in the gist; the API shows {MAX_GIST_FILES}"
            )
        self._gist = self.api.update(self.id, files=files)
        self._fetched_at = time.monotonic()


__all__ = [
    "DEFAULT_API",
    "MAX_GIST_FILES",
    "Gist",
    "GistApi",
    "GistError",
    "GistFile",
    "GistTransport",
    "decode_name",
    "encode_name",
    "find_token",
    "parse_gist_id",
    "why_not_text",
]
