"""Git working-tree transport, PROTOCOL §1.

The vault is a folder inside a git working tree, so it stays plain markdown
that Obsidian, an editor, ``rg`` and ``git`` itself can open. Reads come
straight from disk through :class:`LocalTransport`, so an edit made by hand is
seen at once. Writes land on disk exactly as they do there and are then
committed, which buys what a folder lacks: every superseded version is kept,
and the vault can be cloned, pushed and shared.

What it commits, and what it leaves alone:

- Only the keys this transport wrote. A partial commit (``git commit --
  <paths>``) leaves anything else staged or edited exactly as it was.
- Not a key git ignores. A vault that lists ``index/`` in ``.gitignore`` still
  gets its indexes written to disk, but not committed.
- One commit per logical write: :meth:`GitTransport.batch` groups a stored
  note, its sidecar and the refreshed indexes. A put outside a batch is
  committed alone.

With a remote, writes are local-first: before a batch it fetches and
fast-forwards (or merges); after it, it pushes. It never forces, rebases or
rewrites history. When it cannot sync — offline, a rejected push, a real
conflict — the write still succeeds, because the working tree *is* the store;
the problem is reported and the next push carries it out.

The TypeScript reference's git store, ported: the batch is per thread instead
of per async context, and one batch at a time per working tree is kept by a
lock file in the git dir, which also keeps a second process out of the way.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import random
import re
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..keys import validate_key
from . import UNSET, Listing, Stat, Transport
from .local import LocalTransport

_SNAPSHOT_TTL = 1.0
_NETWORK_TIMEOUT = 60.0
_PUSH_ATTEMPTS = 5
_LOCK_WAIT = 5 * 60.0
_LOCK_STALE = 10 * 60.0

_LOCK_RE = re.compile(
    r"\.lock'?: File exists|Unable to create '[^']*\.lock'|could not lock config file|cannot lock ref 'HEAD'",
    re.I,
)
#: A push turned down because the remote moved on, or another push was
#: updating the branch at the same moment. Either way: pull, push again.
_REJECTED_RE = re.compile(
    r"\[rejected\]|non-fast-forward|fetch first|\[remote rejected\]|cannot lock ref|failed to update ref",
    re.I,
)


@dataclass
class _Out:
    code: int
    stdout: str
    stderr: str


@dataclass
class _Batch:
    keys: set[str] = field(default_factory=set)
    message: Any = None
    trailers: dict[str, str] = field(default_factory=dict)


class GitError(RuntimeError):
    pass


def _split0(s: str) -> list[str]:
    return [p for p in s.split("\0") if p]


def _first_line(s: str | None) -> str:
    line = (s or "").strip().split("\n")[0]
    return re.sub(r"^(fatal|error): ", "", line)


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, but is someone else's
    except OSError:
        return True


def _one_line(s: Any) -> str:
    return " ".join(re.sub("[\u0000-\u001f\u007f-\u009f\u2028\u2029]+", " ", str(s)).split())


def _commit_message(message: Any, trailers: dict[str, str], paths: list[str]) -> str:
    """Subject, blank line, trailers. Nothing a caller passes can add a line."""
    subject = message(paths) if callable(message) else message
    if not subject:
        subject = f"Write {paths[0]}" if len(paths) == 1 else f"Write {len(paths)} objects"
    lines = [
        f"{k}: {_one_line(v)}"
        for k, v in (trailers or {}).items()
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", k) and v is not None and _one_line(v)
    ]
    return _one_line(subject)[:200] + "\n" + (f"\n{chr(10).join(lines)}\n" if lines else "")


class GitTransport(Transport):
    """A vault rooted at a folder inside a git working tree."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        remote: str | None = None,
        derived: list[str] | None = None,
        rederive: Callable[[], None] | None = None,
        warn: Callable[[str], None] | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.fs = LocalTransport(self.root)
        self.remote = remote or None
        self.remote_url: str | None = None
        self.derived = list(derived or [])
        #: Rebuilds and writes the derived keys after a push had to merge, so
        #: what is pushed covers the other side's content. Settable later,
        #: once a vault over this transport exists (the CLI does that).
        self.rederive = rederive
        self.warn = warn or (lambda m: print(f"basalt: {m}", file=sys.stderr))
        # §1's `versioning`: every committed version is retained.
        self.capabilities = frozenset({*self.fs.capabilities, "versioning"})
        self._ready = False
        self._top = Path()
        self._prefix = ""
        self._lock_path = Path()
        self._snap: dict[str, Any] | None = None
        self._local = threading.local()
        self._serial = threading.RLock()

    # ------------------------------------------------------------- git

    def _run(self, args: list[str], *, cwd: Path, input: str | None = None, timeout: float | None = None) -> _Out:
        env = {
            **os.environ,
            # Never wait on a person: no editor, no credential prompt. Messages
            # are matched below, so keep them in one language.
            "GIT_EDITOR": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
        try:
            r = subprocess.run(
                ["git", *args], cwd=cwd, input=input or "", capture_output=True, text=True,
                encoding="utf-8", errors="replace", env=env, timeout=timeout,
            )
        except FileNotFoundError as err:
            raise GitError("the git store needs git on PATH") from err
        except subprocess.TimeoutExpired:
            return _Out(-1, "", f"timed out after {int(timeout or 0)}s")
        return _Out(r.returncode, r.stdout, r.stderr)

    def _git(
        self,
        args: list[str],
        *,
        ok: tuple[int, ...] | None = (0,),
        input: str | None = None,
        cwd: Path | None = None,
        literal: bool = True,
        timeout: float | None = None,
    ) -> _Out:
        """Run git in the vault root. Every pathspec is literal, so a note
        called ``[draft] *.md`` is that file and not a glob."""
        argv = ["--literal-pathspecs", *args] if literal else args
        for attempt in range(9):
            r = self._run(argv, cwd=cwd or self.root, input=input, timeout=timeout)
            if r.code != 0 and _LOCK_RE.search(r.stderr) and attempt < 8:
                # Another git process holds a lock for milliseconds; a failed
                # command here changed nothing.
                time.sleep((25 * 2**attempt + random.random() * 25) / 1000)
                continue
            if ok is not None and r.code not in ok:
                why = _first_line(r.stderr) or _first_line(r.stdout) or f"exit {r.code}"
                raise GitError(f"git {args[0]} failed: {why}")
            return r
        raise AssertionError("unreachable")

    def ready(self) -> None:
        """Check, once, that the root is inside a working tree; with a remote, pull."""
        if self._ready:
            return
        if not self.root.exists():
            raise GitError(f"{self.root} does not exist")
        r = self._git(["rev-parse", "--is-bare-repository", "--is-inside-work-tree"], ok=None, literal=False)
        if r.code != 0:
            raise GitError(
                f"{self.root} is not in a git repository: run `git init` there, "
                "or use --vault for a plain folder"
            )
        bare, _, inside = r.stdout.partition("\n")
        if bare.strip() == "true" or inside.strip() != "true":
            raise GitError(
                f"{self.root} is in a bare repository, or its .git folder; "
                "clone it and point the git store at the clone"
            )
        self._top = Path(self._git(["rev-parse", "--show-toplevel"], literal=False).stdout.strip())
        rel = os.path.relpath(self.root, self._top.resolve())
        self._prefix = "" if rel == "." else rel.replace(os.sep, "/") + "/"
        git_dir = self._git(["rev-parse", "--absolute-git-dir"], literal=False).stdout.strip()
        self._lock_path = Path(git_dir) / "basalt-write.lock"
        if self.remote:
            u = self._git(["remote", "get-url", self.remote], ok=None, literal=False)
            if u.code != 0:
                raise GitError(f"git has no remote named {self.remote}")
            self.remote_url = u.stdout.strip()
        self._ready = True
        if self.remote:
            with self._serial, self._file_lock():
                self._pull()

    def _branch(self) -> str | None:
        r = self._git(["symbolic-ref", "-q", "--short", "HEAD"], ok=None, literal=False)
        return r.stdout.strip() if r.code == 0 else None

    def _rev(self, ref: str) -> str:
        r = self._git(["rev-parse", "-q", "--verify", f"{ref}^{{commit}}"], ok=None, literal=False)
        return r.stdout.strip() if r.code == 0 else ""

    def _is_ancestor(self, a: str, b: str) -> bool:
        return self._git(["merge-base", "--is-ancestor", a, b], ok=(0, 1), literal=False).code == 0

    # ----------------------------------------------------------- reads

    def get(self, key: str) -> bytes | None:
        return self.fs.get(key)

    def list(self, prefix: str = "", *, delimiter: str | None = None, cursor: str | None = None) -> Listing:
        return self.fs.list(prefix, delimiter=delimiter, cursor=cursor)

    def stat(self, key: str) -> Stat | None:
        """The filesystem's size and etag, with the time of the last commit
        that touched the file when its content is what HEAD has — so "recent"
        still means something on a fresh clone."""
        st = self.fs.stat(key)
        if st is None:
            return None
        try:
            self.ready()
            snap = self._snapshot()
            if key in snap["tracked"] and key not in snap["dirty"] and key in snap["times"]:
                return Stat(size=st.size, etag=st.etag, mtime=snap["times"][key])
        except Exception:  # not a reason to fail a read
            pass
        return st

    def _snapshot(self) -> dict[str, Any]:
        snap = self._snap
        if snap and time.monotonic() - snap["at"] < _SNAPSHOT_TTL:
            return snap
        head = self._rev("HEAD")
        if snap and snap["head"] == head and head:
            tracked, times = snap["tracked"], snap["times"]
        else:
            tracked, times = set(), {}
            if head:
                t = self._git(["ls-tree", "-r", "-z", "--name-only", "HEAD"], literal=False)
                tracked = set(_split0(t.stdout))
                log = self._git([
                    "log", "--pretty=format:%x1e%cI", "--name-only", "--no-renames", "-z",
                    "--relative", "HEAD", "--", ".",
                ])
                for chunk in log.stdout.split("\x1e"):
                    nl = chunk.find("\n")
                    if nl == -1:
                        continue
                    when = dt.datetime.fromisoformat(chunk[:nl].strip()).astimezone(dt.UTC)
                    stamp = when.strftime("%Y-%m-%dT%H:%M:%SZ")
                    for p in _split0(chunk[nl + 1 :]):
                        times.setdefault(p, stamp)
        dirty: set[str] = set()
        if head:
            d = self._git(["diff", "--name-only", "-z", "--no-renames", "--relative", "HEAD", "--", "."])
            dirty = set(_split0(d.stdout))
        self._snap = {"head": head, "tracked": tracked, "times": times, "dirty": dirty, "at": time.monotonic()}
        return self._snap

    def _invalidate(self) -> None:
        if self._snap:
            self._snap["at"] = 0.0

    # ---------------------------------------------------------- writes

    def put(self, key: str, data: bytes, *, if_match: Any = UNSET, content_type: str | None = None) -> Stat:
        validate_key(key)
        return self._write(key, lambda: self.fs.put(key, data, if_match=if_match, content_type=content_type))

    def delete(self, key: str) -> None:
        # §1.2: nothing is reported, and a key never there makes no commit.
        self._write(key, lambda: self.fs.delete(key))

    def _write(self, key: str, op: Callable[[], Any]) -> Any:
        b: _Batch | None = getattr(self._local, "batch", None)
        if b is None:
            with self.batch():
                return self._write(key, op)
        try:
            return op()
        finally:
            # Recorded even when the op failed: it may have changed the file.
            b.keys.add(key)
            self._invalidate()

    @contextlib.contextmanager
    def batch(self, *, message: Any = None, trailers: dict[str, str] | None = None) -> Iterator[None]:
        """Group every put and delete made inside the block into one commit.

        ``message`` is the subject, or a function of the keys written. A batch
        inside a batch joins the outer one. The commit happens even if the
        block raises part-way, because the store has changed either way.
        """
        if getattr(self._local, "batch", None) is not None:
            yield
            return
        self.ready()
        with self._serial, self._file_lock():
            if self.remote:
                self._pull()
            b = _Batch(message=message, trailers=dict(trailers or {}))
            self._local.batch = b
            failure: BaseException | None = None
            try:
                yield
            except BaseException as err:
                failure = err
            finally:
                self._local.batch = None
            committed = False
            try:
                committed = self._commit(b)
            except GitError as err:
                e = GitError(f"stored on disk but not committed: {err}")
                if failure is not None:
                    self.warn(str(e))
                else:
                    failure = e
            if committed and self.remote:
                self._push()
            if failure is not None:
                raise failure

    @contextlib.contextmanager
    def _file_lock(self) -> Iterator[None]:
        """One batch at a time per working tree, across processes. A lock left
        by a process that is gone, or older than any batch, is broken
        atomically by rename, so two waiters cannot both take it."""
        file = self._lock_path
        mine = f"{os.getpid()} {dt.datetime.now(dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')} {uuid.uuid4()}\n"
        started = time.monotonic()
        attempt = 0
        while True:
            try:
                fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                with os.fdopen(fd, "w") as f:
                    f.write(mine)
                break
            except FileExistsError:
                pass
            try:
                seen = file.read_text()
            except FileNotFoundError:
                continue
            parts = seen.split()
            pid = int(parts[0]) if parts and parts[0].isdigit() else 0
            try:
                at = dt.datetime.fromisoformat(parts[1].replace("Z", "+00:00")).timestamp()
            except (IndexError, ValueError):
                at = time.time()
            age = time.time() - at
            if not _alive(pid) or age > _LOCK_STALE:
                grave = file.with_name(f"{file.name}.{os.getpid()}.{uuid.uuid4()}")
                try:
                    os.rename(file, grave)
                except FileNotFoundError:
                    continue
                try:
                    moved = grave.read_text()
                except OSError:
                    moved = None
                if moved != seen:
                    with contextlib.suppress(OSError):
                        os.link(grave, file)
                with contextlib.suppress(OSError):
                    grave.unlink()
                continue
            if time.monotonic() - started > _LOCK_WAIT:
                raise GitError(
                    f"another basalt process (pid {pid}) has been writing to this clone "
                    f"for {int(age)}s; if it is gone, remove {file}"
                )
            time.sleep((min(250, 20 + attempt * 10) + random.random() * 20) / 1000)
            attempt += 1
        try:
            yield
        finally:
            # Remove it only while it is still ours.
            try:
                if file.read_text() == mine:
                    file.unlink()
            except OSError:
                pass

    def _commit(self, b: _Batch) -> bool:
        keys = sorted(b.keys)
        if not keys:
            return False
        tracked = set(_split0(self._git(["ls-files", "-z", "--", *keys]).stdout))
        candidates = [k for k in keys if k in tracked or (self.root / k).exists()]
        # An untracked key git ignores stays on disk and out of history; a
        # tracked one is committed whatever .gitignore says, as git would.
        untracked = [k for k in candidates if k not in tracked]
        ignored: set[str] = set()
        if untracked:
            r = self._git(
                ["check-ignore", "-z", "--stdin"], input="\0".join(untracked) + "\0",
                ok=(0, 1), literal=False,
            )
            ignored = set(_split0(r.stdout))
        paths = [k for k in candidates if k not in ignored]
        if not paths:
            return False
        self._git(["add", "-A", "--", *paths])
        if self._git(["diff", "--cached", "--quiet", "--", *paths], ok=(0, 1)).code == 0:
            return False  # wrote what was already committed
        self._git(["commit", "-q", "-F", "-", "--", *paths], input=_commit_message(b.message, b.trailers, paths))
        self._invalidate()
        return True

    # ------------------------------------------------------------ sync

    def _pull(self) -> bool:
        """Fast-forward, or merge when the two have diverged. Reports and
        carries on when it cannot. Returns whether HEAD moved."""
        branch = self._branch()
        if not branch:
            self.warn("HEAD is detached, so nothing is pulled or pushed; check out a branch")
            return False
        remote = self.remote
        tracking = f"refs/remotes/{remote}/{branch}"
        f = self._git(
            ["fetch", "--quiet", "--no-tags", remote, f"+refs/heads/{branch}:{tracking}"],
            ok=None, literal=False, timeout=_NETWORK_TIMEOUT,
        )
        if f.code != 0:
            # A remote with no such branch yet is fine: the first push makes it.
            if "couldn't find remote ref" not in f.stderr.lower():
                self.warn(f"could not fetch {remote}/{branch}: {_first_line(f.stderr)}")
            return False
        theirs = self._rev(tracking)
        ours = self._rev("HEAD")
        if not theirs or theirs == ours:
            return False
        if ours and self._is_ancestor(theirs, ours):
            return False  # only we have moved
        self._invalidate()
        if not ours or self._is_ancestor(ours, theirs):
            m = self._git(["merge", "--ff-only", "--quiet", theirs], ok=None, literal=False)
            if m.code != 0:
                self.warn(f"could not fast-forward to {remote}/{branch}: {_first_line(m.stderr)}")
            return m.code == 0
        m = self._git(
            ["merge", "--no-ff", "--no-edit", "--quiet", "-m", f"Merge {remote}/{branch}", theirs],
            ok=None, literal=False,
        )
        if m.code == 0:
            return True
        if not self._rev("MERGE_HEAD"):
            # Refused before it started, typically over uncommitted edits.
            self.warn(f"could not merge {remote}/{branch}: {_first_line(m.stderr or m.stdout)}")
            return False
        conflicted = _split0(self._git(
            ["diff", "--name-only", "-z", "--no-relative", "--diff-filter=U"], cwd=self._top, literal=False,
        ).stdout)
        derived = [self._prefix + d for d in self.derived]
        if conflicted and all(any(p.startswith(d) for d in derived) for p in conflicted):
            # Derived files: keep ours, finish the merge; the reindex repairs them.
            for p in conflicted:
                c = self._git(["checkout", "--ours", "--", p], cwd=self._top, ok=None)
                if c.code != 0:
                    self._git(["rm", "-q", "--", p], cwd=self._top)
                else:
                    self._git(["add", "--", p], cwd=self._top)
            self._git(["commit", "-q", "--no-edit"], cwd=self._top, literal=False)
            return True
        self._git(["merge", "--abort"], ok=None, literal=False)
        shown = ", ".join(conflicted[:3]) + (", …" if len(conflicted) > 3 else "")
        self.warn(
            f"{remote}/{branch} and this clone both changed {shown}; merge by hand. "
            "Writes stay local until then."
        )
        return False

    def _push(self) -> None:
        """Push; if the remote has moved, pull and try again. Never forces."""
        branch = self._branch()
        if not branch:
            return
        remote = self.remote
        for attempt in range(_PUSH_ATTEMPTS):
            if attempt:
                # Two clones pushing at once keep beating each other by
                # milliseconds; a little jitter breaks the tie.
                time.sleep((50 * attempt + random.random() * 150) / 1000)
            p = self._git(
                ["push", "--quiet", "--porcelain", remote, f"HEAD:refs/heads/{branch}"],
                ok=None, literal=False, timeout=_NETWORK_TIMEOUT,
            )
            if p.code == 0:
                return
            if not _REJECTED_RE.search(p.stdout + p.stderr):
                self.warn(
                    f"could not push to {remote}/{branch}: "
                    f"{_first_line(p.stderr) or _first_line(p.stdout)}; the commit is kept here "
                    "and goes with the next push"
                )
                return
            if self._pull() and self.rederive:
                # The merge brought in content these indexes do not cover:
                # rebuild them now, as a commit of their own, before pushing.
                b = _Batch(message=f"Rebuild indexes after merging {remote}/{branch}")
                self._local.batch = b
                try:
                    self.rederive()
                except Exception as err:
                    self.warn(f"could not rebuild derived files after merging: {err}")
                finally:
                    self._local.batch = None
                    self._commit(b)
        self.warn(
            f"{remote}/{branch} kept moving or could not be merged; "
            "the commit is kept here and goes with the next push"
        )


__all__ = ["GitError", "GitTransport"]
