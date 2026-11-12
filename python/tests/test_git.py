"""The git working-tree transport, PROTOCOL §1 — the contract the TypeScript
and Rust git stores are held to.

Every test makes its own repositories in a temp folder, with git's global and
system config shut out. Remotes are bare repositories on disk; nothing here
touches the network.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from basalt.keys import INDEX
from basalt.store import Provenance, store_object
from basalt.transport.git import GitError, GitTransport
from basalt.vault import Vault

from .conftest import CONFORMANCE

FIXTURE = CONFORMANCE / "vaults/minimal/vault"


@pytest.fixture(autouse=True)
def isolated_git(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path_factory.mktemp("git-home")
    cfg = home / "gitconfig"
    cfg.write_text(
        "[user]\n\tname = Basalt Test\n\temail = test@example.com\n"
        "[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n"
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(cfg))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def repo_with_vault(tmp: Path, sub: str = "", ignore_index: bool = False) -> tuple[Path, Path]:
    top = tmp / "repo"
    top.mkdir()
    git(top, "init", "-q")
    root = top / sub if sub else top
    shutil.copytree(FIXTURE, root, dirs_exist_ok=True)
    if ignore_index:
        (root / ".gitignore").write_text("index/\n")
    git(top, "add", "-A")
    git(top, "commit", "-q", "-m", "Import the vault")
    return top, root


def open_vault(root: Path, remote: str | None = None) -> tuple[Vault, list[str]]:
    warnings: list[str] = []
    t = GitTransport(root, remote=remote, derived=[INDEX], warn=warnings.append)
    t.ready()
    v = Vault(t).load()
    v.reindex()

    def again() -> None:
        v.reload()
        v.reindex(write=True)

    t.rederive = again
    return v, warnings


def put(v: Vault, path: str, text: str, **kw: object) -> object:
    return store_object(v, path=path, data=text.encode(), **kw)  # type: ignore[arg-type]


def subjects(cwd: Path, n: int = 20) -> list[str]:
    return [s for s in git(cwd, "log", f"-{n}", "--format=%s").split("\n") if s]


def changed(cwd: Path, rev: str = "HEAD") -> list[str]:
    return sorted(s for s in git(cwd, "show", "--format=", "--name-only", rev).split("\n") if s)


def test_the_five_operations_round_trip_one_commit_per_write(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path)
    t = GitTransport(root)
    t.put("content/Notes/New.md", b"# New\n")
    assert t.get("content/Notes/New.md") == b"# New\n"
    assert t.stat("content/Notes/New.md") is not None
    assert "content/Notes/New.md" in t.list("content/").keys
    t.delete("content/Notes/New.md")
    assert t.get("content/Notes/New.md") is None
    t.delete("content/Notes/Never.md")  # never there: no commit
    assert subjects(top, 3) == ["Write content/Notes/New.md", "Write content/Notes/New.md", "Import the vault"]
    assert git(top, "status", "--porcelain") == ""


def test_a_vault_in_a_subfolder_indexes_as_the_corpus_expects(tmp_path: Path) -> None:
    _, root = repo_with_vault(tmp_path, sub="vaults/mine")
    v, _ = open_vault(root)
    want = json.loads((CONFORMANCE / "vaults/minimal/expected/nodes.json").read_text())
    got = v.indexes["nodes"]  # type: ignore[index]
    assert [e["path"] for e in got["entries"]] == [e["path"] for e in want["entries"]]
    assert got["source_digest"] == want["source_digest"]


def test_a_stored_note_its_indexes_and_its_provenance_are_one_commit(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path)
    v, _ = open_vault(root)
    put(v, "Notes/Idea.md", "# Idea\n", principal="u:editor",
        provenance=Provenance(agent="claude-code", account="work"))
    assert subjects(top, 1) == ["Add Notes/Idea.md"]
    files = changed(top)
    assert "content/Notes/Idea.md" in files and "index/nodes.json" in files
    body = git(top, "log", "-1", "--format=%B")
    for t in ("Basalt-Principal: u:editor", "Basalt-Agent: claude-code", "Basalt-Account: work"):
        assert t in body
    assert git(top, "status", "--porcelain") == ""


def test_what_you_have_staged_or_are_editing_is_left_alone(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path)
    hexes = root / "content/Notes/Hexes.md"
    hexes.write_text(hexes.read_text() + "\nhalf-done\n")
    (root / "content/Notes/Staged.md").write_text("# staged\n")
    git(top, "add", "content/Notes/Staged.md")
    v, _ = open_vault(root)
    put(v, "Notes/Mine.md", "# mine\n")
    assert not any("Hexes" in f or "Staged" in f for f in changed(top))
    status = subprocess.run(["git", "status", "--porcelain"], cwd=top, capture_output=True, text=True).stdout
    assert " M content/Notes/Hexes.md" in status and "A  content/Notes/Staged.md" in status


def test_a_key_gitignore_excludes_is_stored_but_not_committed(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path, ignore_index=True)
    v, _ = open_vault(root)
    put(v, "Notes/Idea.md", "# Idea\n")
    assert (root / "index/nodes.json").exists()
    assert changed(top) == ["content/Notes/Idea.md"]


def test_reindex_and_mint_are_a_commit_each_and_only_when_something_changed(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path)
    v, _ = open_vault(root)
    v.reindex(write=True)
    first = subjects(top, 1)
    v.reindex(write=True)
    assert subjects(top, 1) == first, "a reindex that changes nothing makes no commit"
    (root / "content/Notes/Unbound.md").write_text("# no id\n")
    assert len(v.mint_ids()) == 1
    assert subjects(top, 1) == ["Mint ids for 1 object"]
    assert v.mint_ids() == []
    assert subjects(top, 1) == ["Mint ids for 1 object"]


def test_mtime_is_the_last_commit_that_touched_a_file(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path)
    when = "2001-02-03T04:05:06Z"
    (root / "content/Notes/Old.md").write_text("# old\n")
    git(top, "add", "-A")
    subprocess.run(
        ["git", "commit", "-qm", "old"], cwd=top, check=True,
        env={**os.environ, "GIT_COMMITTER_DATE": when, "GIT_AUTHOR_DATE": when},
    )
    t = GitTransport(root)
    assert t.stat("content/Notes/Old.md").mtime == when  # type: ignore[union-attr]


def test_a_folder_outside_a_repository_or_a_bare_one_is_refused_plainly(tmp_path: Path) -> None:
    with pytest.raises(GitError, match="not in a git repository"):
        GitTransport(tmp_path).ready()
    bare = tmp_path / "bare"
    bare.mkdir()
    git(bare, "init", "-q", "--bare")
    with pytest.raises(GitError, match="bare repository"):
        GitTransport(bare).ready()


def remote_and_clones(tmp: Path, n: int) -> tuple[Path, list[Path]]:
    top, _ = repo_with_vault(tmp)
    remote = tmp / "remote.git"
    git(tmp, "clone", "-q", "--bare", str(top), str(remote))
    clones = []
    for i in range(n):
        c = tmp / f"clone{i}"
        git(tmp, "clone", "-q", str(remote), str(c))
        clones.append(c)
    return remote, clones


def test_two_clones_writing_through_one_remote_both_land_with_fresh_indexes(tmp_path: Path) -> None:
    remote, (a, b) = remote_and_clones(tmp_path, 2)
    offline, _ = open_vault(b)
    put(offline, "Notes/From B offline.md", "# B0\n")
    va, wa = open_vault(a, "origin")
    put(va, "Notes/From A.md", "# A\n")
    assert wa == []
    vb, wb = open_vault(b, "origin")
    put(vb, "Notes/From B.md", "# B1\n")
    assert wb == []

    check = tmp_path / "check"
    git(tmp_path, "clone", "-q", str(remote), str(check))
    for name in ("From A", "From B offline", "From B"):
        assert (check / f"content/Notes/{name}.md").exists(), name
    fresh, _ = open_vault(check)
    stored = json.loads((check / "index/nodes.json").read_text())
    assert stored["source_digest"] == fresh.indexes["digest"]["root"], "remote indexes are stale"  # type: ignore[index]
    assert git(b, "status", "--porcelain") == ""


def test_a_real_conflict_is_aborted_and_reported_and_the_write_still_succeeds(tmp_path: Path) -> None:
    remote, (a, b) = remote_and_clones(tmp_path, 2)

    def edit(d: Path, line: str) -> None:
        p = d / "content/Notes/Columns.md"
        p.write_text(p.read_text() + f"\n{line}\n")
        git(d, "commit", "-q", "-am", line)

    edit(a, "from A")
    git(a, "push", "-q", "origin", "main")
    edit(b, "from B")
    vb, wb = open_vault(b, "origin")
    put(vb, "Notes/Safe.md", "# Safe\n")
    assert any("both changed content/Notes/Columns.md" in w and "merge by hand" in w for w in wb), wb
    assert (b / "content/Notes/Safe.md").exists()
    assert subjects(b, 1) == ["Add Notes/Safe.md"]
    assert not (b / ".git/MERGE_HEAD").exists()
    assert git(b, "status", "--porcelain") == ""
    assert git(remote, "log", "-1", "--format=%s", "main") == "from A", "nothing was forced"


def test_an_unreachable_remote_is_a_warning_not_a_failed_write(tmp_path: Path) -> None:
    _, (a,) = remote_and_clones(tmp_path, 1)
    git(a, "remote", "set-url", "origin", str(a / "no-such-remote.git"))
    va, wa = open_vault(a, "origin")
    put(va, "Notes/Local.md", "# Local\n")
    assert subjects(a, 1) == ["Add Notes/Local.md"]
    assert any("could not fetch" in w for w in wa), wa
    assert any("could not push" in w and "next push" in w for w in wa), wa


def test_remote_must_name_a_remote_that_exists(tmp_path: Path) -> None:
    _, (a,) = remote_and_clones(tmp_path, 1)
    with pytest.raises(GitError, match="no remote named upstream"):
        GitTransport(a, remote="upstream").ready()


def test_a_push_that_has_to_merge_first_rebuilds_the_indexes_before_it_goes_out(tmp_path: Path) -> None:
    remote, (a, b) = remote_and_clones(tmp_path, 2)
    va, wa = open_vault(a, "origin")
    vb, wb = open_vault(b, "origin")
    with vb.batch(message="B writes"):
        vb.t.put("content/Notes/From B.md", b"# B\n")
        put(va, "Notes/From A.md", "# A\n")
        vb.reindex(write=True)
    assert wa + wb == []
    assert subjects(b, 1) == ["Rebuild indexes after merging origin/main"]
    check = tmp_path / "check"
    git(tmp_path, "clone", "-q", str(remote), str(check))
    fresh, _ = open_vault(check)
    stored = json.loads((check / "index/nodes.json").read_text())
    assert stored["source_digest"] == fresh.indexes["digest"]["root"], "pushed indexes are stale"  # type: ignore[index]
    paths = {e["path"] for e in stored["entries"]}
    assert {"Notes/From A.md", "Notes/From B.md"} <= paths


def test_writers_in_several_processes_take_turns_and_a_dead_ones_lock_is_taken_over(tmp_path: Path) -> None:
    top, root = repo_with_vault(tmp_path)
    lock = top / ".git/basalt-write.lock"
    lock.write_text("999999 2026-01-01T00:00:00Z\n")
    src = tmp_path / "src"
    src.mkdir()
    procs = []
    for i in range(4):
        f = src / f"Turn {i}.md"
        f.write_text(f"# Turn {i}\n")
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "basalt.cli", "add", str(f), "--git", str(root), "--to", "Notes/"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ))
    for p in procs:
        out, err = p.communicate(timeout=120)
        assert p.returncode == 0 and "refused" not in out + err and "basalt:" not in out + err, out + err
    assert len([s for s in subjects(top) if s.startswith("Add Notes/Turn")]) == 4
    assert git(top, "status", "--porcelain") == ""
    assert not lock.exists()


def test_cli_add_stores_a_note_an_image_and_stdin_then_refuses_a_repeat(tmp_path: Path) -> None:
    vault = tmp_path / "vault"
    shutil.copytree(FIXTURE, vault)
    note = tmp_path / "Idea.md"
    png = tmp_path / "dot.png"
    note.write_text("# Idea\n")
    png.write_bytes(b"\x89PNG\xff")

    def cli(*args: str, stdin: str = "") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "basalt.cli", *args], input=stdin, capture_output=True, text=True
        )

    r = cli("add", str(note), str(png), "--vault", str(vault), "--agent", "cli")
    assert r.returncode == 0, r.stdout + r.stderr
    assert (vault / "content/Notes/Idea.md").exists()
    assert (vault / "content/Assets/dot.png").read_bytes() == b"\x89PNG\xff"
    sc = (vault / "meta/folders/Assets/entries.yaml").read_text()
    assert "diagram.png" in sc and "dot.png" in sc and "agent: cli" in sc
    r = cli("add", "-", "--as", "Notes/Piped.md", "--title", "Piped", "--vault", str(vault), stdin="body\n")
    assert r.returncode == 0, r.stderr
    piped = (vault / "content/Notes/Piped.md").read_text()
    assert "title: Piped" in piped and "created_by" not in piped
    r = cli("add", str(note), "--vault", str(vault))
    assert r.returncode == 1 and "already exists" in r.stderr
    r = cli("add", str(note), "--to", "Assets/", "--vault", str(vault), "--principal", "u:editor")
    assert r.returncode == 1 and "forbidden" in r.stderr
