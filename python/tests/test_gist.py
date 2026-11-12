"""Folders to and from GitHub gists: the name mapping from the corpus, the API
client, ``gist export`` and ``gist import``, and a whole vault living in a gist.

The same scenarios ``ts/test/gist.test.mjs`` runs. Everything talks to a local
stand-in for the gist API (``gist_server``), so no test touches the network or
anyone's GitHub account.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from basalt.gist import collect, export_to_gist, import_from_gist
from basalt.store import StoreFault, store_object
from basalt.transport import PreconditionFailed
from basalt.transport.gist import (
    GistApi,
    GistError,
    GistTransport,
    decode_name,
    encode_name,
    parse_gist_id,
    why_not_text,
)
from basalt.transport.local import LocalTransport
from basalt.vault import Vault

from .conftest import CONFORMANCE, corpus
from .gist_server import TOKEN, FakeGists

FIXTURE = CONFORMANCE / "vaults/minimal/vault"
MAPPING = corpus("cases/gist/mapping.yaml")
CASES = list(MAPPING["cases"])

# --------------------------------------------------------------- the corpus


def test_corpus_is_inventoried() -> None:
    suite = next(s for s in corpus("manifest.yaml")["suites"] if s["file"] == "cases/gist/mapping.yaml")
    assert suite["feature"] == "gist"
    assert suite["spec"] == MAPPING["spec"] == "tooling"
    assert len(CASES) >= suite["cases"], "a case was dropped from the corpus file"


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_gist_corpus(case: dict[str, Any]) -> None:
    kind = case["kind"]
    if kind == "name":
        assert encode_name(case["path"]) == case["file"], "encode"
        assert decode_name(case["file"]) == case["path"], "decode"
    elif kind == "decode":
        assert decode_name(case["file"]) == case["path"]
    elif kind == "id":
        assert parse_gist_id(case["input"]) == case["id"]
    elif kind == "eligible":
        data = (
            base64.b64decode(case["base64"], validate=True)
            if case.get("base64") is not None
            else case["text"].encode("utf-8")
        )
        assert why_not_text(data) == (None if case["ok"] else case["reason"])
    else:
        pytest.fail(f"unknown case kind {kind}")


# ----------------------------------------------------------------- helpers


@pytest.fixture
def server() -> Iterator[FakeGists]:
    s = FakeGists()
    yield s
    s.close()


@pytest.fixture
def make_server() -> Iterator[Any]:
    made: list[FakeGists] = []

    def make(**kwargs: Any) -> FakeGists:
        s = FakeGists(**kwargs)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def api_for(s: FakeGists, token: str | None = TOKEN) -> GistApi:
    return GistApi(token=token, api_url=s.url)


def copy_of_vault(tmp_path: Path, name: str = "vault") -> tuple[Path, Vault]:
    target = tmp_path / name
    shutil.copytree(FIXTURE, target)
    v = Vault(LocalTransport(target))
    v.load()
    return target, v


# ------------------------------------------------------------------ client


def test_client_a_new_gist_is_secret_unless_asked_and_carries_the_description(server: FakeGists) -> None:
    a = api_for(server).create(files={"a.md": "hi"}, description="notes")
    assert a.public is False
    assert server.gists[a.id]["description"] == "notes"
    b = api_for(server).create(files={"a.md": "hi"}, public=True)
    assert b.public is True


def test_client_writing_without_a_token_fails_before_any_request(server: FakeGists) -> None:
    with pytest.raises(GistError, match="GITHUB_TOKEN") as err:
        api_for(server, None).create(files={"a.md": "hi"})
    assert err.value.code == "no_token"
    assert server.requests == []


def test_client_a_wrong_token_is_reported_as_one_and_a_missing_gist_as_missing(server: FakeGists) -> None:
    with pytest.raises(GistError) as err:
        api_for(server, "nope").create(files={"a.md": "hi"})
    assert err.value.code == "unauthorized"
    with pytest.raises(GistError) as err:
        api_for(server).get("0123456789abcdef")
    assert err.value.code == "not_found"
    with pytest.raises(GistError) as err:
        api_for(server).get("../etc")
    assert err.value.code == "bad_id"


def test_client_a_rate_limit_says_so_and_when_it_ends(make_server: Any) -> None:
    s = make_server(limit_reads=True)
    with pytest.raises(GistError) as err:
        api_for(s, None).get("0123456789abcdef")
    assert err.value.code == "rate_limited"
    assert re.search(r"resets 2033", str(err.value))
    assert "GITHUB_TOKEN" in str(err.value)


def test_client_the_token_never_goes_to_a_plain_http_host_nor_to_the_raw_file_host(
    make_server: Any,
) -> None:
    # An http API that is not loopback: a write refuses, a read goes out bare.
    sent: list[Any] = []

    class Response:
        def __enter__(self) -> Response:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self) -> bytes:
            return json.dumps({"id": "abcde", "files": {}}).encode()

    class Opener:
        def open(self, req: Any, timeout: float | None = None) -> Response:
            sent.append(req)
            return Response()

    api = GistApi(token=TOKEN, api_url="http://gists.example.com", opener=Opener())  # type: ignore[arg-type]
    with pytest.raises(GistError) as err:
        api.create(files={"a.md": "x"})
    assert err.value.code == "insecure_api"
    api.get("abcde")
    assert len(sent) == 1
    assert sent[0].get_header("Authorization") is None

    # A truncated file is fetched from its raw URL, with no credentials at all.
    s = make_server(truncate_over=10)
    gist_id = s.seed({"big.md": "x" * 50})
    g = api_for(s).get(gist_id)
    assert g.files["big.md"].truncated is True
    assert len(api_for(s).content(g.files["big.md"])) == 50
    raw = [r for r in s.requests if r["path"].startswith("/raw/")]
    assert len(raw) == 1
    assert raw[0]["auth"] is None


# ------------------------------------------------------------------ export


def test_export_a_folder_becomes_a_secret_gist_with_flat_names_and_says_what_it_left_out(
    server: FakeGists, tmp_path: Path
) -> None:
    d, v = copy_of_vault(tmp_path)
    # The fixture's "diagram.png" is a text placeholder; this one is a real PNG header.
    (d / "content/Assets/real.png").write_bytes(bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0x0D]))

    # The whole content tree: three notes and the placeholder go; the PNG cannot.
    r = export_to_gist(v, folder="", api=api_for(server))
    assert r.created is True
    assert r.public is False
    assert r.skipped == [{"path": "Assets/real.png", "reason": "not_text"}]
    assert sorted(r.names) == [
        "Assets%2Fdiagram.png",
        "Notes%2FColumns.md",
        "Notes%2FHexes.md",
        "Notes%2FStart Here.md",
    ]
    sent = server.gists[r.id]
    assert sent["public"] is False
    assert sent["files"]["Notes%2FHexes.md"] == (FIXTURE / "content/Notes/Hexes.md").read_text(encoding="utf-8")


def test_export_a_subfolder_is_named_relative_to_itself(server: FakeGists, tmp_path: Path) -> None:
    _, v = copy_of_vault(tmp_path)
    r = export_to_gist(v, folder="Notes/", api=api_for(server), public=True, description="d")
    assert sorted(r.names) == ["Columns.md", "Hexes.md", "Start Here.md"]
    assert r.public is True
    assert server.gists[r.id]["description"] == "d"


def test_export_a_principal_sends_only_what_it_may_read_and_the_rest_is_counted_not_named(
    server: FakeGists, tmp_path: Path
) -> None:
    _, v = copy_of_vault(tmp_path)
    v.reindex()
    r = export_to_gist(v, folder="Notes/", api=api_for(server), principal="u:reader")
    assert sorted(r.names) == ["Hexes.md", "Start Here.md"]
    assert r.withheld == 1
    assert "Columns" not in repr(r), "a withheld path must not be named"
    owner = export_to_gist(v, folder="Notes/", api=api_for(server), principal="u:carter")
    assert len(owner.names) == 3


def test_export_dry_run_works_out_the_files_and_makes_no_request(server: FakeGists, tmp_path: Path) -> None:
    _, v = copy_of_vault(tmp_path)
    r = export_to_gist(v, folder="Notes/", api=api_for(server), dry_run=True)
    assert r.dry_run is True
    assert r.count == 3
    assert server.requests == []
    assert server.gists == {}


def test_export_empty_and_blank_files_are_left_out_named_and_an_all_empty_folder_is_an_error(
    server: FakeGists, tmp_path: Path
) -> None:
    d, v = copy_of_vault(tmp_path)
    (d / "content/Odd").mkdir()
    (d / "content/Odd/zero.md").write_text("")
    (d / "content/Odd/blank.md").write_text(" \n\n")
    with pytest.raises(RuntimeError, match="nothing to export"):
        export_to_gist(v, folder="Odd/", api=api_for(server))
    (d / "content/Odd/real.md").write_text("# real\n")
    r = export_to_gist(v, folder="Odd/", api=api_for(server))
    assert r.names == ["real.md"]
    assert [(x["path"], x["reason"]) for x in r.skipped] == [
        ("Odd/blank.md", "empty"),
        ("Odd/zero.md", "empty"),
    ]
    assert len(server.requests) == 1, "one create; the empty files never went out"


def test_export_a_file_name_the_protocol_forbids_is_named_as_left_out_not_lost_quietly(
    server: FakeGists, tmp_path: Path
) -> None:
    d, v = copy_of_vault(tmp_path)
    # "Café" spelled with a combining accent: §1.1 requires NFC, so it is no object of the vault.
    (d / "content/Notes/Café.md").write_text("# decomposed\n")
    r = export_to_gist(v, folder="Notes/", api=api_for(server))
    assert [x["reason"] for x in r.skipped] == ["invalid_key"]
    assert r.count == 3


def test_export_more_files_than_a_gist_shows_is_refused_before_anything_is_sent(
    server: FakeGists, tmp_path: Path
) -> None:
    d, v = copy_of_vault(tmp_path)
    (d / "content/Many").mkdir()
    for i in range(301):
        (d / f"content/Many/n{i}.md").write_text(f"n{i}\n")
    with pytest.raises(RuntimeError, match="more than a gist shows"):
        export_to_gist(v, folder="Many/", api=api_for(server))
    assert server.requests == []


def test_export_public_goes_with_a_new_gist_only_and_prune_with_update_only(
    server: FakeGists, tmp_path: Path
) -> None:
    _, v = copy_of_vault(tmp_path)
    with pytest.raises(RuntimeError, match="cannot change sides"):
        export_to_gist(v, folder="Notes/", api=api_for(server), update="abcde", public=True)
    with pytest.raises(RuntimeError, match="--prune is for --update"):
        export_to_gist(v, folder="Notes/", api=api_for(server), prune=True)
    with pytest.raises(RuntimeError, match="operator"):
        export_to_gist(v, whole=True, folder="", api=api_for(server), principal="u:reader")
    assert server.requests == []


def test_export_update_writes_what_changed_and_leaves_the_gists_other_files_unless_pruned(
    server: FakeGists, tmp_path: Path
) -> None:
    d, v = copy_of_vault(tmp_path)
    first = export_to_gist(v, folder="Notes/", api=api_for(server))
    server.gists[first.id]["files"]["mine.txt"] = "something I added on the website"

    # Nothing changed: no PATCH at all.
    before = len(server.requests)
    same = export_to_gist(v, folder="Notes/", api=api_for(server), update=first.id)
    assert same.updated is False
    assert same.unchanged == 3
    assert same.left == ["mine.txt"]
    assert sum(1 for r in server.requests[before:] if r["method"] == "PATCH") == 0

    # One note edited, one added: those two are written, the rest untouched.
    (d / "content/Notes/Hexes.md").write_text("# changed\n")
    (d / "content/Notes/New.md").write_text("# new\n")
    r = export_to_gist(v, folder="Notes/", api=api_for(server), update=first.id)
    assert r.written == 2
    assert r.unchanged == 2
    assert r.removed == 0
    assert "mine.txt" in server.gists[first.id]["files"], "a file basalt did not write is kept"
    assert server.gists[first.id]["files"]["Hexes.md"] == "# changed\n"

    # --prune takes out what the folder no longer has, and only that.
    (d / "content/Notes/New.md").unlink()
    p = export_to_gist(v, folder="Notes/", api=api_for(server), update=first.id, prune=True)
    assert p.removed == 2  # New.md and mine.txt
    assert sorted(server.gists[first.id]["files"]) == ["Columns.md", "Hexes.md", "Start Here.md"]


# ------------------------------------------------------------------ import

ULID = re.compile(r"^[0-9a-hjkmnp-tv-z]{26}$")


def test_import_every_file_lands_as_a_new_object_with_an_id_and_a_second_import_refuses(
    server: FakeGists, tmp_path: Path
) -> None:
    _, v = copy_of_vault(tmp_path)
    gist_id = server.seed(
        {
            "Intro.md": "# Intro\n\nSee [[Hexes]].\n",
            "Deep%2FNested%2Fnote.md": "nested\n",
            "data.json": '{"a": 1}\n',
        }
    )

    r = import_from_gist(v, api=api_for(server, None), id=gist_id, to="Gists/x/")
    assert r.refused == []
    assert sorted(o.path for o in r.stored) == [
        "Gists/x/Deep/Nested/note.md",
        "Gists/x/Intro.md",
        "Gists/x/data.json",
    ]
    for o in r.stored:
        assert ULID.match(o.id)
    intro = (v.t.get("content/Gists/x/Intro.md") or b"").decode("utf-8")
    assert re.match(r"^---\n[\s\S]*?id: [0-9a-z]{26}[\s\S]*?\n---\n# Intro", intro)
    idx = v.reindex()
    assert [e for e in idx["integrity"]["entries"] if e.get("severity") == "error"] == []

    again = import_from_gist(v, api=api_for(server, None), id=gist_id, to="Gists/x/")
    assert again.stored == []
    assert len(again.refused) == 3
    assert "already exists" in again.refused[0]["error"]
    # Reading a gist took no token, and sent none.
    assert all(q["auth"] is None for q in server.requests)


def test_import_one_bad_name_is_refused_and_the_others_still_go(server: FakeGists, tmp_path: Path) -> None:
    _, v = copy_of_vault(tmp_path)
    gist_id = server.seed(
        {"ok.md": "fine\n", "a%2F..%2Fb.md": "escapes\n", "Notes%2FHexes.md": "taken?\n"}
    )
    # Into the vault root, so "Notes/Hexes.md" is a path that is already taken.
    r = import_from_gist(v, api=api_for(server, None), id=gist_id, to="")
    assert [o.path for o in r.stored] == ["ok.md"]
    assert len(r.refused) == 2
    assert any("not a valid path" in x["error"] for x in r.refused)
    assert any("already exists" in x["error"] for x in r.refused)
    # The note that was taken is untouched, and nothing went outside the vault.
    assert "Hexagons" in (v.t.get("content/Notes/Hexes.md") or b"").decode("utf-8")


def test_import_a_principal_needs_create_child_on_the_folder(server: FakeGists, tmp_path: Path) -> None:
    _, v = copy_of_vault(tmp_path)
    v.reindex()
    gist_id = server.seed({"a.md": "x\n"})
    r = import_from_gist(v, api=api_for(server, None), id=gist_id, to="Notes/", principal="u:reader")
    assert r.stored == []
    assert len(r.refused) == 1
    assert v.t.get("content/Notes/a.md") is None


def test_import_a_file_the_listing_truncated_is_fetched_whole(make_server: Any, tmp_path: Path) -> None:
    s = make_server(truncate_over=20)
    _, v = copy_of_vault(tmp_path)
    body = f"# Long\n\n{'word ' * 40}\n"
    gist_id = s.seed({"long.md": body})
    r = import_from_gist(v, api=api_for(s, None), id=gist_id, to="In/")
    assert len(r.stored) == 1
    assert (v.t.get("content/In/long.md") or b"").decode("utf-8").endswith(body)


def test_round_trip_export_a_folder_import_it_elsewhere_the_text_survives(
    server: FakeGists, tmp_path: Path
) -> None:
    _, a = copy_of_vault(tmp_path, "a")
    _, b = copy_of_vault(tmp_path, "b")
    out = export_to_gist(a, folder="Notes/", api=api_for(server))
    back = import_from_gist(b, api=api_for(server, None), id=out.id, to="Copy/")
    assert back.refused == []
    assert len(back.stored) == 3

    def strip(x: str) -> str:
        return re.sub(r"^---\n[\s\S]*?\n---\n", "", x)

    for name in ("Columns", "Hexes", "Start Here"):
        orig = (a.t.get(f"content/Notes/{name}.md") or b"").decode("utf-8")
        copy = (b.t.get(f"content/Copy/{name}.md") or b"").decode("utf-8")
        assert strip(copy) == strip(orig), name
        # A fresh identity, not the source vault's.
        old = re.search(r"id: (\w+)", orig)
        new = re.search(r"id: (\w+)", copy)
        assert new is not None
        assert old is None or new.group(1) != old.group(1)


# ------------------------------------------------------------- gist store


def test_store_a_whole_vault_in_a_gist_opens_reads_and_a_batch_of_writes_is_one_revision(
    server: FakeGists, tmp_path: Path
) -> None:
    _, v = copy_of_vault(tmp_path)
    out = export_to_gist(v, whole=True, folder="", api=api_for(server))
    assert "basalt.yaml" in out.names
    assert "content%2FNotes%2FHexes.md" in out.names

    g = Vault(GistTransport(out.id, api=api_for(server)))
    g.t.ready()  # type: ignore[attr-defined]
    g.load()
    idx = g.reindex()
    assert len([e for e in idx["nodes"]["entries"] if e["path"].startswith("Notes/")]) == 3

    assert server.patches() == 0
    stored = store_object(g, path="Notes/Added.md", data=b"# Added\n")
    assert stored.created is True
    assert server.patches() == 1, "the note and the refreshed indexes went out as one PATCH"
    files = server.gists[out.id]["files"]
    assert "content%2FNotes%2FAdded.md" in files
    assert "index%2Fnodes.json" in files

    # A second process sees it.
    other = Vault(GistTransport(out.id, api=api_for(server, None), ttl=0))
    other.t.ready()  # type: ignore[attr-defined]
    other.load()
    assert other.t.get("content/Notes/Added.md") is not None
    with pytest.raises(StoreFault, match="never overwrite"):
        store_object(g, path="Notes/Added.md", data=b"again")


def test_store_what_a_gist_cannot_hold_is_refused_by_name_not_mangled(server: FakeGists) -> None:
    gist_id = server.seed({"basalt.yaml": "basalt: 1\n"})
    tr = GistTransport(gist_id, api=api_for(server))
    tr.ready()
    with pytest.raises(GistError, match="not UTF-8 text") as err:
        tr.put("content/Assets/a.png", bytes([0x89, 0x50, 0, 1]))
    assert err.value.code == "unsupported"
    with pytest.raises(GistError, match="empty") as err:
        tr.put("content/Notes/empty.md", b"")
    assert err.value.code == "unsupported"
    with pytest.raises(GistError, match="longer than") as err:
        tr.put("content/" + "x" * 300 + ".md", b"x")
    assert err.value.code == "unsupported"
    assert server.patches() == 0


def test_store_list_stat_delete_and_a_conditional_put_behave_like_the_others(server: FakeGists) -> None:
    gist_id = server.seed(
        {"basalt.yaml": "basalt: 1\n", "content%2FA%2Fb.md": "hello\n", "content%2FA%2Fc.md": "c\n"}
    )
    tr = GistTransport(gist_id, api=api_for(server), ttl=0)
    tr.ready()

    assert sorted(tr.list("content/A/").keys) == ["content/A/b.md", "content/A/c.md"]
    top = tr.list("", delimiter="/")
    assert top.keys == ["basalt.yaml"]
    assert top.prefixes == ["content/"]
    st = tr.stat("content/A/b.md")
    assert st is not None
    assert st.size == 6
    assert st.etag is not None and re.match(r'^"[0-9a-f]{32}"$', st.etag)
    assert tr.get("content/A/zzz.md") is None
    assert tr.stat("content/A/zzz.md") is None

    # Create-only: refused when the key exists, allowed when it does not.
    with pytest.raises(PreconditionFailed):
        tr.put("content/A/b.md", b"x", if_match=None)
    tr.put("content/A/new.md", b"n\n", if_match=None)
    assert server.gists[gist_id]["files"]["content%2FA%2Fnew.md"] == "n\n"
    # Stale etag.
    with pytest.raises(PreconditionFailed):
        tr.put("content/A/b.md", b"x", if_match='"stale"')

    tr.delete("content/A/c.md")
    tr.delete("content/A/never-existed.md")  # idempotent, and sends nothing for it
    assert "content%2FA%2Fc.md" not in server.gists[gist_id]["files"]


def test_store_a_gist_too_big_for_the_api_to_list_is_refused_up_front(server: FakeGists) -> None:
    gist_id = server.seed({f"f{i}.md": "x" for i in range(301)})
    with pytest.raises(GistError, match="clone it with git") as err:
        GistTransport(gist_id, api=api_for(server)).ready()
    assert err.value.code == "too_big"


# --------------------------------------------------------------------- CLI


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Any:
    """Run ``basalt`` in this process, with ``gh`` left off the PATH so a
    developer's own login cannot be found, and the environment pinned."""
    from basalt.cli import main

    def run(s: FakeGists, args: list[str], *, token: str | None = TOKEN) -> tuple[int, str, str]:
        monkeypatch.setenv("PATH", "/nonexistent")
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("GITHUB_TOKEN", token or "")
        monkeypatch.setenv("GH_TOKEN", "")
        monkeypatch.delenv("GITHUB_API_URL", raising=False)
        capsys.readouterr()
        code = main([*args, "--api-url", s.url])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return run


def test_cli_export_dry_run_export_then_import_into_a_vault_end_to_end(
    server: FakeGists, tmp_path: Path, cli: Any
) -> None:
    d, _ = copy_of_vault(tmp_path)
    other, _ = copy_of_vault(tmp_path, "other")
    (d / "content/Assets/real.png").write_bytes(bytes([0x89, 0x50, 0, 1]))

    code, out, err = cli(server, ["gist", "export", "Notes/", "--vault", str(d), "--dry-run"])
    assert code == 0, err
    assert re.search(r"would send 3 file\(s\).*secret gist", out)
    assert "Hexes.md" in out
    assert server.requests == []

    code, out, err = cli(server, ["gist", "export", "", "--vault", str(d)])
    assert code == 0, err
    assert re.search(r"created secret gist https://gist\.github\.com/test/[0-9a-f]{32}", out)
    assert "Secret means unlisted, not private" in out
    assert re.search(r"Assets/real\.png.*not text a gist can hold", out)
    gist_id = next(iter(server.gists))

    code, out, err = cli(
        server,
        ["gist", "import", f"https://gist.github.com/someone/{gist_id}", "--vault", str(other), "--to", "From/"],
        token=None,
    )
    assert code == 0, err
    assert re.search(r"stored\s+From/Notes/Hexes\.md", out)
    assert "4 stored, 0 refused" in out
    assert "Hexagons" in (other / "content/From/Notes/Hexes.md").read_text(encoding="utf-8")

    code, out, err = cli(server, ["gist", "import", gist_id, "--vault", str(other), "--to", "From/"], token=None)
    assert code == 1
    assert "already exists" in err


def test_cli_no_token_means_no_export_and_it_says_how_to_fix_that(
    server: FakeGists, tmp_path: Path, cli: Any
) -> None:
    d, _ = copy_of_vault(tmp_path)
    code, _, err = cli(server, ["gist", "export", "Notes/", "--vault", str(d)], token=None)
    assert code == 1
    assert "GITHUB_TOKEN" in err
    assert server.requests == []


def test_cli_gist_opens_a_vault_from_a_gist_and_a_token_is_never_taken_as_a_flag(
    server: FakeGists, tmp_path: Path, cli: Any
) -> None:
    d, _ = copy_of_vault(tmp_path)
    code, _, err = cli(server, ["gist", "export", "--whole", "--vault", str(d)])
    assert code == 0, err
    gist_id = next(iter(server.gists))

    code, out, err = cli(server, ["index", "--gist", gist_id], token=None)
    assert code == 0, err
    assert "4 nodes" in out

    code, _, err = cli(server, ["index", "--gist", gist_id, "--vault", str(d)])
    assert "pick one store" in err

    # There is no --token flag: it would end up in shell history and `ps`.
    before = server.posts()
    code, _, err = cli(server, ["gist", "export", "Notes/", "--vault", str(d), "--token", "x"], token=None)
    assert code == 1
    assert "no --token flag" in err
    assert server.posts() == before


def test_collect_lists_the_same_names_in_order_for_an_operator(tmp_path: Path) -> None:
    _, v = copy_of_vault(tmp_path)
    a = collect(v, folder="")
    b = collect(v, folder="")
    names = [f.name for f in a.files]
    assert names == [f.name for f in b.files]
    assert names == sorted(names)
