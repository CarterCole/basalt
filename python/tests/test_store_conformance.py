"""Runs ``conformance/cases/store/creation.yaml``, PROTOCOL §12.7.

The TypeScript and Rust runners execute the same file, so the three write
paths agree on every case it holds. Expectations live in the corpus.
"""

from __future__ import annotations

import base64
import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from basalt import yamlio
from basalt.frontmatter import is_ulid, split_frontmatter
from basalt.store import (
    Provenance,
    StoreFault,
    check_provenance_label,
    normalize_caller,
    store_object,
)
from basalt.transport.local import LocalTransport
from basalt.vault import Vault

from .conftest import CONFORMANCE, corpus

SUITE = corpus("cases/store/creation.yaml")
AT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _bytes(req: dict[str, Any]) -> bytes:
    if req.get("base64") is not None:
        return base64.b64decode(req["base64"], validate=True)
    return (req.get("text") or "").encode("utf-8")


def _provenance(req: dict[str, Any]) -> Provenance | None:
    if "provenance" not in req:
        return None
    p = req["provenance"] or {}
    return Provenance(
        agent=p.get("agent"), account=p.get("account"), caller=p.get("caller"), client=p.get("client")
    )


def _store(v: Vault, req: dict[str, Any]) -> Any:
    return store_object(
        v,
        path=req.get("path"),
        data=_bytes(req),
        principal=req.get("principal"),
        title=req.get("title"),
        alt=req.get("alt"),
        provenance=_provenance(req),
    )


def _file_at(p: Path) -> bytes | None:
    try:
        return p.read_bytes() if p.is_file() else None
    except OSError:  # a name the filesystem cannot hold is not a file
        return None


@pytest.mark.parametrize("case", SUITE["cases"], ids=[c["name"] for c in SUITE["cases"]])
def test_store_corpus(case: dict[str, Any], tmp_path: Path) -> None:
    if case["kind"] == "label":
        try:
            check_provenance_label("agent", case["value"])
            ok = True
        except StoreFault:
            ok = False
        assert ok is case["ok"]
        return
    if case["kind"] == "caller":
        try:
            out = normalize_caller(case["value"])
        except StoreFault:
            out = None
        assert out == case["out"]
        return

    root = tmp_path / "vault"
    shutil.copytree(CONFORMANCE / "vaults/minimal/vault", root)
    v = Vault(LocalTransport(root)).load()
    v.reindex(write=True)
    for g in case.get("given") or []:
        _store(v, g)

    req = case["request"]
    path = req["path"]
    key = root / "content" / path
    index_before = (root / "index/nodes.json").read_text(encoding="utf-8")
    folder = path.rsplit("/", 1)[0] if "/" in path else None
    def sidecar_file(f: str) -> Path:
        return root / "meta/folders" / f / "entries.yaml"

    sidecar_before = (
        yamlio.load(sidecar_file(folder).read_text(encoding="utf-8"), {})
        if folder and sidecar_file(folder).is_file()
        else {}
    )

    if "refused" in case:
        before = _file_at(key)
        with pytest.raises(StoreFault) as err:
            _store(v, req)
        assert err.value.code == case["refused"], str(err.value)
        assert _file_at(key) == before, "the key is as it was"
        assert (root / "index/nodes.json").read_text(encoding="utf-8") == index_before
        return

    r = _store(v, req)
    assert r.kind == case["stored"]
    assert is_ulid(r.id)

    fresh = Vault(LocalTransport(root)).load()
    idx = fresh.reindex()
    entry = next((e for e in idx["nodes"]["entries"] if e["path"] == path), None)
    assert entry is not None, "the object is indexed"
    assert entry["id"] == r.id
    assert not any(e["id"] == r.id and e["path"] != path for e in idx["nodes"]["entries"])
    stored = json.loads((root / "index/nodes.json").read_text(encoding="utf-8"))
    assert any(e["path"] == path and e["id"] == r.id for e in stored["entries"]), "indexes are fresh"
    if "title" in case:
        assert entry["title"] == case["title"]

    on_disk = key.read_bytes()
    if case["stored"] == "note":
        fm = yamlio.load(split_frontmatter(on_disk.decode("utf-8")).raw or "", {})
        assert fm["basalt"]["id"] == r.id
        stamp = fm["basalt"].get("created_by")
    else:
        assert on_disk == _bytes(req), "stored byte for byte"
        sc = yamlio.load(sidecar_file(folder).read_text(encoding="utf-8"), {})
        own = sc["entries"][path.rsplit("/", 1)[1]]
        assert own["id"] == r.id
        if "alt" in case:
            assert own.get("alt") == case["alt"]
        for name in case.get("sidecar_keeps") or []:
            assert sc["entries"][name] == sidecar_before["entries"][name], f"{name} kept"
        stamp = own.get("created_by")

    if "created_by" in case:
        if case["created_by"] is None:
            assert stamp is None
        else:
            stamp = dict(stamp)
            at = str(stamp.pop("at"))
            assert AT.fullmatch(at), at
            assert stamp == case["created_by"]
