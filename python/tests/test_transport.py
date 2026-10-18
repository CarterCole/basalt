"""The five operations, PROTOCOL §1 (L0).

Both the local-filesystem and in-memory transports are held to the same
contract, because §1's whole point is that a vault behaves identically over
any substrate that provides it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from basalt.keys import BasaltKeyError
from basalt.transport import PreconditionFailed, Transport
from basalt.transport.local import LocalTransport
from basalt.transport.memory import MemoryTransport
from basalt.transport.s3 import PRESETS, S3Transport


@pytest.fixture(params=["memory", "local"])
def transport(request: Any, tmp_path: Path) -> Transport:
    if request.param == "memory":
        return MemoryTransport()
    return LocalTransport(tmp_path)


def test_get_missing_key_returns_none(transport: Transport) -> None:
    assert transport.get("content/nope.md") is None


def test_stat_missing_key_returns_none(transport: Transport) -> None:
    assert transport.stat("content/nope.md") is None


def test_put_then_get_is_read_after_write(transport: Transport) -> None:
    """§1 promises read-after-write for a single key, and nothing more."""
    stat = transport.put("content/a.md", b"hello")
    assert stat.size == 5
    assert transport.get("content/a.md") == b"hello"


def test_put_replaces_atomically(transport: Transport) -> None:
    transport.put("content/a.md", b"one")
    transport.put("content/a.md", b"two!")
    assert transport.get("content/a.md") == b"two!"
    stat = transport.stat("content/a.md")
    assert stat is not None and stat.size == 4


def test_delete_is_idempotent(transport: Transport) -> None:
    transport.put("content/a.md", b"x")
    assert transport.delete("content/a.md") is True
    assert transport.delete("content/a.md") is False
    assert transport.get("content/a.md") is None


def test_list_enumerates_under_a_prefix(transport: Transport) -> None:
    for key in ("content/Notes/a.md", "content/Notes/b.md", "content/Assets/c.png"):
        transport.put(key, b"x")
    transport.put("basalt.yaml", b"basalt: 1\n")

    assert sorted(transport.list("content/Notes/").keys) == [
        "content/Notes/a.md",
        "content/Notes/b.md",
    ]
    assert len(transport.list("content/").keys) == 3
    assert "basalt.yaml" in transport.list().keys


def test_list_with_a_delimiter_returns_common_prefixes(transport: Transport) -> None:
    for key in ("content/Notes/a.md", "content/Notes/Deep/b.md", "content/top.md"):
        transport.put(key, b"x")
    listing = transport.list("content/", delimiter="/")
    assert listing.keys == ["content/top.md"]
    assert listing.prefixes == ["content/Notes/"]


def test_put_validates_the_key(transport: Transport) -> None:
    """§1.1 — a conforming implementation MUST reject these on write."""
    for key, code in (
        ("", "KEY_EMPTY"),
        ("/content/a.md", "KEY_LEADING_SLASH"),
        ("content/a/", "KEY_TRAILING_SLASH"),
        ("content//a.md", "KEY_EMPTY_SEGMENT"),
        ("content/../a.md", "KEY_DOT_SEGMENT"),
        ("content/a\u0000b.md", "KEY_CONTROL_CHAR"),
        ("content/Café.md", "KEY_NOT_NFC"),
    ):
        with pytest.raises(BasaltKeyError) as excinfo:
            transport.put(key, b"x")
        assert excinfo.value.code == code, key


def test_key_longer_than_1024_bytes_is_refused(transport: Transport) -> None:
    with pytest.raises(BasaltKeyError) as excinfo:
        transport.put("content/" + "a" * 1100, b"x")
    assert excinfo.value.code == "KEY_TOO_LONG"


def test_conditional_put_surfaces_a_conflict(transport: Transport) -> None:
    """§11.3 — a failed condition MUST be a conflict, never a blind retry.

    Last-write-wins on a knowledge vault silently destroys work.
    """
    assert "conditional_put" in transport.capabilities
    first = transport.put("content/a.md", b"one", if_match=None)

    # if_match=None means "must not exist", so a second create fails.
    with pytest.raises(PreconditionFailed):
        transport.put("content/a.md", b"two", if_match=None)

    # The etag the writer read lets the update through; a stale one does not.
    transport.put("content/a.md", b"two", if_match=first.etag)
    with pytest.raises(PreconditionFailed):
        transport.put("content/a.md", b"three", if_match=first.etag)


def test_etag_changes_with_content(transport: Transport) -> None:
    a = transport.put("content/a.md", b"one")
    b = transport.put("content/a.md", b"two")
    assert a.etag != b.etag


def test_presign_is_not_offered_by_these_transports(transport: Transport) -> None:
    assert "presign" not in transport.capabilities
    with pytest.raises(NotImplementedError):
        transport.presign("content/a.md")


# ---------------------------------------------------------------- local only


def test_local_refuses_a_key_escaping_the_root(tmp_path: Path) -> None:
    """The transport is the last line of defense against path traversal."""
    transport = LocalTransport(tmp_path / "vault")
    with pytest.raises(ValueError, match="escapes vault root"):
        transport.get("../../etc/passwd")


def test_local_vault_is_a_plain_folder(tmp_path: Path) -> None:
    """§3 — point a text editor at ``content/`` and it works."""
    transport = LocalTransport(tmp_path)
    transport.put("content/Notes/Hexes.md", b"# Hexagons\n")
    assert (tmp_path / "content" / "Notes" / "Hexes.md").read_text() == "# Hexagons\n"


def test_local_list_skips_in_flight_writes_and_droppings(tmp_path: Path) -> None:
    transport = LocalTransport(tmp_path)
    transport.put("content/a.md", b"x")
    (tmp_path / "content" / "b.md.1234.tmp").write_bytes(b"half")
    (tmp_path / "content" / ".DS_Store").write_bytes(b"junk")
    assert transport.list("content/").keys == ["content/a.md"]


def test_local_never_writes_directory_markers(tmp_path: Path) -> None:
    """§2.1 — folders are virtual; there is no such thing as an empty folder."""
    transport = LocalTransport(tmp_path)
    transport.put("content/Notes/a.md", b"x")
    transport.delete("content/Notes/a.md")
    assert transport.list("content/").keys == []


# ------------------------------------------------------------------- S3 only


def test_s3_flavor_presets_match_what_each_store_needs() -> None:
    """The three stores disagree in ways §1 pushes into the adapter."""
    r2 = S3Transport(bucket="b", flavor="r2", endpoint="https://x.r2.example")
    assert r2.region == "auto"  # R2 requires it
    assert r2.relax_checksums is True  # R2 rejects the newer integrity headers
    assert r2.force_path_style is False  # R2 prefers virtual-host style

    minio = S3Transport(bucket="b", flavor="minio", endpoint="http://localhost:9000")
    assert minio.force_path_style is True  # self-hosted gateways need it
    assert minio.relax_checksums is True

    s3 = S3Transport(bucket="b", flavor="s3", region="us-west-2")
    assert s3.region == "us-west-2"
    assert s3.force_path_style is False
    assert s3.relax_checksums is False

    assert set(PRESETS) == {"s3", "minio", "r2"}


def test_s3_declares_presign_and_caps_its_ttl() -> None:
    """§12.4 — a presigned URL is a bearer token that outlives its ACL check."""
    transport = S3Transport(bucket="b")
    assert "presign" in transport.capabilities
    with pytest.raises(ValueError, match="300s"):
        transport.presign("content/a.md", ttl_seconds=3600)


def test_s3_requires_a_bucket_and_a_trailing_slash_on_the_prefix() -> None:
    with pytest.raises(ValueError, match="bucket is required"):
        S3Transport(bucket="")
    with pytest.raises(ValueError, match="must end in /"):
        S3Transport(bucket="b", prefix="vaults/mine")


def test_s3_prefix_is_transparent_to_keys() -> None:
    transport = S3Transport(bucket="b", prefix="vaults/mine/")
    assert transport._full("content/a.md") == "vaults/mine/content/a.md"
    assert transport._strip("vaults/mine/content/a.md") == "content/a.md"
