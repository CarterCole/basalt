"""Gatekeeper behavior, PROTOCOL §12 (L4).

The tests that matter most here are the two leak boundaries: §12.3's 404/403
split, where returning 403 on a path the requester was not allowed to discover
confirms that path exists, and §12.5's cache key, which §12.5 itself names as
the single most likely place for a conforming-looking implementation to leak.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import pytest

from basalt.gatekeeper import Gatekeeper
from basalt.transport.local import LocalTransport
from basalt.vault import Vault

from .conftest import CONFORMANCE

VAULT = CONFORMANCE / "vaults" / "minimal" / "vault"


@dataclass
class Call:
    status: int
    body: Any
    headers: dict[str, str]


def _make_gatekeeper() -> Gatekeeper:
    vault = Vault(LocalTransport(VAULT))
    vault.load()
    vault.reindex()
    # A test-only identity source. §12.1 forbids letting a *client* assert its
    # own principal id; here the header is read by the server's own identify
    # callback, which is exactly where §12.1 puts the decision.
    return Gatekeeper(
        vault,
        identify=lambda headers, query: (
            (headers.get("x-test-principal") if headers else None) or "anonymous"
        ),
    )


@pytest.fixture
def gatekeeper() -> Gatekeeper:
    return _make_gatekeeper()


def call(
    gatekeeper: Gatekeeper, path: str, principal: str | None = None, method: str = "GET"
) -> Call:
    """Dispatch without a socket; the routing layer is the same code path."""
    headers = {"x-test-principal": principal} if principal else {}
    response = gatekeeper.dispatch(method, path, headers)
    payload = response.payload()
    try:
        body: Any = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        body = payload
    return Call(response.status, body, response.headers)


# ------------------------------------------------------------------ reads


def test_serves_a_readable_node_and_its_links(gatekeeper: Gatekeeper) -> None:
    r = call(gatekeeper, "/api/v1/node/Notes%2FHexes.md", "u:reader")
    assert r.status == 200
    assert r.body["node"]["title"] == "Hexagons"
    assert "Back to" in r.body["text"]
    assert r.headers["x-basalt-vault"] == "01JBQ7X8Z4N3VYK9M2T5HRWC6P"
    assert r.headers["x-basalt-index-state"]


def test_403_when_discoverable_404_when_not(gatekeeper: Gatekeeper) -> None:
    """§12.3 — the information-leak boundary."""
    # u:reader may list Notes/ so it knows Columns.md exists, but cannot read it.
    assert call(gatekeeper, "/api/v1/node/Notes%2FColumns.md", "u:reader").status == 403
    # A path that does not exist must be 404 — never 403, which would confirm
    # the path to someone not allowed to discover it.
    assert call(gatekeeper, "/api/v1/node/Notes%2FNope.md", "u:reader").status == 404
    assert call(gatekeeper, "/api/v1/node/Notes%2FColumns.md", "u:carter").status == 200


def test_anonymous_is_denied_under_a_gated_audience(gatekeeper: Gatekeeper) -> None:
    """§12.2 — the ceiling applies before §8.4 and can only narrow."""
    r = call(gatekeeper, "/api/v1/node/Notes%2FHexes.md")
    assert r.status in (403, 404), f"anonymous got {r.status} on a gated vault"


@pytest.mark.parametrize(
    "target",
    [
        "index/nodes.json",
        "index/links.json",
        "meta/acl/Notes/acl.yaml",
        "principals/users.yaml",
        "basalt.yaml",
    ],
)
def test_never_serves_the_protocol_trees(gatekeeper: Gatekeeper, target: str) -> None:
    """§12.4 — even to the vault owner: these leak the private half (§8.8)."""
    quoted = urllib.request.quote(target, safe="")
    assert call(gatekeeper, f"/api/v1/raw/{quoted}", "u:carter").status == 404


def test_raw_bytes_carry_the_right_media_type(gatekeeper: Gatekeeper) -> None:
    r = call(gatekeeper, "/api/v1/raw/Notes%2FHexes.md", "u:reader")
    assert r.status == 200
    assert "text/markdown" in r.headers["content-type"]


def test_listing_is_filtered_per_principal(gatekeeper: Gatekeeper) -> None:
    reader = call(gatekeeper, "/api/v1/list/Notes%2F", "u:reader")
    owner = call(gatekeeper, "/api/v1/list/Notes%2F", "u:carter")

    def paths(r: Call) -> list[str]:
        return [e["path"] for e in r.body["entries"]]

    assert "Notes/Columns.md" not in paths(reader)
    assert "Notes/Columns.md" in paths(owner)


def test_cache_is_keyed_by_subject_set(gatekeeper: Gatekeeper) -> None:
    """§12.5 — THE leak test.

    Warm the cache as the owner, then ask as the reader: if the cache key
    omits the subject set, the reader is served the owner's visibility and
    sees a note whose existence it may know but whose contents it must not.
    """
    owner = call(gatekeeper, "/api/v1/list/Notes%2F", "u:carter")
    assert any(e["path"] == "Notes/Columns.md" for e in owner.body["entries"])

    reader = call(gatekeeper, "/api/v1/list/Notes%2F", "u:reader")
    assert not any(e["path"] == "Notes/Columns.md" for e in reader.body["entries"]), (
        "the cache served one principal's visibility to another"
    )

    # And the reverse order, in case the first principal seen wins.
    fresh = _make_gatekeeper()
    r2 = call(fresh, "/api/v1/list/Notes%2F", "u:reader")
    o2 = call(fresh, "/api/v1/list/Notes%2F", "u:carter")
    assert not any(e["path"] == "Notes/Columns.md" for e in r2.body["entries"])
    assert any(e["path"] == "Notes/Columns.md" for e in o2.body["entries"])


def test_tree_is_pruned_to_what_the_principal_may_see(gatekeeper: Gatekeeper) -> None:
    r = call(gatekeeper, "/api/v1/tree", "u:reader")
    assert r.status == 200
    rendered = json.dumps(r.body)
    assert "Columns.md" not in rendered, "an unreadable node appeared in the tree"
    assert "Hexes.md" in rendered


def test_links_to_unreadable_nodes_come_back_redacted(gatekeeper: Gatekeeper) -> None:
    """§9.5 — a redacted edge is never removed, only replaced.

    Removing it would make the graph silently wrong, and a reader could not
    tell a redacted link from a dangling one.
    """
    r = call(gatekeeper, "/api/v1/links/Notes%2FHexes.md", "u:reader")
    assert r.status == 200
    edge = next((e for e in r.body["out"] if e["raw"] == "Columns"), None)
    assert edge is not None, "the edge was dropped instead of redacted"
    assert edge["to"] == "redacted"
    assert edge["target"]["title"] is None  # redact_titles defaults to true


def test_effective_rights_need_read_acl(gatekeeper: Gatekeeper) -> None:
    """§8.7 — the privileged "Effective Access" view."""
    # u:carter holds full_control on Columns.md, which includes read_acl.
    allowed = call(
        gatekeeper,
        "/api/v1/effective?path=Notes%2FColumns.md&principal=u:reader",
        "u:carter",
    )
    assert allowed.status == 200
    assert "read" not in allowed.body["granted"]
    assert allowed.body["decisions"]["read"]["by"], "no deciding ACE reported"

    # u:reader cannot inspect anyone's rights on it.
    denied = call(gatekeeper, "/api/v1/effective?path=Notes%2FColumns.md", "u:reader")
    assert denied.status == 403


def test_search_results_are_filtered_not_just_ranked(gatekeeper: Gatekeeper) -> None:
    r = call(gatekeeper, "/api/v1/search?q=cooling", "u:reader")
    assert r.status == 200
    # The vault is gated, so §8.8 left search.json empty; nothing may leak.
    assert r.body["hits"] == []


def test_rejects_writes(gatekeeper: Gatekeeper) -> None:
    r = call(gatekeeper, "/api/v1/node/Notes%2FHexes.md", "u:reader", method="POST")
    assert r.status == 405


def test_manifest_exposes_only_the_public_subset(gatekeeper: Gatekeeper) -> None:
    r = call(gatekeeper, "/api/v1/manifest", "u:reader")
    assert r.status == 200
    assert r.body["vault"]["id"] == "01JBQ7X8Z4N3VYK9M2T5HRWC6P"
    # §15: the manifest's security block controls enforcement globally, so it
    # is not part of the public subset §12.3 defines.
    assert "security" not in r.body


def test_unknown_route_is_404(gatekeeper: Gatekeeper) -> None:
    assert call(gatekeeper, "/api/v1/nope/x", "u:carter").status == 404
    assert call(gatekeeper, "/other", "u:carter").status == 404


# ------------------------------------------------------------ over a socket


def test_serves_over_a_real_socket() -> None:
    """The handler, not just the dispatcher: headers and status reach the wire."""
    gatekeeper = _make_gatekeeper()
    host, port = gatekeeper.start(port=0)
    try:
        request = urllib.request.Request(
            f"http://{host}:{port}/api/v1/node/Notes%2FHexes.md",
            headers={"x-test-principal": "u:reader"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert response.headers["x-basalt-vault"] == "01JBQ7X8Z4N3VYK9M2T5HRWC6P"
            body = json.loads(response.read().decode("utf-8"))
        assert body["node"]["title"] == "Hexagons"

        # And a denial reaches the wire with its own status.
        denied = urllib.request.Request(
            f"http://{host}:{port}/api/v1/node/Notes%2FColumns.md",
            headers={"x-test-principal": "u:reader"},
        )
        with pytest.raises(urllib.error.HTTPError) as excinfo:
            urllib.request.urlopen(denied, timeout=5)
        assert excinfo.value.code == 403
    finally:
        gatekeeper.close()
