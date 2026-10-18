"""Runs the language-neutral ACL corpus, PROTOCOL §14.2 (L3).

Each case asserts the deciding ACE, not just the boolean: two implementations
can agree on "denied" for different reasons and only one of them is following
§8.4. Checking the decider catches the band-ordering bug a boolean assertion
misses.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from basalt.acl import Principals
from basalt.security import DescriptorStore, check_access

from .conftest import corpus

_CORPUS = corpus("cases/acl/evaluation.yaml")

_PRINCIPALS = Principals(
    users=_CORPUS["principals"]["users"],
    groups=_CORPUS["principals"]["groups"],
    roles=_CORPUS["principals"]["roles"],
)


def _build_store(descriptors: dict[str, Any] | None) -> DescriptorStore:
    """Turn a case's ``descriptors`` map into a store.

    A key of ``/`` or one ending in ``/`` is a folder descriptor; anything
    else names a node, which the case supplies the way an inline frontmatter
    ACL would (§8.6).
    """
    folder_acls: dict[str, Any] = {}
    inline_acls: dict[str, Any] = {}
    for path, descriptor in (descriptors or {}).items():
        if path == "/" or path.endswith("/"):
            folder_acls["" if path == "/" else path] = {
                "folder": descriptor,
                "entries": {},
            }
        else:
            inline_acls[path] = descriptor
    return DescriptorStore(folder_acls=folder_acls, inline_acls=inline_acls)


def _merge_manifest(defaults: Any, override: Any) -> dict[str, Any]:
    """Deep-merge a case's ``manifest`` over the corpus ``defaults.manifest``."""
    out = copy.deepcopy(defaults or {})
    for k, v in (override or {}).items():
        if isinstance(v, dict) and not isinstance(out.get(k), type(None)):
            out[k] = _merge_manifest(out.get(k), v)
        elif isinstance(v, dict):
            out[k] = _merge_manifest({}, v)
        else:
            out[k] = v
    return out


def _opts_for(case: dict[str, Any]) -> dict[str, Any]:
    manifest = _merge_manifest(
        (_CORPUS.get("defaults") or {}).get("manifest"), case.get("manifest")
    )
    publish = manifest.get("publish") or {}
    security = manifest.get("security") or {}
    return {
        "audience": publish.get("audience") or "gated",
        "bypass_traverse": bool(security.get("bypass_traverse", False)),
        "deny_unresolved": security.get("deny_unresolved", True) is not False,
    }


@pytest.mark.parametrize("case", _CORPUS["cases"], ids=lambda c: c["name"])
def test_acl_case(case: dict[str, Any]) -> None:
    store = _build_store(case.get("descriptors"))
    # A case carries either one `request` or a list of `requests`.
    requests = case.get("requests") or [{**case["request"], "expect": case["expect"]}]

    for req in requests:
        result = check_access(
            store=store,
            principals=_PRINCIPALS,
            principal_id=req["principal"],
            path=req["path"],
            rights=req["rights"],
            **_opts_for(case),
        )

        for right, want in req["expect"].items():
            got = result.decisions.get(right)
            assert got is not None, f"{case['name']}: no decision for {right}"
            where = f"{case['name']} [{req['principal']} {right} {req['path']}]"
            assert got["decision"] == want["decision"], (
                f"{where}: decision {got['decision']} (by {got['by']}), "
                f"want {want['decision']} (by {want['by']})"
            )
            assert got["by"] == want["by"], (
                f"{where}: decided by {got['by']}, want {want['by']}"
            )
            if "failed_at" in want:
                assert got.get("failed_at") == want["failed_at"], (
                    f"{where}: failed_at {got.get('failed_at')}, "
                    f"want {want['failed_at']}"
                )

        if "overall" in case:
            assert result.allowed == (case["overall"] == "allow"), (
                f"{case['name']}: overall {result.allowed}"
            )

    # Integrity expectations (§7.2 cycles, §8.4 unresolvable subjects).
    for want in case.get("integrity") or []:
        if want["code"] == "GROUP_CYCLE":
            assert any(
                i["code"] == "GROUP_CYCLE" for i in _PRINCIPALS.integrity
            ), f"{case['name']}: expected a GROUP_CYCLE integrity report"
        else:
            # The condition is detected while evaluating the request itself,
            # so re-run and look at what the evaluation collected.
            result = check_access(
                store=_build_store(case.get("descriptors")),
                principals=_PRINCIPALS,
                principal_id=case["request"]["principal"],
                path=case["request"]["path"],
                rights=case["request"]["rights"],
                **_opts_for(case),
            )
            assert any(
                i["code"] == want["code"] and i.get("subject") == want.get("subject")
                for i in result.integrity
            ), f"{case['name']}: expected {want['code']} for {want.get('subject')}"


def test_group_cycle_reported_once_and_expansion_terminates() -> None:
    """§7.2 — a membership cycle must terminate and still yield the reachable set."""
    assert any(i["code"] == "GROUP_CYCLE" for i in _PRINCIPALS.integrity)
    # The cycle members are reachable from each other and the walk returns.
    assert _PRINCIPALS.groups_of("g:loop_a") == frozenset({"g:loop_a", "g:loop_b"})
    # And a real user's transitive closure is unaffected by the cycle (§7.2).
    assert _PRINCIPALS.groups_of("u:editor") == frozenset({"g:editors", "g:staff"})


def test_an_undefined_role_denies_rather_than_being_dropped() -> None:
    """§7.4 and §8.4 — and a divergence from the TypeScript reference.

    §7.4: "An ACE naming an undefined role is an integrity error and MUST be
    treated per ``security.deny_unresolved``." §8.4 says what that treatment
    is: "when ``true`` (the default and the recommended setting) the ACE is
    treated as a deny of all its rights; when ``false`` it is dropped."

    So an allow ACE carrying ``rights: [read, typorole]`` must *deny* ``read``
    under the default. The reference implementation instead drops the unknown
    name and honors the rest of the ACE, allowing ``read``. No corpus case
    covers it, so both pass conformance — the hole sits exactly where §8.4's
    "safe direction" default lives.
    """
    store = DescriptorStore(
        inline_acls={
            "Notes/A.md": {
                "dacl": [
                    {
                        "id": "X1",
                        "type": "allow",
                        "subject": "u:reader",
                        "rights": ["read", "typorole"],
                        "flags": [],
                    }
                ]
            }
        }
    )
    common = {
        "store": store,
        "principals": _PRINCIPALS,
        "principal_id": "u:reader",
        "path": "Notes/A.md",
        "rights": ["read"],
        "audience": "gated",
        "bypass_traverse": True,
    }

    strict = check_access(**common, deny_unresolved=True)
    assert strict.decisions["read"] == {"decision": "deny", "by": "X1"}
    assert any(i["code"] == "UNRESOLVED_RIGHT" for i in strict.integrity)

    lenient = check_access(**common, deny_unresolved=False)
    assert lenient.decisions["read"]["decision"] == "allow"
