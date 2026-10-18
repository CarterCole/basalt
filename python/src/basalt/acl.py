"""Principals and NTFS-style access control, PROTOCOL §7 and §8.

The band ordering in :func:`evaluate_chain` is where naive implementations go
wrong. §8.4 is explicit that deny beats allow only *within* a band: an
explicit allow on a note overrides an inherited deny from its folder, because
that is what makes "deny the whole tree, allow this one file" expressible. An
implementation that globally prioritizes deny over allow is not conforming.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any

#: Every right (§8.1), in the order the CLI reports them. ``full_control``
#: expands to this list at evaluation time, never baked into a stored ACE.
RIGHTS: tuple[str, ...] = (
    "read",
    "list",
    "traverse",
    "comment",
    "write",
    "create_child",
    "delete",
    "delete_child",
    "read_acl",
    "write_acl",
    "take_ownership",
    "read_history",
    "publish",
)

#: §7.3. Reserved: a vault must not define a user or group with any of these.
WELL_KNOWN = frozenset({"everyone", "anonymous", "authenticated", "owner", "system"})

#: §7.4. Five predefined role names, overridable by the vault.
DEFAULT_ROLES: dict[str, list[str]] = {
    "reader": ["read", "list", "traverse"],
    "commenter": ["read", "list", "traverse", "comment"],
    "editor": [
        "read",
        "list",
        "traverse",
        "comment",
        "write",
        "create_child",
        "delete_child",
    ],
    "owner": ["full_control"],
    "auditor": ["read", "list", "traverse", "read_acl", "read_history"],
}


def _parse_timestamp(value: Any) -> dt.datetime | None:
    """Parse an RFC 3339 timestamp, tolerating a YAML-parsed datetime."""
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    if isinstance(value, dt.date):
        return dt.datetime(value.year, value.month, value.day, tzinfo=dt.UTC)
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


@dataclass
class ExpandedRights:
    rights: set[str]
    unresolved: list[str]


class Principals:
    """Principal directory: users, groups and roles, with transitive membership."""

    def __init__(
        self,
        users: list[dict[str, Any]] | None = None,
        groups: list[dict[str, Any]] | None = None,
        roles: dict[str, list[str]] | None = None,
    ) -> None:
        self.users: dict[str, dict[str, Any]] = {
            u["id"]: u for u in (users or []) if isinstance(u, dict) and u.get("id")
        }
        self.groups: dict[str, dict[str, Any]] = {
            g["id"]: g for g in (groups or []) if isinstance(g, dict) and g.get("id")
        }
        self.roles: dict[str, list[str]] = {**DEFAULT_ROLES, **(roles or {})}
        self.integrity: list[dict[str, str]] = []
        self._groups_cache: dict[str, frozenset[str]] = {}
        self._validate()

    def _validate(self) -> None:
        for pid in [*self.users, *self.groups]:
            if pid in WELL_KNOWN:
                # §7.3: these ids are reserved, and a principals file that
                # redefines one must be rejected.
                self.integrity.append(
                    {
                        "severity": "error",
                        "code": "RESERVED_PRINCIPAL_ID",
                        "subject": pid,
                    }
                )
        # §7.2: detect membership cycles once, up front. The expansion below
        # is cycle-safe regardless, but a cycle is an integrity error and the
        # vault owner needs to be told.
        for gid in self.groups:
            if self._has_cycle(gid, set()):
                self.integrity.append(
                    {"severity": "error", "code": "GROUP_CYCLE", "subject": gid}
                )

    def _has_cycle(self, gid: str, seen: set[str]) -> bool:
        if gid in seen:
            return True
        group = self.groups.get(gid)
        if group is None:
            return False
        seen = seen | {gid}
        for member in group.get("members") or []:
            if member in self.groups and self._has_cycle(member, seen):
                return True
        return False

    def exists(self, pid: object) -> bool:
        """True when the id names a known user, group or well-known principal."""
        return pid in WELL_KNOWN or pid in self.users or pid in self.groups

    def is_active(self, user_id: str) -> bool:
        """Is this user active? Suspended and expired both count as inactive (§7.1)."""
        user = self.users.get(user_id)
        if user is None:
            return False
        status = user.get("status")
        if status and status != "active":
            return False
        expires = _parse_timestamp(user.get("expires"))
        if expires is not None and expires <= dt.datetime.now(dt.UTC):
            return False
        return True

    def groups_of(self, principal_id: str) -> frozenset[str]:
        """Every group reachable from a principal, transitively (§7.2).

        Cycle-safe: §7.2 requires that a membership cycle still terminate and
        yield the reachable set rather than hanging or overflowing, so the
        walk tracks what it has visited.
        """
        cached = self._groups_cache.get(principal_id)
        if cached is not None:
            return cached

        out: set[str] = set()
        seen: set[str] = set()
        stack = [principal_id]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            for gid, group in self.groups.items():
                if current in (group.get("members") or []) and gid not in out:
                    out.add(gid)
                    stack.append(gid)

        frozen = frozenset(out)
        self._groups_cache[principal_id] = frozen
        return frozen

    def expand_rights(self, rights: Any) -> ExpandedRights:
        """Expand a rights list, resolving roles and ``full_control`` (§7.4, §8.1).

        Roles are expanded at evaluation time, never baked into stored ACEs,
        so editing a role changes every ACE that names it.
        """
        out: set[str] = set()
        unresolved: list[str] = []
        self._expand_into(rights, out, unresolved, set())
        return ExpandedRights(rights=out, unresolved=unresolved)

    def _expand_into(
        self, rights: Any, out: set[str], unresolved: list[str], visiting: set[str]
    ) -> None:
        for r in rights or []:
            if not isinstance(r, str):
                continue
            if r == "full_control":
                out.update(RIGHTS)
                continue
            if r in RIGHTS:
                out.add(r)
                continue
            if r in self.roles:
                # A role that names itself would recurse forever; a vault can
                # contain that typo, and refusing to terminate is not an
                # option for a publishing system.
                if r in visiting:
                    unresolved.append(r)
                    continue
                self._expand_into(self.roles[r], out, unresolved, visiting | {r})
                continue
            unresolved.append(r)


def subject_set(
    principals: Principals, principal_id: str, owner: object = None
) -> set[str]:
    """The subject set for a request (§8.4 step 1).

    The principal, its transitive groups, the applicable well-known
    principals, and ``owner`` when it owns the object being tested. Computed
    per object, because ``owner`` depends on which object is being evaluated —
    an ancestor's traverse check uses that ancestor's owner.
    """
    subjects = {principal_id, "everyone"}
    anonymous = principal_id == "anonymous"

    if anonymous:
        subjects.add("anonymous")
    elif principals.is_active(principal_id):
        subjects.add("authenticated")
        subjects.update(principals.groups_of(principal_id))
    # A suspended user keeps only its own id and `everyone`, so denies naming
    # it still bite while its group-derived allows vanish (§7.1).

    if owner and owner == principal_id:
        subjects.add("owner")
    return subjects


@dataclass
class ChainLink:
    """One descriptor in the chain §8.4 step 2 collects."""

    path: str
    descriptor: dict[str, Any]
    distance: int


@dataclass
class _Candidate:
    ace: dict[str, Any]
    explicit: bool
    distance: int
    order: int


@dataclass
class Evaluation:
    decisions: dict[str, dict[str, Any]]
    allowed: bool
    subjects: list[str]
    integrity: list[dict[str, str]] = field(default_factory=list)


def _ace_id(ace: dict[str, Any]) -> str:
    """The name a decision reports for an ACE.

    The corpus gives each fixture ACE an ``id`` so a case can assert *which*
    entry decided a right (§14.2): two implementations can agree on "denied"
    for different reasons and only one of them is following §8.4.
    """
    given = ace.get("id")
    if given is not None:
        return str(given)
    return f"{ace.get('type')}:{ace.get('subject')}"


def evaluate_chain(
    *,
    principals: Principals,
    principal_id: str,
    chain: list[ChainLink],
    rights: list[str],
    target_is_folder: bool,
    audience: str = "gated",
    deny_unresolved: bool = True,
) -> Evaluation:
    """Evaluate a request against a descriptor chain (§8.4).

    ``chain`` is ordered nearest-first — the object's own descriptor, then its
    parent folder's, and so on — and already truncated at the first
    ``protected`` (§8.3).
    """
    own = chain[0].descriptor if chain else {}
    subjects = subject_set(principals, principal_id, own.get("owner"))
    integrity: list[dict[str, str]] = []

    candidates: list[_Candidate] = []
    for link in chain:
        aces = link.descriptor.get("dacl") or []
        for i, ace in enumerate(aces):
            if not isinstance(ace, dict):
                continue
            explicit = link.distance == 0
            flags = set(ace.get("flags") or [])

            # §8.4 step 3: flag filtering.
            if not explicit:
                # An inherited ACE applies only if it carries the flag for
                # this kind: `oi` for non-folders, `ci` for folders.
                if target_is_folder and "ci" not in flags:
                    continue
                if not target_is_folder and "oi" not in flags:
                    continue
                # `np` stops propagation past direct children.
                if "np" in flags and link.distance > 1:
                    continue
            elif "io" in flags:
                continue  # inherit-only never applies to its carrier

            candidates.append(_Candidate(ace, explicit, link.distance, i))

    # §8.4 step 4: four bands — explicit deny, explicit allow, inherited deny,
    # inherited allow — then nearer ancestors first within a band, then the
    # authored order within one descriptor.
    def band(c: _Candidate) -> int:
        return (0 if c.explicit else 2) + (0 if c.ace.get("type") == "deny" else 1)

    candidates.sort(key=lambda c: (band(c), c.distance, c.order))

    decisions: dict[str, dict[str, Any]] = {}
    requested = list(dict.fromkeys(rights))

    # §12.2: the audience ceiling applies *before* the DACL and can only
    # narrow, never widen, what the ACL allows.
    anonymous = principal_id == "anonymous"
    if anonymous and audience != "public":
        for r in requested:
            decisions[r] = {"decision": "deny", "by": "audience_ceiling"}
        return Evaluation(decisions, False, sorted(subjects), integrity)

    # A user that exists but is suspended or expired loses its allows while
    # keeping the denies that name it (§7.1): suspension must never widen
    # access, so it cannot be implemented by simply dropping the principal.
    suspended = (
        not anonymous
        and principal_id in principals.users
        and not principals.is_active(principal_id)
    )

    ceiling_dropped: set[str] = set()
    reported: set[tuple[str, str]] = set()

    def report(code: str, subject: str) -> None:
        """Collect an integrity condition once, not once per right evaluated."""
        if (code, subject) not in reported:
            reported.add((code, subject))
            integrity.append({"severity": "error", "code": code, "subject": subject})

    for r in requested:
        decided: dict[str, Any] | None = None
        for c in candidates:
            ace = c.ace

            if not principals.exists(ace.get("subject")):
                # §8.4: an unresolvable subject denies its rights when
                # security.deny_unresolved is true (the default and the safe
                # direction — a typo in a group name must not silently grant).
                expanded = principals.expand_rights(ace.get("rights"))
                report("UNRESOLVED_SUBJECT", str(ace.get("subject")))
                if deny_unresolved and r in expanded.rights:
                    decided = {"decision": "deny", "by": _ace_id(ace)}
                    break
                continue

            if ace.get("subject") not in subjects:
                continue

            # Under `private`, grants to `everyone` are ignored (§12.2).
            if (
                audience == "private"
                and ace.get("subject") == "everyone"
                and ace.get("type") == "allow"
            ):
                if r in principals.expand_rights(ace.get("rights")).rights:
                    ceiling_dropped.add(r)
                continue

            if ace.get("type") == "allow" and suspended:
                continue

            expanded = principals.expand_rights(ace.get("rights"))
            if expanded.unresolved:
                # §7.4: an ACE naming an undefined role is an integrity error
                # and is treated per security.deny_unresolved — "the ACE is
                # treated as a deny of all its rights" (§8.4).
                for name in expanded.unresolved:
                    report("UNRESOLVED_RIGHT", name)
                if deny_unresolved and r in expanded.rights:
                    decided = {"decision": "deny", "by": _ace_id(ace)}
                    break
                if deny_unresolved:
                    continue

            if r not in expanded.rights:
                continue

            decided = {
                "decision": "deny" if ace.get("type") == "deny" else "allow",
                "by": _ace_id(ace),
            }
            break  # §8.4 step 5: the first ACE mentioning this right decides it

        if decided is None:
            # §8.4 step 5: a right no ACE mentions is denied. When the only
            # entry that would have granted it was dropped by the audience
            # ceiling, say so rather than blaming the default.
            decided = {
                "decision": "deny",
                "by": "audience_ceiling" if r in ceiling_dropped else "default",
            }
        decisions[r] = decided

    # §8.1: a node reachable by `anonymous` requires `publish` in addition to
    # `read`, so that "shared with everyone who has an account" and "on the
    # public internet" stay different decisions and no single mis-set ACE can
    # confuse them.
    if anonymous and "read" in decisions and decisions["read"]["decision"] == "allow":
        pub = evaluate_chain(
            principals=principals,
            principal_id=principal_id,
            chain=chain,
            rights=["publish"],
            target_is_folder=target_is_folder,
            audience="public",
            deny_unresolved=deny_unresolved,
        )
        if pub.decisions["publish"]["decision"] != "allow":
            decisions["read"] = {"decision": "deny", "by": "missing_publish"}

    allowed = all(decisions[r]["decision"] == "allow" for r in requested)
    return Evaluation(decisions, allowed, sorted(subjects), integrity)


__all__ = [
    "DEFAULT_ROLES",
    "RIGHTS",
    "WELL_KNOWN",
    "ChainLink",
    "Evaluation",
    "ExpandedRights",
    "Principals",
    "evaluate_chain",
    "subject_set",
]
