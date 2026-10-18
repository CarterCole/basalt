"""Descriptor lookup and the full access check, PROTOCOL §8.5 and §8.6.

:func:`basalt.acl.evaluate_chain` decides one object against one chain. This
module builds those chains from the vault's ACL files and composes the
traverse checks, which §8.5 is explicit about: ``traverse`` on an ancestor is
decided by that ancestor's *own* evaluation, including its own inheritance
chain. The checks compose; they are not one flattened pass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .acl import RIGHTS, ChainLink, Evaluation, Principals, evaluate_chain
from .keys import ancestor_folders, basename, is_folder, parent_folder


class DescriptorStore:
    """A descriptor store backed by per-folder ACL files (§8.6).

    ``folder_acls`` maps a folder path (``""``, ``"Notes/"``) to the parsed
    ``acl.yaml``: ``{folder: {owner, protected, dacl}, entries: {...}}``.
    ``inline_acls`` maps a node path to a descriptor from its frontmatter,
    which **replaces** rather than merges with the folder file's entry —
    merging two hand-edited sources would make the effective ACL depend on
    load order, so §8.6 picks one winner.
    """

    def __init__(
        self,
        folder_acls: dict[str, dict[str, Any]] | None = None,
        inline_acls: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.folder_acls: dict[str, dict[str, Any]] = folder_acls or {}
        self.inline_acls: dict[str, dict[str, Any]] = inline_acls or {}

    def for_folder(self, folder_path: str) -> dict[str, Any] | None:
        """The descriptor for a folder path, or ``None``."""
        acl = self.folder_acls.get(folder_path)
        if not isinstance(acl, dict):
            return None
        folder = acl.get("folder")
        return folder if isinstance(folder, dict) else None

    def for_node(self, node_path: str) -> dict[str, Any] | None:
        """The descriptor for a node path, inline winning over the folder file."""
        inline = self.inline_acls.get(node_path)
        if inline is not None:
            return inline if isinstance(inline, dict) else None
        acl = self.folder_acls.get(parent_folder(node_path))
        if not isinstance(acl, dict):
            return None
        entries = acl.get("entries")
        if not isinstance(entries, dict):
            return None
        found = entries.get(basename(node_path))
        return found if isinstance(found, dict) else None

    def for_path(self, path: str) -> dict[str, Any] | None:
        """The descriptor for any path, folder or node."""
        return self.for_folder(path) if is_folder(path) else self.for_node(path)

    def chain_for(self, path: str) -> list[ChainLink]:
        """The chain for a path (§8.4 step 2).

        The object's own descriptor, then each ancestor folder's, nearest
        first, truncated at the first ``protected: true`` — §8.3's NTFS
        "disable inheritance" case, where evaluation at and below that folder
        considers no ancestor above it.
        """
        own = self.for_path(path)
        chain = [ChainLink(path=path, descriptor=own or {}, distance=0)]
        if own and own.get("protected"):
            return chain

        # ancestor_folders returns root-first; walk it backwards for
        # nearest-first ordering, which is what the band sort in §8.4 step 4
        # relies on to make the closest folder's intent govern.
        ancestors = _ancestors_of(path)

        distance = 1
        for folder in reversed(ancestors):
            if folder == path:
                continue
            descriptor = self.for_folder(folder)
            chain.append(
                ChainLink(path=folder, descriptor=descriptor or {}, distance=distance)
            )
            distance += 1
            if descriptor and descriptor.get("protected"):
                break  # §8.3: inheritance stops here
        return chain


def _ancestors_of(path: str) -> list[str]:
    """Ancestor folders of a path, root-first, excluding the path itself.

    A folder path needs a synthetic trailing entry so ``ancestor_folders``
    treats the folder itself as a container rather than as the entry name.
    """
    if is_folder(path):
        return ancestor_folders(path.rstrip("/") + "/x")[:-1]
    return ancestor_folders(path)


@dataclass
class AccessResult:
    allowed: bool
    decisions: dict[str, dict[str, Any]]
    subjects: list[str] = field(default_factory=list)
    failed_at: str | None = None
    integrity: list[dict[str, str]] = field(default_factory=list)

    @property
    def granted(self) -> list[str]:
        return [r for r, d in self.decisions.items() if d["decision"] == "allow"]


def check_access(
    *,
    store: DescriptorStore,
    principals: Principals,
    principal_id: str,
    path: str,
    rights: list[str],
    audience: str = "gated",
    bypass_traverse: bool = False,
    deny_unresolved: bool = True,
) -> AccessResult:
    """The complete access check: the leaf decision plus the traverse chain (§8.5).

    ``failed_at`` names the ancestor whose ``traverse`` check failed, which is
    the single most useful thing to report when a deep vault denies something
    unexpectedly.
    """
    target_is_folder = is_folder(path)

    leaf: Evaluation = evaluate_chain(
        principals=principals,
        principal_id=principal_id,
        chain=store.chain_for(path),
        rights=rights,
        target_is_folder=target_is_folder,
        audience=audience,
        deny_unresolved=deny_unresolved,
    )

    if not bypass_traverse:
        # §8.5: reading Notes/Private/Secrets.md requires `read` on that node
        # *and* `traverse` on Notes/ and Notes/Private/. Each ancestor's
        # traverse is decided by its own chain.
        for folder in _ancestors_of(path):
            if folder == path:
                continue
            t = evaluate_chain(
                principals=principals,
                principal_id=principal_id,
                chain=store.chain_for(folder),
                rights=["traverse"],
                target_is_folder=True,
                audience=audience,
                deny_unresolved=deny_unresolved,
            )
            if not t.allowed:
                reason = t.decisions["traverse"]["by"]
                decisions = {
                    r: {"decision": "deny", "by": reason, "failed_at": folder}
                    for r in dict.fromkeys(rights)
                }
                return AccessResult(
                    allowed=False,
                    decisions=decisions,
                    subjects=leaf.subjects,
                    failed_at=folder,
                    integrity=[*leaf.integrity, *t.integrity],
                )

    return AccessResult(
        allowed=leaf.allowed,
        decisions=leaf.decisions,
        subjects=leaf.subjects,
        failed_at=None,
        integrity=leaf.integrity,
    )


def effective_rights(
    *,
    store: DescriptorStore,
    principals: Principals,
    principal_id: str,
    path: str,
    rights: list[str] | None = None,
    **opts: Any,
) -> AccessResult:
    """Effective rights for a principal on a path (§8.7).

    The Windows "Effective Access" equivalent, with the deciding ACE for each
    right. §8.7 makes this a SHOULD and §14.3 makes the CLI that surfaces it a
    MUST, because without it an inherited-deny misconfiguration deep in a tree
    is close to undiagnosable.
    """
    return check_access(
        store=store,
        principals=principals,
        principal_id=principal_id,
        path=path,
        rights=list(rights) if rights is not None else list(RIGHTS),
        **opts,
    )


__all__ = [
    "AccessResult",
    "DescriptorStore",
    "check_access",
    "effective_rights",
]
