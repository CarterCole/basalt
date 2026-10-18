"""The Basalt Protocol v1, in Python.

A portable, self-describing knowledge vault that lives in any key-value object
store, with real per-object access control and fully derived indexes. See
``protocol/PROTOCOL.md`` for the normative spec; every section reference in
this package points into it.

Conformance (§14.1): this implementation targets **L0-L4** — transport,
content, index, security, gatekeeper. L5 (history) is not implemented.
"""

from __future__ import annotations

from .acl import DEFAULT_ROLES, RIGHTS, WELL_KNOWN, Principals, evaluate_chain
from .canonical import canonical_bytes, canonical_json, comparable
from .frontmatter import kind_for, parse_note
from .indexer import build_indexes, build_search_index, compute_digest
from .keys import BasaltKeyError, is_valid_key, validate_key
from .links import build_resolver, extract_links, resolve_target
from .security import DescriptorStore, check_access, effective_rights
from .transport import Transport
from .transport.local import LocalTransport
from .transport.memory import MemoryTransport
from .vault import Vault, ulid

__version__ = "0.1.0"

#: The spec major version this package implements (§3.1, §16).
BASALT_SPEC = 1

#: The conformance levels claimed (§14.1).
CONFORMANCE_LEVELS = ("L0", "L1", "L2", "L3", "L4")

__all__ = [
    "BASALT_SPEC",
    "CONFORMANCE_LEVELS",
    "DEFAULT_ROLES",
    "RIGHTS",
    "WELL_KNOWN",
    "BasaltKeyError",
    "DescriptorStore",
    "LocalTransport",
    "MemoryTransport",
    "Principals",
    "Transport",
    "Vault",
    "__version__",
    "build_indexes",
    "build_resolver",
    "build_search_index",
    "canonical_bytes",
    "canonical_json",
    "check_access",
    "comparable",
    "compute_digest",
    "effective_rights",
    "evaluate_chain",
    "extract_links",
    "is_valid_key",
    "kind_for",
    "parse_note",
    "resolve_target",
    "ulid",
    "validate_key",
]
