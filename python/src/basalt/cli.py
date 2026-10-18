"""The Basalt CLI.

``basalt check`` is the self-check PROTOCOL §14.3 *requires* of a conforming
implementation: given a vault it reports integrity (§10.7), index freshness
(§10.6), whether a rebuild reproduces the stored indexes byte for byte (§13),
and the ACL evaluation of a named principal against a named path (§8.7).
Without it, "is my private note actually private" is unanswerable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .acl import RIGHTS
from .canonical import canonical_json, comparable
from .gatekeeper import Gatekeeper
from .indexer import EPOCH
from .transport import Transport
from .transport.local import LocalTransport
from .vault import INDEX_KEYS, INDEX_KINDS, Vault


class _Color:
    """ANSI colors, suppressed when stdout is not a terminal."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def green(self, text: str) -> str:
        return self._wrap("32", text)


C = _Color(sys.stdout.isatty())


def _transport(args: argparse.Namespace) -> Transport:
    """Build a transport from the flags: ``--vault`` for a path, ``--bucket`` for S3."""
    if getattr(args, "bucket", None):
        from .transport.s3 import S3Transport

        return S3Transport(
            bucket=args.bucket,
            prefix=args.prefix or "",
            endpoint=args.endpoint,
            region=args.region,
            flavor=args.flavor,
        )
    return LocalTransport(Path(args.vault).resolve())


def _open(args: argparse.Namespace) -> Vault:
    vault = Vault(_transport(args))
    vault.load()
    return vault


# ------------------------------------------------------------------ check


def cmd_check(args: argparse.Namespace) -> int:
    """§14.3's required self-check."""
    vault = _open(args)
    manifest = vault.manifest or {}
    vault_meta = manifest.get("vault") or {}

    # The stored indexes first, then a fresh rebuild to compare against.
    vault.load_indexes()
    stored = dict(vault.indexes or {})
    fresh = vault.reindex(generated=EPOCH)

    print(C.bold(f"vault {vault_meta.get('id')}"), C.dim(str(vault_meta.get("title") or "")))
    security = manifest.get("security") or {}
    publish = manifest.get("publish") or {}
    print(
        C.dim(
            f"audience={publish.get('audience')} "
            f"bypass_traverse={str(bool(security.get('bypass_traverse', False))).lower()}"
        )
    )

    # 1. Integrity (§10.7). A vault with errors is still servable: refusing to
    #    serve because one file has bad frontmatter would be the wrong trade
    #    for a publishing system.
    issues = fresh["integrity"]["entries"]
    errors = [i for i in issues if i.get("severity") == "error"]
    warnings = [i for i in issues if i.get("severity") == "warning"]
    print(
        f"\n{C.bold('integrity')}  "
        + (C.red(f"{len(errors)} error(s)") if errors else C.green("0 errors"))
        + ", "
        + (C.yellow(f"{len(warnings)} warning(s)") if warnings else "0 warnings")
    )
    for issue in issues[:20]:
        tag = C.red("error") if issue.get("severity") == "error" else C.yellow("warn ")
        path = issue.get("path")
        detail = issue.get("detail")
        print(
            f"  {tag} {issue['code']} "
            f"{C.dim(str(path) if isinstance(path, str) else '')} "
            f"{detail if isinstance(detail, str) else ''}".rstrip()
        )
    if len(issues) > 20:
        print(C.dim(f"  …{len(issues) - 20} more"))

    # 2. Freshness (§10.6) — one digest comparison, never timestamps.
    stored_digest = (stored.get("nodes") or {}).get("source_digest")
    current = fresh["digest"]["root"]
    state = (
        C.yellow("no stored index")
        if stored_digest is None
        else C.green("fresh")
        if stored_digest == current
        else C.yellow("stale")
    )
    print(f"\n{C.bold('index')}      {state}")
    print(C.dim(f"  current {current}"))
    if stored_digest:
        print(C.dim(f"  stored  {stored_digest}"))
    if stored_digest is not None and stored_digest != current:
        print(C.dim(f"  stale_policy={(manifest.get('index') or {}).get('stale_policy')}"))

    # 3. Byte-for-byte reproduction (§13).
    reproduced = True
    compared = 0
    for kind in INDEX_KINDS:
        if kind not in stored:
            continue
        compared += 1
        if canonical_json(comparable(stored[kind])) != canonical_json(
            comparable(fresh[kind])
        ):
            reproduced = False
            print(f"  {C.red('differs')} {INDEX_KEYS[kind]}")
    print(
        f"\n{C.bold('rebuild')}    "
        + (
            C.dim("nothing stored to compare")
            if not compared
            else C.green("reproduces stored indexes byte for byte")
            if reproduced
            else C.red("does NOT reproduce stored indexes")
        )
    )

    # 4. ACL evaluation (§8.7) — the question the tool exists to answer.
    if args.principal and args.path is not None:
        result = vault.effective(args.principal, args.path)
        print(f"\n{C.bold('access')}     {args.principal} on {args.path or '/'}")
        for right in RIGHTS:
            decision = result.decisions.get(right)
            if decision is None:
                continue
            mark = (
                C.green("allow") if decision["decision"] == "allow" else C.red("deny ")
            )
            at = (
                C.dim(f" at {decision['failed_at']}")
                if decision.get("failed_at") is not None
                else ""
            )
            print(f"  {mark} {right:<15} {C.dim('by ' + str(decision['by']))}{at}")
    else:
        print(C.dim("\n  (pass --principal and --path for an ACL evaluation)"))

    return 1 if errors or not reproduced else 0


# ------------------------------------------------------------------ index


def cmd_index(args: argparse.Namespace) -> int:
    vault = _open(args)
    indexes = vault.reindex(write=args.write, force=args.force)
    print(
        f"{len(indexes['nodes']['entries'])} nodes, "
        f"{len(indexes['links']['entries'])} edges, "
        f"{len(indexes['tags']['entries'])} tags"
    )
    print(f"digest {indexes['digest']['root']}")
    if args.write:
        print(f"wrote {len(INDEX_KEYS)} index objects")
    else:
        print(C.dim("(dry run; pass --write to persist)"))
    return 0


def cmd_mint(args: argparse.Namespace) -> int:
    vault = _open(args)
    minted = vault.mint_ids()
    if not minted:
        print("every object already carries an id")
    for m in minted:
        print(f"  {m['id']}  {m['path']} {C.dim('(' + m['where'] + ')')}")
    return 0


# ------------------------------------------------------------------ serve


def cmd_serve(args: argparse.Namespace) -> int:
    vault = _open(args)
    vault.reindex()
    forced = args.principal
    gatekeeper = Gatekeeper(
        vault,
        # §12.1: a client must never be able to assert its own principal id,
        # so --principal is a server-side override for local testing and the
        # request itself has no say.
        identify=lambda headers, query: forced or "anonymous",
        delivery=args.delivery,
    )
    host, port = gatekeeper.start(port=args.port)
    print(f"gatekeeper on http://{host}:{port}")
    publish = (vault.manifest or {}).get("publish") or {}
    print(
        C.dim(
            f"  audience={publish.get('audience')} principal={forced or 'anonymous'}"
        )
    )
    print(
        C.dim(
            "  GET /api/v1/{manifest,tree,node/<path>,raw/<path>,"
            "list/<folder>,links/<path>,search?q=,effective?path=}"
        )
    )
    try:
        import threading

        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        gatekeeper.close()
    return 0


def cmd_effective(args: argparse.Namespace) -> int:
    vault = _open(args)
    vault.reindex()
    result = vault.effective(args.principal or "anonymous", args.path or "")
    for right in RIGHTS:
        decision = result.decisions.get(right)
        if decision is None:
            continue
        mark = C.green("allow") if decision["decision"] == "allow" else C.red("deny ")
        print(f"{mark} {right:<15} {C.dim('by ' + str(decision['by']))}")
    return 0


def cmd_tree(args: argparse.Namespace) -> int:
    vault = _open(args)
    vault.reindex()
    tree = vault.tree(args.principal or "anonymous")["tree"]

    def show(node: dict[str, Any] | None, depth: int = 0) -> None:
        if not node:
            return
        pad = "  " * depth
        print(f"{pad}{C.bold(str(node.get('title') or node['folder']))} {C.dim(node['folder'])}")
        for entry in node["entries"]:
            print(f"{pad}  {entry.get('title')} {C.dim(entry['path'])}")
        for child in node["folders"]:
            show(child, depth + 1)

    show(tree)
    return 0


def cmd_conformance_regen(args: argparse.Namespace) -> int:
    """Regenerate a conformance vault's ``expected/`` output.

    A change in this diff is a change to the protocol's observable output, so
    it is reviewed by hand, never rubber-stamped. This implementation is held
    to fixtures generated by the reference implementation, so running this is
    normally a way of *inspecting* a disagreement, not of resolving one.
    """
    directory = Path(args.vault).resolve()
    out = Path(args.out).resolve() if args.out else directory.parent / "expected"
    vault = Vault(LocalTransport(directory))
    vault.load()
    indexes = vault.reindex(generated=EPOCH)
    out.mkdir(parents=True, exist_ok=True)
    for kind in INDEX_KINDS:
        obj = indexes.get(kind)
        if obj is None:
            continue
        target = out / f"{kind}.json"
        target.write_text(canonical_json(obj), encoding="utf-8")
        print(f"  wrote {target}")
    return 0


def cmd_digest(args: argparse.Namespace) -> int:
    """Print the content digest (§10.6) — the one `get` that decides freshness."""
    vault = _open(args)
    vault.load_indexes()
    state = vault.index_state()
    print(json.dumps({"current": state.current, "stored": state.stored, "fresh": state.fresh}))
    return 0


# ------------------------------------------------------------------- main


def _add_transport_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--vault", default=".", help="local vault directory")
    parser.add_argument("--bucket", help="S3-compatible bucket name")
    parser.add_argument("--prefix", help="key prefix within the bucket (must end in /)")
    parser.add_argument("--endpoint", help="endpoint URL (required for MinIO and R2)")
    parser.add_argument("--region", help="region (R2 requires 'auto')")
    parser.add_argument(
        "--flavor", default="s3", choices=("s3", "minio", "r2"), help="store flavor"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="basalt",
        description="The Basalt Protocol v1 — a portable knowledge vault in any "
        "object store. Conformance levels L0-L4 (§14.1).",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser(
        "check",
        help="self-check (§14.3): integrity, freshness, byte-exact rebuild, ACL",
    )
    _add_transport_flags(check)
    check.add_argument("--principal", help="principal id for the ACL evaluation")
    check.add_argument("--path", help="path for the ACL evaluation")
    check.set_defaults(func=cmd_check)

    index = sub.add_parser("index", help="rebuild every index from content alone")
    _add_transport_flags(index)
    index.add_argument("--write", action="store_true", help="persist the indexes")
    index.add_argument(
        "--force", action="store_true", help="allow writing an empty index"
    )
    index.set_defaults(func=cmd_index)

    mint = sub.add_parser("mint", help="mint node ids for unbound objects (§4.3)")
    _add_transport_flags(mint)
    mint.set_defaults(func=cmd_mint)

    serve = sub.add_parser("serve", help="run the gatekeeper (§12)")
    _add_transport_flags(serve)
    serve.add_argument("--port", type=int, default=4380)
    serve.add_argument(
        "--principal", help="force an identity for local testing (server-side only)"
    )
    serve.add_argument("--delivery", default="proxy", choices=("proxy", "redirect"))
    serve.set_defaults(func=cmd_serve)

    effective = sub.add_parser(
        "effective", help="effective rights with the deciding ACE per right (§8.7)"
    )
    _add_transport_flags(effective)
    effective.add_argument("--principal", default="anonymous")
    effective.add_argument("--path", default="")
    effective.set_defaults(func=cmd_effective)

    tree = sub.add_parser("tree", help="the visible tree for a principal")
    _add_transport_flags(tree)
    tree.add_argument("--principal", default="anonymous")
    tree.set_defaults(func=cmd_tree)

    digest = sub.add_parser("digest", help="print the content digest and freshness")
    _add_transport_flags(digest)
    digest.set_defaults(func=cmd_digest)

    regen = sub.add_parser(
        "conformance-regen", help="regenerate a conformance vault's expected/ output"
    )
    regen.add_argument("--vault", default="../conformance/vaults/minimal/vault")
    regen.add_argument("--out")
    regen.set_defaults(func=cmd_conformance_regen)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except Exception as err:  # the CLI reports, never traces
        print(C.red(f"error: {err}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
