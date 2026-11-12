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
    """Build a transport from the flags. One store per process: ``--vault`` for
    a plain folder (the default, "."), ``--git`` for a folder in a git working
    tree, ``--bucket`` for S3, MinIO or R2, ``--gist`` for a GitHub gist."""
    given = [n for n in ("git", "bucket", "gist") if getattr(args, n, None)]
    if getattr(args, "vault", None) is not None:
        given.insert(0, "vault")
    if len(given) > 1:
        raise RuntimeError(
            "pick one store: " + " and ".join(f"--{n}" for n in given) + " were both given"
        )
    if getattr(args, "remote", None) and not getattr(args, "git", None):
        raise RuntimeError("--remote is for a git store (--git DIR)")
    if getattr(args, "git", None):
        from .keys import INDEX
        from .transport.git import GitTransport

        # Indexes are rebuilt from content (§10), so a merge that conflicts
        # only in them keeps this side's and the next reindex settles it.
        t = GitTransport(Path(args.git), remote=args.remote, derived=[INDEX])
        t.ready()
        return t
    if getattr(args, "gist", None):
        from .transport.gist import GistTransport

        t = GistTransport(args.gist, api=_gist_api(args))
        t.ready()
        return t
    if getattr(args, "bucket", None):
        from .transport.s3 import S3Transport

        return S3Transport(
            bucket=args.bucket,
            prefix=args.prefix or "",
            endpoint=args.endpoint,
            region=args.region,
            flavor=args.flavor,
        )
    return LocalTransport(Path(args.vault or ".").resolve())


def _gist_api(args: argparse.Namespace) -> Any:
    """The GitHub client. The token comes from the environment, never a flag."""
    from .transport.gist import GistApi

    return GistApi(api_url=getattr(args, "api_url", None))


def _open(args: argparse.Namespace) -> Vault:
    vault = Vault(_transport(args))
    vault.load()
    rederive = getattr(vault.t, "rederive", False)
    if rederive is None:
        # After a push that had to merge first, rebuild the indexes so what
        # goes out matches the merged content.
        def again() -> None:
            vault.reload()
            vault.reindex(write=True)

        vault.t.rederive = again  # type: ignore[attr-defined]
    return vault


def _lookup_caller(vault: Vault) -> str | None:
    """What the store says the credentials behind this process belong to
    (§12.7 ``caller``). Asked once; a store that fails to answer is reported
    and the writes go ahead without it."""
    from .store import normalize_caller

    try:
        return normalize_caller(vault.t.caller_identity())
    except Exception as err:
        print(f"basalt: could not name the caller, so writes will not record one: {err}", file=sys.stderr)
        return None


# -------------------------------------------------------------------- add


def cmd_add(args: argparse.Namespace) -> int:
    """Store files as NEW objects (§12.7)."""
    import unicodedata

    from .frontmatter import kind_for
    from .store import Provenance, StoreFault, check_provenance_label, store_object

    sources: list[str] = args.files
    if args.as_ and args.to:
        raise RuntimeError("--as names the whole path; --to names only the folder")
    if len(sources) > 1 and (args.as_ or args.title or args.alt):
        raise RuntimeError("--as, --title and --alt describe one file; add several with --to FOLDER/")
    try:
        agent = check_provenance_label("--agent", args.agent)
        account = check_provenance_label("--account", args.account)
    except StoreFault as err:
        raise RuntimeError(err.detail) from err
    # No --principal: you are the operator, who holds the credentials and could
    # write the file by hand. With one, §8 applies as for anyone.
    principal = args.principal or None
    vault = _open(args)
    # Stamp only when there is something true to say: the labels typed, or the
    # caller the store names.
    caller = _lookup_caller(vault)
    if caller:
        print(C.dim(f"storing as {caller}"))
    provenance = Provenance(agent=agent, account=account, caller=caller) if (agent or account or caller) else None

    def folder_for(name: str) -> str:
        if args.to is None:
            return "Notes/" if kind_for(name) == "note" else "Assets/"
        f = args.to.lstrip("/")
        return f if f == "" or f.endswith("/") else f + "/"

    def size(n: int) -> str:
        return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB" if n < 1048576 else f"{n / 1048576:.1f} MB"

    stored: list[str] = []
    refused = 0

    def message(_keys: list[str]) -> str:
        return f"Add {stored[0]}" if len(stored) == 1 else f"Add {len(stored)} files"

    # On a git store the whole command is one commit.
    with vault.batch(message=message, trailers={"Basalt-Principal": principal} if principal else {}):
        for src in sources:
            try:
                if src == "-":
                    if not args.as_:
                        raise RuntimeError("content from stdin needs --as PATH")
                    data = sys.stdin.buffer.read()
                    name = ""
                else:
                    p = Path(src)
                    if p.is_dir():
                        raise RuntimeError("is a directory; add the files in it")
                    data = p.read_bytes()
                    # macOS hands out decomposed (NFD) filenames, which §1.1 rejects.
                    name = unicodedata.normalize("NFC", p.name)
                dest = args.as_ or folder_for(name) + name
                r = store_object(
                    vault, path=dest, data=data, principal=principal, title=args.title,
                    alt=args.alt, provenance=provenance, reindex=False,
                )
                stored.append(r.path)
                print(f"{C.green('stored')}  {r.path}  {C.dim(f'{r.id}  {r.kind}, {size(r.size)}')}")
            except (StoreFault, RuntimeError, OSError) as err:
                refused += 1
                print(f"{C.red('refused')} {'stdin' if src == '-' else src}: {err}", file=sys.stderr)
        if stored:
            idx = vault.reindex(write=True)
            issues = idx["integrity"]["entries"]
            errs = sum(1 for i in issues if i.get("severity") == "error")
            print(C.dim(f"indexes refreshed · integrity {errs} errors, {len(issues) - errs} warnings"))
    return 1 if refused else 0


# ------------------------------------------------------------------- gist


def _size(n: int) -> str:
    return f"{n} B" if n < 1024 else f"{n / 1024:.1f} KB" if n < 1048576 else f"{n / 1048576:.1f} MB"


_SKIPPED_WHY = {
    "empty": "empty",
    "not_text": "not text a gist can hold",
    "name_too_long": "name too long",
    "invalid_key": "not a valid vault path",
}


def cmd_gist_export(args: argparse.Namespace) -> int:
    """Send a vault folder to a GitHub gist."""
    from .gist import export_to_gist, folder_path
    from .transport.gist import parse_gist_id

    whole = bool(args.whole)
    if (args.folder is not None) if whole else (args.folder is None):
        raise RuntimeError("gist export needs one folder (e.g. Projects/), or --whole")
    update = None
    if args.update is not None:
        update = parse_gist_id(args.update)
        if not update:
            raise RuntimeError("--update needs a gist id or URL")
    principal = args.principal or None
    vault = _open(args)
    # A principal's view needs inline ACLs, which come from a reindex.
    if principal:
        vault.reindex()
    r = export_to_gist(
        vault,
        api=_gist_api(args),
        folder="" if whole else folder_path(args.folder),
        whole=whole,
        update=update,
        prune=args.prune,
        public=args.public,
        description=args.description,
        principal=principal,
        dry_run=args.dry_run,
    )
    where = C.red("PUBLIC") if r.public else "secret"
    if r.dry_run:
        print(
            f"would send {r.count} file(s), {_size(r.bytes)}, as a new {where} gist"
            + C.dim(" (nothing sent: --dry-run)")
        )
        for n in r.names:
            print(f"  {n}")
    if r.skipped:
        print(C.yellow(f"left out {len(r.skipped)} file(s) a gist cannot hold:"))
        for s in r.skipped[:20]:
            print(C.yellow(f"  {s['path']}  ({_SKIPPED_WHY.get(s['reason'], s['reason'])})"))
        if len(r.skipped) > 20:
            print(C.dim(f"  …{len(r.skipped) - 20} more"))
    if r.withheld:
        print(C.dim(f"{r.withheld} file(s) withheld: {principal} may not read them"))
    if not r.dry_run:
        if r.created:
            print(f"{C.green('created')} {where} gist {r.url}")
            print(
                C.dim(
                    f"  {r.count} file(s), {_size(r.bytes)}"
                    + (
                        ". It is public: anyone can find and read it."
                        if r.public
                        else ". Secret means unlisted, not private: anyone with the URL can read it."
                    )
                )
            )
        elif not r.updated:
            print(f"{C.green('up to date')}  {r.url}  {C.dim(f'{r.unchanged} file(s) unchanged')}")
        else:
            print(f"{C.green('updated')} {where} gist {r.url}")
            print(
                C.dim(
                    f"  {r.written} written, {r.unchanged} unchanged"
                    + (f", {r.removed} removed" if r.removed else "")
                )
            )
        if r.left:
            more = ", …" if len(r.left) > 5 else ""
            print(
                C.yellow(
                    f"{len(r.left)} file(s) in the gist are not in the folder "
                    f"(--prune removes them): {', '.join(r.left[:5])}{more}"
                )
            )
    return 0


def cmd_gist_import(args: argparse.Namespace) -> int:
    """Store every file of a gist as a NEW object under a folder."""
    from .gist import folder_path, import_from_gist
    from .store import Provenance, StoreFault, check_provenance_label
    from .transport.gist import parse_gist_id

    gist_id = parse_gist_id(args.id)
    if not gist_id:
        raise RuntimeError(f"not a gist id or URL: {args.id}")
    try:
        agent = check_provenance_label("--agent", args.agent)
        account = check_provenance_label("--account", args.account)
    except StoreFault as err:
        raise RuntimeError(err.detail) from err
    principal = args.principal or None
    vault = _open(args)
    caller = _lookup_caller(vault)
    provenance = Provenance(agent=agent, account=account, caller=caller) if (agent or account or caller) else None
    to = f"Gists/{gist_id}/" if args.to is None else folder_path(args.to)
    r = import_from_gist(
        vault,
        api=_gist_api(args),
        id=gist_id,
        to=to,
        principal=principal,
        provenance=provenance,
        log=lambda o, _name: print(f"{C.green('stored')}  {o.path}  {C.dim(f'{o.id}  {o.kind}, {_size(o.size)}')}"),
    )
    for x in r.refused:
        print(f"{C.red('refused')} {x['name']}: {x['error']}", file=sys.stderr)
    kind = "public" if r.gist["public"] else "secret"
    print(
        C.dim(
            f"{len(r.stored)} stored, {len(r.refused)} refused, from {kind} gist "
            f"{r.gist['url'] or r.gist['id']}" + (" · indexes refreshed" if r.stored else "")
        )
    )
    return 1 if r.refused else 0


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


def cmd_find(args: argparse.Namespace) -> int:
    """Find notes by topic. Not part of the protocol: see :mod:`basalt.topics`."""
    if bool(args.query) == bool(args.like):
        raise ValueError("give a query, or --like PATH, but not both")
    # Imported here so that no other command pays for gensim's start-up.
    from .topics import TopicSearch

    vault = _open(args)
    vault.reindex()
    topics = TopicSearch(vault, num_topics=args.topics)
    if args.like:
        hits = topics.related(args.principal, args.like, limit=args.limit)
    else:
        hits = topics.find(args.principal, args.query, limit=args.limit)

    if not hits:
        print(C.dim("no readable notes on that topic"))
    for hit in hits:
        print(f"{hit['score']:.2f}  {hit['title'] or hit['path']}  {C.dim(hit['path'])}")
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
    parser.add_argument("--vault", help="local vault directory (the default: .)")
    parser.add_argument(
        "--git",
        help="a folder in a git working tree: each write is one commit of only the "
        "files basalt wrote, with your git identity",
    )
    parser.add_argument(
        "--remote",
        help="with --git: pull before each write and push after it (never forced). "
        "Pushing copies the vault to that remote",
    )
    parser.add_argument(
        "--gist",
        metavar="ID|URL",
        help="a whole vault inside one gist (made with `gist export --whole`). Text only, "
        "at most 300 files; a batch of writes is one gist revision. Writes need GITHUB_TOKEN",
    )
    parser.add_argument("--api-url", help="GitHub API URL, for GitHub Enterprise")
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

    add = sub.add_parser(
        "add",
        help="store a note, image or any other file as a NEW object (§12.7); never overwrites",
    )
    _add_transport_flags(add)
    add.add_argument("files", nargs="+", metavar="FILE", help="files to store, or - for stdin with --as")
    add.add_argument("--to", help="folder to store in (default: Notes/ for notes, Assets/ otherwise)")
    add.add_argument("--as", dest="as_", metavar="PATH", help="the exact vault path of a single file")
    add.add_argument("--title", help="a note's frontmatter title, or an asset's sidecar title")
    add.add_argument("--alt", help="an asset's alt text")
    add.add_argument("--principal", help="enforce this principal's create_child (default: the operator)")
    add.add_argument("--agent", help='stamp created_by with this agent label, e.g. "claude-code"')
    add.add_argument("--account", help='stamp created_by with this account label, e.g. "work"')
    add.set_defaults(func=cmd_add)

    gist = sub.add_parser(
        "gist",
        help="move folders to and from GitHub gists (the token is read from GITHUB_TOKEN or GH_TOKEN)",
    )
    gsub = gist.add_subparsers(dest="gist_command", required=True)

    gexport = gsub.add_parser(
        "export",
        help="send a vault folder to a gist: a NEW secret gist, or --update one you have",
        description="A gist is flat and holds non-empty text, so a file's path inside FOLDER/ "
        'becomes one file name ("Notes/A.md" is "Notes%2FA.md"), and a binary or empty file '
        "is left out and listed, never dropped silently. A secret gist is unlisted, not private: "
        "anyone with its URL can read it, whatever basalt.yaml says.",
    )
    _add_transport_flags(gexport)
    gexport.add_argument("folder", nargs="?", metavar="FOLDER/", help="the vault folder to send")
    gexport.add_argument(
        "--whole", action="store_true",
        help="send every key of the vault, so the gist opens as a vault with --gist",
    )
    gexport.add_argument("--update", metavar="ID|URL", help="write into this gist instead of making one")
    gexport.add_argument(
        "--prune", action="store_true",
        help="with --update, also remove the gist's files the folder no longer has",
    )
    gexport.add_argument("--public", action="store_true", help="a PUBLIC gist (listed); new gists only")
    gexport.add_argument("--description", help="the gist's description")
    gexport.add_argument(
        "--dry-run", action="store_true", help="print what would be sent and send nothing"
    )
    gexport.add_argument("--principal", help="send only what this principal may read")
    gexport.set_defaults(func=cmd_gist_export)

    gimport = gsub.add_parser(
        "import",
        help="store every file of a gist as a NEW object under a folder",
        description="Each file gets an id, as `basalt add` does; one whose path is taken is "
        "refused, never replaced. A public or secret gist needs no token to read.",
    )
    _add_transport_flags(gimport)
    gimport.add_argument("id", metavar="ID|URL", help="the gist")
    gimport.add_argument("--to", metavar="FOLDER/", help="folder to store in (default: Gists/<id>/)")
    gimport.add_argument("--principal", help="enforce this principal's create_child (default: the operator)")
    gimport.add_argument("--agent", help='stamp created_by with this agent label, e.g. "claude-code"')
    gimport.add_argument("--account", help='stamp created_by with this account label, e.g. "work"')
    gimport.set_defaults(func=cmd_gist_import)

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

    find = sub.add_parser(
        "find",
        help="find notes by topic rather than by keyword (optional: needs the 'topics' extra)",
    )
    _add_transport_flags(find)
    find.add_argument("query", nargs="?", help="what the notes are about, in your own words")
    find.add_argument("--like", metavar="PATH", help="notes on the same topics as this one")
    find.add_argument("--principal", default="anonymous")
    find.add_argument("--limit", type=int, default=10)
    find.add_argument(
        "--topics",
        type=int,
        help="latent dimensions to fit (default: about the square root of the note count)",
    )
    find.set_defaults(func=cmd_find)

    regen = sub.add_parser(
        "conformance-regen", help="regenerate a conformance vault's expected/ output"
    )
    regen.add_argument("--vault", default="../conformance/vaults/minimal/vault")
    regen.add_argument("--out")
    regen.set_defaults(func=cmd_conformance_regen)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw[:1] == ["gist"] and any(a == "--token" or a.startswith("--token=") for a in raw):
        # A token on the command line lands in shell history and `ps`.
        print(
            C.red(
                "error: there is no --token flag: set GITHUB_TOKEN (or GH_TOKEN), "
                "or sign in with `gh auth login`"
            ),
            file=sys.stderr,
        )
        return 1
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
