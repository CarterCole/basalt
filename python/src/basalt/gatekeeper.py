"""The gatekeeper HTTP service, PROTOCOL §12.

This process holds the only credentials to the store. The bucket stays
private and never faces the reader, which is what makes §8's inherited
permissions real rather than advisory: no S3-like store can express an
inherited deny, so something has to enforce it.

Built on :mod:`http.server` rather than a framework, because §12's surface is
eight read-only routes and a dependency that large would be the heaviest
thing in the package.
"""

from __future__ import annotations

import hashlib
import http.server
import socketserver
import urllib.parse
from typing import Any

from .canonical import canonical_json
from .keys import is_folder, path_to_key
from .vault import Vault

_MEDIA = {
    ".md": "text/markdown; charset=utf-8",
    ".markdown": "text/markdown; charset=utf-8",
    ".json": "application/json",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".pdf": "application/pdf",
    ".txt": "text/plain; charset=utf-8",
}

#: §12.4 forbids ever serving these trees to a non-``system`` principal: they
#: are the index, the ACLs and the principal list, and §8.8 explains why
#: handing them out leaks the private half of the vault.
NEVER_SERVE = ("meta/", "index/", "principals/", "history/", "basalt.yaml")

_ROUTES = frozenset(
    {"manifest", "node", "raw", "list", "links", "search", "tree", "effective"}
)


def _media_for(path: str) -> str:
    i = path.rfind(".")
    return _MEDIA.get(path[i:].lower(), "application/octet-stream") if i > 0 else (
        "application/octet-stream"
    )


def _error_for(status: int) -> str:
    if status == 404:
        return "not_found"
    if status == 403:
        return "forbidden"
    return "error"


class Response:
    """One HTTP response, built before anything is written to the socket."""

    def __init__(
        self,
        status: int,
        body: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.headers = headers or {}

    def payload(self) -> bytes:
        if self.body is None:
            return b""
        if isinstance(self.body, bytes):
            return self.body
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return canonical_json(self.body).encode("utf-8")


class Gatekeeper:
    """§12's read surface over a loaded and indexed :class:`~basalt.vault.Vault`."""

    def __init__(
        self,
        vault: Vault,
        *,
        identify: Any = None,
        delivery: str = "proxy",
    ) -> None:
        self.vault = vault
        # §12.1: how a request acquires a principal id is out of scope —
        # session cookie, OIDC, signed token, mTLS, a reverse proxy header.
        # The gatekeeper MUST reduce every request to exactly one principal id
        # or to `anonymous`, and MUST NOT let a client assert its own.
        self.identify = identify or (lambda headers, query: "anonymous")
        self.delivery = delivery
        self.cache: dict[str, Any] = {}
        self.index_state = "fresh"
        self._httpd: socketserver.BaseServer | None = None

    # ------------------------------------------------------------ caching

    def _cache_key(self, route: str, principal_id: str, arg: str = "") -> str:
        """A cache key for index-derived responses (§12.5).

        It MUST include the principal's effective subject set, or the cache
        serves one user's visibility to another. §12.5 names this as the
        single most likely place for a conforming-looking implementation to
        leak, so the subject set is hashed into the key rather than the
        principal id alone — two principals with identical visibility may
        share an entry, but no principal can ever read another's.
        """
        principals = self.vault.principals
        groups = sorted(principals.groups_of(principal_id)) if principals else []
        subjects = ",".join([principal_id, *groups])
        digest = hashlib.sha256(subjects.encode("utf-8")).hexdigest()[:16]
        return f"{route}\x00{digest}\x00{arg}"

    def invalidate(self) -> None:
        """Drop cached index-derived responses; call after a reindex."""
        self.cache.clear()

    # ------------------------------------------------------------ routing

    def dispatch(
        self, method: str, raw_path: str, headers: Any = None
    ) -> Response:
        """Route one request. Separated from the socket so it is directly testable."""
        parsed = urllib.parse.urlsplit(raw_path)
        query = urllib.parse.parse_qs(parsed.query)
        principal = self.identify(headers or {}, query)

        if method not in ("GET", "HEAD"):
            return self._send(405, {"error": "method_not_allowed"})

        prefix = "/api/v1/"
        if not parsed.path.startswith(prefix):
            return self._send(404, {"error": "not_found"})
        rest = parsed.path[len(prefix) :]
        route, _, tail = rest.partition("/")
        if route not in _ROUTES:
            return self._send(404, {"error": "not_found"})
        target = urllib.parse.unquote(tail)

        # §12.4: refuse the protocol's own trees outright, before any ACL work.
        if any(target == p or target.startswith(p) for p in NEVER_SERVE):
            return self._send(404, {"error": "not_found"})

        try:
            return getattr(self, f"_route_{route}")(principal, target, query)
        except Exception as err:  # a 500 is the right answer
            return self._send(500, {"error": "internal", "detail": str(err)})

    def _send(
        self, status: int, body: Any, headers: dict[str, str] | None = None
    ) -> Response:
        manifest = self.vault.manifest or {}
        base = {
            "content-type": "application/json",
            "x-basalt-vault": (manifest.get("vault") or {}).get("id") or "",
            # §12.3: every response carries the index state, so a client is
            # never silently served old data under any stale policy (§10.6).
            "x-basalt-index-state": self.index_state,
            "cache-control": "private, no-store",
        }
        base.update(headers or {})
        return Response(status, body, base)

    # ------------------------------------------------------------- routes

    def _route_manifest(self, principal: str, target: str, query: Any) -> Response:
        """The public subset of the manifest (§12.3).

        Deliberately not the whole file: ``security.bypass_traverse`` and
        ``publish.audience`` describe the enforcement posture, and §15 notes
        that whoever can write ``basalt.yaml`` controls it.
        """
        manifest = self.vault.manifest or {}
        vault = manifest.get("vault") or {}
        publish = manifest.get("publish") or {}
        return self._send(
            200,
            {
                "basalt": manifest.get("basalt"),
                "vault": {"id": vault.get("id"), "title": vault.get("title")},
                "publish": {
                    "audience": publish.get("audience"),
                    "home": publish.get("home"),
                },
            },
        )

    def _route_node(self, principal: str, target: str, query: Any) -> Response:
        result = self.vault.read_node(principal, target)
        if result.status != 200:
            return self._send(result.status, {"error": _error_for(result.status)})
        return self._send(
            200,
            {
                "node": result.node,
                "text": result.text,
                "links": self.vault.links(principal, target),
            },
        )

    def _route_raw(self, principal: str, target: str, query: Any) -> Response:
        result = self.vault.read_node(principal, target)
        if result.status != 200:
            return self._send(result.status, {"error": _error_for(result.status)})

        if self.delivery == "redirect" and "presign" in self.vault.t.capabilities:
            # §12.4: a presigned URL is a bearer token that outlives the ACL
            # check that produced it, so the TTL is short and it is never
            # allowed into a shared cache.
            location = self.vault.t.presign(path_to_key(target), ttl_seconds=120)
            return self._send(
                302, b"", {"location": location, "cache-control": "private, no-store"}
            )
        return self._send(200, result.data, {"content-type": _media_for(target)})

    def _route_list(self, principal: str, target: str, query: Any) -> Response:
        folder = "" if target == "" else (target if is_folder(target) else target + "/")
        key = self._cache_key("list", principal, folder)
        if key in self.cache:
            return self._send(200, self.cache[key])
        listing = self.vault.list_folder(principal, folder)
        if listing["status"] != 200:
            return self._send(listing["status"], {"error": _error_for(listing["status"])})
        body = {
            "folder": folder,
            "entries": listing["entries"],
            "folders": listing["folders"],
        }
        self.cache[key] = body
        return self._send(200, body)

    def _route_links(self, principal: str, target: str, query: Any) -> Response:
        result = self.vault.links(principal, target)
        if result["status"] != 200:
            return self._send(result["status"], {"error": _error_for(result["status"])})
        return self._send(200, {"out": result["out"], "backlinks": result["backlinks"]})

    def _route_search(self, principal: str, target: str, query: Any) -> Response:
        q = (query.get("q") or [""])[0]
        if not q:
            return self._send(400, {"error": "missing_q"})
        return self._send(200, self.vault.search(principal, q))

    def _route_tree(self, principal: str, target: str, query: Any) -> Response:
        key = self._cache_key("tree", principal)
        if key in self.cache:
            return self._send(200, self.cache[key])
        result = self.vault.tree(principal)
        self.cache[key] = result
        return self._send(200, result)

    def _route_effective(self, principal: str, target: str, query: Any) -> Response:
        path = (query.get("path") or [""])[0]
        who = (query.get("principal") or [principal])[0]
        # §8.7 is a privileged view: seeing someone else's effective rights
        # requires read_acl on the object.
        if not self.vault.can(principal, path, ["read_acl"]).allowed:
            return self._send(403, {"error": "forbidden"})
        result = self.vault.effective(who, path)
        return self._send(
            200,
            {
                "principal": who,
                "path": path,
                "granted": result.granted,
                "decisions": result.decisions,
                "failed_at": result.failed_at,
            },
        )

    # ------------------------------------------------------------ serving

    def serve_forever(self, port: int = 4380, host: str = "127.0.0.1") -> None:
        """Run the service until interrupted."""
        self._httpd = _make_server(self, host, port)
        self._httpd.serve_forever()

    def start(self, port: int = 4380, host: str = "127.0.0.1") -> tuple[str, int]:
        """Start the service on a background thread; returns the bound address."""
        import threading

        self._httpd = _make_server(self, host, port)
        thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        thread.start()
        bound = self._httpd.server_address
        return str(bound[0]), int(bound[1])

    def close(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


def _make_server(
    gatekeeper: Gatekeeper, host: str, port: int
) -> socketserver.BaseServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "basalt-gatekeeper/1"

        def _respond(self, include_body: bool) -> None:
            response = gatekeeper.dispatch(self.command, self.path, self.headers)
            payload = response.payload()
            self.send_response(response.status)
            for name, value in response.headers.items():
                self.send_header(name, value)
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            if include_body:
                self.wfile.write(payload)

        def do_GET(self) -> None:  # stdlib naming
            self._respond(True)

        def do_HEAD(self) -> None:  # stdlib naming
            self._respond(False)

        def do_POST(self) -> None:  # stdlib naming
            self._respond(True)

        def log_message(self, fmt: str, *args: Any) -> None:
            pass  # the CLI prints its own line; a request log is not §12's job

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server((host, port), Handler)


__all__ = ["NEVER_SERVE", "Gatekeeper", "Response"]
