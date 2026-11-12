"""A stand-in for the part of the GitHub gist API that basalt uses, on a local
port, so the gist tests never touch the network or anyone's account.

It is deliberately stricter than it needs to be where GitHub's behaviour is the
reason for a rule in the code under test: a file name with a "/" is refused, an
empty file is refused, a write without the right token is a 401, deleting a
file the gist does not have is a 422, and a file over ``truncate_over`` bytes is
listed without its content. A bug that only shows against the real thing would
be a failure here instead.

The same behaviour as ``ts/test/support/gist-server.mjs``. Not a ``test_*``
module, so pytest does not collect it.
"""

from __future__ import annotations

import datetime as dt
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import quote, unquote, urlparse

TOKEN = "test-token-not-a-real-secret"


def _now() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGists:
    def __init__(self, *, truncate_over: int = 1_000_000, limit_reads: bool = False) -> None:
        self.truncate_over = truncate_over
        self.limit_reads = limit_reads
        self.gists: dict[str, dict[str, Any]] = {}
        self.requests: list[dict[str, Any]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:  # keep test output quiet
                pass

            def _send(self, status: int, body: Any, headers: dict[str, str] | None = None) -> None:
                payload = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(payload)

            def _handle(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else {}
                path = urlparse(self.path).path
                auth = self.headers.get("authorization")
                fake.requests.append(
                    {
                        "method": self.command,
                        "path": path,
                        "auth": auth,
                        "ua": self.headers.get("user-agent"),
                    }
                )
                fake._route(self, self.command, path, auth, body)

            do_GET = do_POST = do_PATCH = _handle

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self.token = TOKEN
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.01), daemon=True
        )
        self._thread.start()

    # ------------------------------------------------------------ helpers

    def seed(
        self, files: dict[str, str], *, public: bool = False, description: str = ""
    ) -> str:
        """Put a gist there directly, as if someone had made it on the website."""
        gist_id = secrets.token_hex(16)
        self.gists[gist_id] = {
            "id": gist_id,
            "public": public,
            "description": description,
            "updated_at": _now(),
            "revisions": 1,
            "files": dict(files),
        }
        return gist_id

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def patches(self) -> int:
        return sum(1 for r in self.requests if r["method"] == "PATCH")

    def posts(self) -> int:
        return sum(1 for r in self.requests if r["method"] == "POST")

    def _view(self, g: dict[str, Any]) -> dict[str, Any]:
        files: dict[str, Any] = {}
        for name, content in g["files"].items():
            size = len(content.encode("utf-8"))
            f: dict[str, Any] = {
                "filename": name,
                "size": size,
                "raw_url": f"{self.url}/raw/{g['id']}/{quote(name, safe='')}",
            }
            if size > self.truncate_over:
                f["truncated"] = True
            else:
                f["truncated"] = False
                f["content"] = content
            files[name] = f
        return {
            "id": g["id"],
            "html_url": f"https://gist.github.com/test/{g['id']}",
            "public": g["public"],
            "description": g["description"],
            "files": files,
            "updated_at": g["updated_at"],
            "truncated": len(g["files"]) > 300,
        }

    @staticmethod
    def _check_files(files: Any, *, creating: bool) -> str | None:
        for name, f in (files or {}).items():
            if not name or "/" in name:
                return f"file name {json.dumps(name)} is not allowed"
            if f is None:
                if creating:
                    return "cannot delete in a create"
                continue
            if not isinstance(f, dict) or not isinstance(f.get("content"), str) or f["content"] == "":
                return f"{name}: content is empty"
        return None

    def _route(
        self, h: BaseHTTPRequestHandler, method: str, path: str, auth: str | None, body: dict[str, Any]
    ) -> None:
        send = h._send  # type: ignore[attr-defined]
        parts = [p for p in path.split("/") if p]

        if method == "GET" and len(parts) == 3 and parts[0] == "raw":
            g = self.gists.get(parts[1])
            content = g["files"].get(unquote(parts[2])) if g else None
            if content is None:
                return send(404, {"message": "Not Found"})
            payload = content.encode("utf-8")
            h.send_response(200)
            h.send_header("Content-Type", "text/plain")
            h.send_header("Content-Length", str(len(payload)))
            h.end_headers()
            h.wfile.write(payload)
            return None
        if self.limit_reads and method == "GET":
            return send(
                403,
                {"message": "API rate limit exceeded"},
                {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "2000000000"},
            )
        if method != "GET" and auth != f"Bearer {TOKEN}":
            return send(401, {"message": "Requires authentication"})

        if method == "POST" and parts == ["gists"]:
            bad = self._check_files(body.get("files"), creating=True)
            if bad:
                return send(422, {"message": f"Validation Failed: {bad}"})
            files = body.get("files") or {}
            if not files:
                return send(422, {"message": "files are required"})
            if len(files) > 300:
                return send(422, {"message": "too many files"})
            gist_id = secrets.token_hex(16)
            g = {
                "id": gist_id,
                "public": bool(body.get("public")),
                "description": body.get("description") or "",
                "updated_at": _now(),
                "revisions": 1,
                "files": {n: f["content"] for n, f in files.items()},
            }
            self.gists[gist_id] = g
            return send(201, self._view(g))

        if len(parts) == 2 and parts[0] == "gists":
            g = self.gists.get(parts[1])
            if g is None:
                return send(404, {"message": "Not Found"})
            if method == "GET":
                return send(200, self._view(g))
            if method == "PATCH":
                bad = self._check_files(body.get("files"), creating=False)
                if bad:
                    return send(422, {"message": f"Validation Failed: {bad}"})
                for n, f in (body.get("files") or {}).items():
                    if f is None:
                        # GitHub answers an unknown file in a delete with 422,
                        # so the code under test must not send one.
                        if n not in g["files"]:
                            return send(422, {"message": f"{n}: no such file"})
                        del g["files"][n]
                    else:
                        g["files"][n] = f["content"]
                if not g["files"]:
                    return send(422, {"message": "a gist needs a file"})
                if len(g["files"]) > 300:
                    return send(422, {"message": "too many files"})
                if isinstance(body.get("description"), str):
                    g["description"] = body["description"]
                g["updated_at"] = _now()
                g["revisions"] += 1
                return send(200, self._view(g))
        return send(404, {"message": "Not Found"})
