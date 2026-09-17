"""Local ephemeral canary listener for SSRF validation (rules.md §3.5, PRD FR-72).

The canary is the ONLY out-of-band receiver AEGIS ever uses to prove a
server-side fetch. It binds strictly to the loopback interface on an ephemeral
port, records every hit (method, path, headers, source address), and exposes
those hits for evidence. There is no external reachability and no third-party
webhook SaaS involvement - even in dev (rules.md §3.5).

Only the platform creates canaries; tools reference `{canary}` via the
`ssrf.canary` controlled payload, whose value is substituted with this
canary's base URL at runtime.
"""

import asyncio
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timezone

from app.core.logging import get_logger

log = get_logger("aegis.control_plane.canary")

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class CanaryHostError(Exception):
    pass


@dataclass
class CanaryHit:
    hit_id: str
    method: str
    path: str
    headers: dict[str, str]
    remote_addr: str
    timestamp: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_handler(store: list, lock: threading.Lock):
    class CanaryHandler(BaseHTTPRequestHandler):
        def _record(self) -> None:
            hit = CanaryHit(
                hit_id=str(uuid.uuid4()),
                method=self.command,
                path=self.path,
                headers={k: v for k, v in self.headers.items()},
                remote_addr=self.client_address[0],
                timestamp=_now(),
            )
            with lock:
                store.append(hit)
            log.info("canary.hit", hit_id=hit.hit_id, method=self.command,
                     path=self.path, source=hit.remote_addr)

        def _respond(self) -> None:
            body = b"canary:ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 (http.server protocol method)
            self._record()
            self._respond()

        def do_POST(self):  # noqa: N802
            self._record()
            self._respond()

        def do_PUT(self):  # noqa: N802
            self._record()
            self._respond()

        def do_HEAD(self):  # noqa: N802
            self._record()
            self._respond()

        def log_message(self, fmt: str, *args) -> None:  # silence default stderr logging
            pass

    return CanaryHandler


class SsrfCanary:
    """Async-managed loopback-only HTTP listener. Lifecycle is start()/stop();
    safe to hold one per scan (Phase 1.5 wire-in)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        if host.lower() not in LOOPBACK_HOSTS:
            raise CanaryHostError(f"canary may only bind a loopback interface, got {host!r}")
        self.host = host
        self.port = port  # 0 => OS-assigned ephemeral port once started
        self._store: list = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._server is None or not self.port:
            raise RuntimeError("canary not started")
        return f"http://{self.host}:{self.port}"

    @property
    def origin(self) -> tuple[str, int]:
        if self._server is None or not self.port:
            raise RuntimeError("canary not started")
        return (self.host, self.port)

    def start(self) -> None:
        if self._server is not None:
            return
        handler = _make_handler(self._store, self._lock)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)  # noqa: S432
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        log.info("canary.started", host=self.host, port=self.port, base_url=self.base_url)

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        self._server = None
        self._thread = None
        log.info("canary.stopped", host=self.host, port=self.port)

    def hits(self) -> list[CanaryHit]:
        with self._lock:
            return list(self._store)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    async def wait_for_hit(self, timeout: float = 5.0) -> CanaryHit | None:
        """Poll for at least one hit; returns the first, or None on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hits = self.hits()
            if hits:
                return hits[0]
            await asyncio.sleep(0.05)
        return None