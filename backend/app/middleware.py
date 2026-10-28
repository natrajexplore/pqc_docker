"""Request guard, access log and logging setup for the API.

Guard: the UI is published on loopback only, but the browser on this machine will
send requests there on behalf of any website it visits. Two checks close that gap:
  * the Host header must name an allowed host - defeats DNS rebinding;
  * an Origin header, when the browser sends one, must equal the Host - defeats CSRF
    on the POST endpoints and cross-site WebSocket hijacking. Non-browser clients
    (curl, scripts/smoke.sh) send no Origin and are unaffected.

Access log: one line per request (method, path, status, duration) tagged with a
request id - nginx's X-Request-ID when present, otherwise generated - which is also
stamped on every log record emitted while the request (or a run it started) executes.
"""
from __future__ import annotations

import contextvars
import json
import logging
import re
import secrets
import time
from urllib.parse import urlsplit

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
log = logging.getLogger("pqcw.access")

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
QUIET_PATHS = {"/api/health"}  # healthchecks would drown the log at INFO


def _hostname(netloc: str) -> str:
    """'127.0.0.1:8080' -> '127.0.0.1', '[::1]:8080' -> '::1'."""
    try:
        return (urlsplit(f"//{netloc}").hostname or "").lower()
    except ValueError:
        return ""


class GuardAndLog:
    """Pure ASGI middleware so it covers WebSockets as well as HTTP."""

    def __init__(self, app, allowed_hosts: set[str]):
        self.app = app
        self.allowed = {h.strip().lower() for h in allowed_hosts if h.strip()}

    def _reject_reason(self, headers: dict[str, str]) -> str | None:
        host = headers.get("host", "")
        if "*" not in self.allowed and _hostname(host) not in self.allowed:
            return f"host {host!r} not allowed"
        origin = headers.get("origin")
        if origin is not None and urlsplit(origin).netloc.lower() != host.lower():
            return f"cross-origin request from {origin!r}"
        return None

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        rid = headers.get("x-request-id", "")
        if not REQUEST_ID_RE.match(rid):
            rid = secrets.token_hex(8)
        token = request_id.set(rid)
        method = scope.get("method", "WS")
        path = scope.get("path", "")
        start = time.perf_counter()
        status = 0

        async def send_wrapper(msg):
            nonlocal status
            if msg["type"] == "http.response.start":
                status = msg["status"]
                msg["headers"] = [*msg.get("headers", []), (b"x-request-id", rid.encode())]
            elif msg["type"] == "websocket.accept":
                status = 101
            elif msg["type"] == "websocket.close" and not status:
                status = 403
            await send(msg)

        try:
            reason = self._reject_reason(headers)
            if reason:
                log.warning("rejected %s %s: %s", method, path, reason)
                if scope["type"] == "websocket":
                    await receive()  # websocket.connect
                    await send_wrapper({"type": "websocket.close", "code": 4403})
                else:
                    await send_wrapper({"type": "http.response.start", "status": 403,
                                        "headers": [(b"content-type", b"application/json")]})
                    await send_wrapper({"type": "http.response.body", "body": b'{"detail":"request rejected"}'})
                return
            await self.app(scope, receive, send_wrapper)
        finally:
            ms = (time.perf_counter() - start) * 1000
            level = logging.DEBUG if path in QUIET_PATHS and status < 400 else logging.INFO
            log.log(level, "%s %s -> %s in %.1f ms", method, path, status or "-", ms)
            request_id.reset(token)


# ------------------------------------------------------------- logging --
class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get()
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {"ts": self.formatTime(record), "level": record.levelname, "logger": record.name,
               "request_id": getattr(record, "request_id", "-"), "msg": record.getMessage()}
        if record.exc_info:
            doc["exc"] = self.formatException(record.exc_info)
        return json.dumps(doc)


def configure_logging(level: str, fmt: str) -> None:
    """fmt: 'text' (default, human) or 'json' (one object per line, for log shippers)."""
    handler = logging.StreamHandler()
    handler.addFilter(_RequestIdFilter())
    if fmt == "json":
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s [%(request_id)s]: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
