"""Pure-ASGI middleware: security headers and request body size limit."""
from __future__ import annotations

import json

CSP_APP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'self'; frame-ancestors 'none'"
)
# Swagger UI loads its bundle from jsDelivr; allow that only on the docs page.
CSP_API_DOCS = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    def __init__(self, app, hsts: bool = False):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in {
                    b"x-frame-options", b"x-content-type-options", b"referrer-policy", b"server"}]
                existing = {k.lower() for k, _ in headers}
                add = {
                    b"x-content-type-options": b"nosniff",
                    b"x-frame-options": b"DENY",
                    b"referrer-policy": b"no-referrer",
                    b"permissions-policy": b"camera=(), microphone=(), geolocation=(), payment=()",
                    b"cross-origin-opener-policy": b"same-origin",
                    b"cross-origin-resource-policy": b"same-origin",
                }
                if b"content-security-policy" not in existing:
                    csp = CSP_API_DOCS if path in ("/api/docs", "/api/docs/oauth2-redirect") else CSP_APP
                    add[b"content-security-policy"] = csp.encode()
                if path.startswith("/api/") and b"cache-control" not in existing:
                    add[b"cache-control"] = b"no-store"
                    add[b"pragma"] = b"no-cache"
                if self.hsts:
                    add[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                for k, v in add.items():
                    if k not in existing:
                        headers.append((k, v))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


class BodySizeLimitMiddleware:
    """Reject request bodies above ``max_bytes`` - by Content-Length up front,
    and by counting for chunked bodies - before any parsing happens."""

    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for key, value in scope.get("headers", []):
            if key == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await _too_large(send)
                        return
                except ValueError:
                    await _too_large(send, 400, "Invalid Content-Length")
                    return
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _too_large(send)


class _BodyTooLarge(Exception):
    pass


async def _too_large(send, status: int = 413, detail: str = "Request body too large"):
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
