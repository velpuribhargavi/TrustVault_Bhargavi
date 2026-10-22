"""Application factory."""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import Settings, load_settings
from .context import AppContext
from .db import connect, init_schema
from .deps import Principal, current_principal
from .middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from .routes import admin, auth, documents, public, sharing
from .services import purge_expired_trash
from .utils import now_iso
from .validation import ALLOWED_TYPES, CATEGORIES

log = logging.getLogger("trustvault")
STATIC_DIR = Path(__file__).with_name("static")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    first_run = not settings.db_path.exists()
    init_schema(settings.db_path, durable=settings.durable_writes)
    ctx = AppContext.build(settings, create_keys=first_run)

    # Housekeeping at start-up: expired sessions and trash past retention.
    conn = connect(settings.db_path, durable=settings.durable_writes)
    try:
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
        purge_expired_trash(conn, ctx)
    finally:
        conn.close()

    app = FastAPI(
        title="TrustVault API",
        version=__version__,
        description="Secure document sharing with a tamper-evident audit trail. "
                    "Every endpoint states who may call it. See API.md for the full table.",
        docs_url="/api/docs" if settings.enable_api_docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if settings.enable_api_docs else None,
    )
    app.state.ctx = ctx

    # Body limit: the largest legitimate request is one upload plus form overhead.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes + 512 * 1024)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.cookie_secure)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Report which fields are wrong without echoing the submitted values back.
        problems = [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]), "problem": e.get("msg")}
                    for e in exc.errors()]
        return JSONResponse({"detail": "Invalid request", "problems": problems}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        incident = uuid.uuid4().hex[:12]
        log.exception("Unhandled error %s on %s %s", incident, request.method, request.url.path)
        return JSONResponse({"detail": "Internal error", "incident": incident}, status_code=500)

    for module in (auth, documents, sharing, public, admin):
        app.include_router(module.router)

    @app.get("/api/meta", tags=["meta"], summary="Categories and upload limits (any signed-in user)")
    def meta(principal: Principal = Depends(current_principal)):
        return {"categories": list(CATEGORIES), "allowed_extensions": sorted(ALLOWED_TYPES),
                "max_upload_bytes": settings.max_upload_bytes,
                "share_link_max_hours": settings.share_link_max_hours,
                "share_link_max_uses": settings.share_link_max_uses}

    @app.get("/api/health", tags=["meta"], summary="Liveness probe (anyone)")
    def health():
        return {"status": "ok"}

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/share", include_in_schema=False)
    def share_page():
        return FileResponse(STATIC_DIR / "share.html")

    return app
