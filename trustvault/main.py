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
from . import classification as labels
from .config import Settings, load_settings
from .context import AppContext
from .db import connect, init_schema
from .deps import Principal, current_principal
from .middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from .audit import AuditContext
from .db import transaction
from .deps import session_end_reason
from .expiry import log_expired_grants
from .migrations import import_legacy_audit
from .security import session_ref
from .routes import access_requests, admin, auth, documents, sharing
from .services import purge_expired_trash
from .utils import utcnow
from .validation import ALLOWED_TYPES, CATEGORIES

log = logging.getLogger("trustvault")
STATIC_DIR = Path(__file__).with_name("static")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    first_run = not settings.db_path.exists()
    upgrade = init_schema(settings.db_path, durable=settings.durable_writes)
    ctx = AppContext.build(settings, create_keys=first_run)

    # Housekeeping at start-up: finish a schema upgrade (hash backfill needs
    # the audit key), sessions that ended while the server was down, grants
    # that expired while it was down, and trash past retention.
    conn = connect(settings.db_path, durable=settings.durable_writes)
    try:
        record_upgrade(conn, ctx, upgrade)
        end_stale_sessions(conn, ctx)
        log_expired_grants(conn, ctx.audit)
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
        body = {"detail": exc.detail}
        if getattr(exc, "code", None):  # errors.CodedHTTPException: no_access, session_expired
            body["code"] = exc.code
        return JSONResponse(body, status_code=exc.status_code, headers=getattr(exc, "headers", None))

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

    for module in (auth, documents, sharing, access_requests, admin):
        app.include_router(module.router)

    @app.get("/api/meta", tags=["meta"], summary="Categories, upload limits and time limits (any signed-in user)")
    def meta(principal: Principal = Depends(current_principal)):
        return {"categories": list(CATEGORIES), "allowed_extensions": sorted(ALLOWED_TYPES),
                "classifications": list(labels.LABELS), "default_classification": labels.DEFAULT,
                "confidential_grant_minutes": settings.confidential_grant_minutes,
                "access_request_days": settings.access_request_days,
                "max_upload_bytes": settings.max_upload_bytes,
                "link_ttl_seconds": settings.link_ttl_seconds,
                "default_grant_minutes": settings.default_grant_minutes,
                "max_grant_days": settings.max_grant_days,
                "session_idle_minutes": settings.session_idle_minutes,
                "session_max_hours": settings.session_absolute_hours,
                "session_warning_seconds": settings.session_warning_seconds,
                "office_renderer": "libreoffice" if ctx.office.available else "text"}

    @app.get("/api/health", tags=["meta"], summary="Liveness probe (anyone)")
    def health():
        return {"status": "ok"}

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html")

    return app


SYSTEM_MIGRATION = AuditContext(actor_id=None, actor_name="system:migration", ip=None, user_agent=None)


def record_upgrade(conn, ctx: AppContext, upgrade) -> None:
    """Backfill hashes for a pre-chain audit table, then record the upgrade
    itself as an audit event (so the trail shows when the schema changed)."""
    if upgrade is None:
        return
    import_legacy_audit(conn, ctx.audit, upgrade)
    if upgrade.changed:
        with transaction(conn) as tx:
            ctx.audit.append(tx, SYSTEM_MIGRATION, "audit.migrated", "info", details=upgrade.details())
        log.info("Database upgraded from schema v%s to v%s: %s", upgrade.from_version, upgrade.to_version,
                 "; ".join(upgrade.steps))


def end_stale_sessions(conn, ctx: AppContext) -> int:
    """Remove sessions that hit the idle or absolute limit while nobody used
    them, recording each as auth.session_expired."""
    now = utcnow()
    rows = conn.execute("""SELECT s.token_hash, s.created_at, s.last_seen_at, s.expires_at, u.id, u.username
                           FROM sessions s JOIN users u ON u.id = s.user_id""").fetchall()
    ended = 0
    for row in rows:
        reason = session_end_reason(ctx, row, now)
        if reason is None:
            continue
        with transaction(conn) as tx:
            if tx.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],)).rowcount:
                ctx.audit.append(tx, AuditContext(row["id"], row["username"], None, None,
                                                  session_ref=session_ref(row["token_hash"])), "auth.session_expired",
                                 "info", details={"reason": reason, "last_seen_at": row["last_seen_at"],
                                                  "signed_in_at": row["created_at"], "detected": "start-up"})
                ended += 1
    return ended
