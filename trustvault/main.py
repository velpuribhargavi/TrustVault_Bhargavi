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

__version__ = "0.1.0"
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

[... whole function same as yours ...]

def end_stale_sessions(conn, ctx: AppContext) -> int:
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

# For Render / Uvicorn - THIS WAS MISSING
app = create_app()
