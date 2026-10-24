"""FastAPI dependencies: database connection, current principal, CSRF, roles."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Iterator

from fastapi import Depends, HTTPException, Request

from .audit import AuditContext
from .context import AppContext
from .db import connect, transaction
from .errors import session_expired
from .expiry import SWEEP_INTERVAL_SECONDS, log_expired_grants
from .links import HEADER as LINK_HEADER
from .links import MAX_TOKEN_LENGTH
from .security import hash_token, session_ref, tokens_equal
from .utils import iso, parse_iso, utcnow

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
# last_seen_at is only rewritten when it is older than this, so a burst of
# requests costs one write. Kept well below the UI's 2-minute warning.
SLIDE_WRITE_SECONDS = 15
COOKIE_NAME = "tv_session"
SECURE_COOKIE_NAME = "__Host-tv_session"  # __Host- prefix: Secure, Path=/, no Domain


def app_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def get_db(request: Request) -> Iterator[sqlite3.Connection]:
    settings = request.app.state.ctx.settings
    conn = connect(settings.db_path, durable=settings.durable_writes)
    try:
        yield conn
    finally:
        conn.close()


def client_ip(request: Request) -> str:
    ctx: AppContext = request.app.state.ctx
    if ctx.settings.trust_proxy:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else "unknown"


def cookie_name(ctx: AppContext) -> str:
    return SECURE_COOKIE_NAME if ctx.settings.cookie_secure else COOKIE_NAME


@dataclass
class Principal:
    user: dict
    token_hash: str
    csrf_token: str
    via: str  # "cookie" or "bearer"
    audit_ctx: AuditContext
    session: dict  # created_at, last_seen_at, expires_at (absolute)

    @property
    def id(self) -> str:
        return self.user["id"]

    @property
    def role(self) -> str:
        return self.user["role"]


def anonymous_audit_ctx(request: Request, name: str | None = None) -> AuditContext:
    return AuditContext(actor_id=None, actor_name=name, ip=client_ip(request),
                        user_agent=request.headers.get("user-agent"))


def _extract_token(request: Request, ctx: AppContext) -> tuple[str | None, str]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip() or None, "bearer"
    return request.cookies.get(cookie_name(ctx)), "cookie"


def current_principal(request: Request, conn: sqlite3.Connection = Depends(get_db)) -> Principal:
    ctx: AppContext = request.app.state.ctx
    token, via = _extract_token(request, ctx)
    if not token:  # AUTHZ-CHECK[session-required]
        raise HTTPException(status_code=401, detail="Not authenticated")
    token_hash = hash_token(token)
    row = conn.execute(
        """SELECT s.token_hash, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at,
                  u.id, u.username, u.display_name, u.role, u.is_active, u.is_external
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?""",
        (token_hash,),
    ).fetchone()
    if row is None:  # AUTHZ-CHECK[session-must-exist]
        raise HTTPException(status_code=401, detail="Not authenticated")
    now = utcnow()
    audit_ctx = AuditContext(actor_id=row["id"], actor_name=row["username"], ip=client_ip(request),
                             user_agent=request.headers.get("user-agent"), session_ref=session_ref(token_hash))
    reason = session_end_reason(ctx, row, now)
    if reason is not None:  # AUTHZ-CHECK[session-expiry]
        with transaction(conn) as tx:
            gone = tx.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,)).rowcount
            if gone:  # only the request that ends the session records it
                ctx.audit.append(tx, audit_ctx, "auth.session_expired", "info",
                                 details={"reason": reason, "last_seen_at": row["last_seen_at"],
                                          "signed_in_at": row["created_at"]})
        raise session_expired()
    if not row["is_active"]:  # AUTHZ-CHECK[inactive-user-rejected]
        raise HTTPException(status_code=401, detail="Not authenticated")
    if request.method not in SAFE_METHODS and via == "cookie":
        if not tokens_equal(request.headers.get("x-csrf-token"), row["csrf_token"]):  # AUTHZ-CHECK[csrf-token-required]
            raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    # Sliding idle timeout: every request counts as activity.
    last_seen = row["last_seen_at"]
    if (now - parse_iso(row["last_seen_at"])).total_seconds() > SLIDE_WRITE_SECONDS:
        last_seen = iso(now)
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (last_seen, token_hash))
    maybe_log_expired_grants(conn, ctx, now)
    user = {
        "id": row["id"], "username": row["username"], "display_name": row["display_name"],
        "role": row["role"], "is_active": row["is_active"], "is_external": row["is_external"],
    }
    session = {"created_at": row["created_at"], "last_seen_at": last_seen, "expires_at": row["expires_at"]}
    return Principal(user=user, token_hash=token_hash, csrf_token=row["csrf_token"], via=via, audit_ctx=audit_ctx,
                     session=session)


def session_end_reason(ctx: AppContext, row, now) -> str | None:
    """'max_lifetime' after SESSION_MAX_HOURS, 'idle' after SESSION_IDLE_MINUTES without a request."""
    if parse_iso(row["expires_at"]) <= now:
        return "max_lifetime"
    if parse_iso(row["last_seen_at"]) <= now - timedelta(minutes=ctx.settings.session_idle_minutes):
        return "idle"
    return None


def maybe_log_expired_grants(conn: sqlite3.Connection, ctx: AppContext, now) -> None:
    """Record expired grants in the audit trail at most every SWEEP_INTERVAL_SECONDS."""
    ts = now.timestamp()
    if ts - ctx.last_expiry_sweep < SWEEP_INTERVAL_SECONDS:
        return
    ctx.last_expiry_sweep = ts
    log_expired_grants(conn, ctx.audit)


def link_token(request: Request) -> str | None:
    """A share link sent with a content request (X-Link-Token header, never the URL)."""
    value = request.headers.get(LINK_HEADER)
    return value[:MAX_TOKEN_LENGTH + 1] if value else None


def require_role(*roles: str):
    """Only these global roles may call the endpoint. A refusal is written to
    the audit trail as 'auth.forbidden' (reason role_required) with the
    method and path, so a viewer probing administrator functions shows up."""
    def checker(request: Request, principal: Principal = Depends(current_principal),
                conn: sqlite3.Connection = Depends(get_db)) -> Principal:
        if principal.role not in roles:  # AUTHZ-CHECK[role-required]
            ctx: AppContext = request.app.state.ctx
            with transaction(conn) as tx:
                ctx.audit.append(tx, principal.audit_ctx, "auth.forbidden", "denied",
                                 details={"reason": "role_required", "role": principal.role, "required": list(roles),
                                          "method": request.method, "path": request.url.path[:200]})
            raise HTTPException(status_code=403, detail="Your role does not allow this action")
        return principal
    return checker
