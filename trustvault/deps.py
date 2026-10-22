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
from .security import hash_token, tokens_equal
from .utils import iso, parse_iso, utcnow

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
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
        """SELECT s.token_hash, s.csrf_token, s.last_seen_at, s.expires_at,
                  u.id, u.username, u.display_name, u.role, u.is_active, u.is_external
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?""",
        (token_hash,),
    ).fetchone()
    if row is None:  # AUTHZ-CHECK[session-must-exist]
        raise HTTPException(status_code=401, detail="Not authenticated")
    now = utcnow()
    idle_limit = now - timedelta(minutes=ctx.settings.session_idle_minutes)
    if parse_iso(row["expires_at"]) <= now or parse_iso(row["last_seen_at"]) <= idle_limit:  # AUTHZ-CHECK[session-expiry]
        with transaction(conn) as tx:
            tx.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        raise HTTPException(status_code=401, detail="Session expired")
    if not row["is_active"]:  # AUTHZ-CHECK[inactive-user-rejected]
        raise HTTPException(status_code=401, detail="Not authenticated")
    if request.method not in SAFE_METHODS and via == "cookie":
        if not tokens_equal(request.headers.get("x-csrf-token"), row["csrf_token"]):  # AUTHZ-CHECK[csrf-token-required]
            raise HTTPException(status_code=403, detail="Missing or invalid CSRF token")
    # Sliding idle timeout; only write when it moved by > 60 s to keep reads cheap.
    if (now - parse_iso(row["last_seen_at"])).total_seconds() > 60:
        conn.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (iso(now), token_hash))
    user = {
        "id": row["id"], "username": row["username"], "display_name": row["display_name"],
        "role": row["role"], "is_active": row["is_active"], "is_external": row["is_external"],
    }
    audit_ctx = AuditContext(actor_id=row["id"], actor_name=row["username"], ip=client_ip(request),
                             user_agent=request.headers.get("user-agent"))
    return Principal(user=user, token_hash=token_hash, csrf_token=row["csrf_token"], via=via, audit_ctx=audit_ctx)


def require_role(*roles: str):
    def checker(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in roles:  # AUTHZ-CHECK[role-required]
            raise HTTPException(status_code=403, detail="Your role does not allow this action")
        return principal
    return checker
