"""External share links - the only unauthenticated document route.

The token arrives in a POST body (the page reads it from the URL fragment),
is looked up by its SHA-256, and every condition is re-checked on every use:
not revoked, not expired, uses left, document still live, creator still
active and still the owner. The use counter is incremented with a single
conditional UPDATE so two simultaneous requests cannot both take the last use.
"""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request

from ..audit import AuditContext
from ..context import AppContext
from ..crypto import IntegrityError
from ..db import transaction
from ..deps import anonymous_audit_ctx, app_ctx, client_ip, get_db
from ..models import ShareTokenRequest
from ..security import hash_token
from ..services import get_version, read_version
from ..utils import now_iso
from .documents import download_response

router = APIRouter(prefix="/api/public/share", tags=["public share links"])

INVALID = "This link is invalid, has expired or has been revoked"


def _ctx_for(request: Request, link: dict | None) -> AuditContext:
    label = f"share-link:{link['id']}" if link else "share-link:unknown"
    return anonymous_audit_ctx(request, label)


def _refuse(conn, ctx: AppContext, request: Request, action: str, link: dict | None, reason: str):
    with transaction(conn) as tx:
        ctx.audit.append(tx, _ctx_for(request, link), action, "denied",
                         document_id=link["document_id"] if link else None,
                         details={"reason": reason, "link_id": link["id"] if link else None})
    raise HTTPException(status_code=404, detail=INVALID)


def _resolve(conn, ctx: AppContext, request: Request, token: str, action: str) -> tuple[dict, dict]:
    if not ctx.limiter.allow(f"share-ip:{client_ip(request)}", ctx.settings.public_rate_per_ip_per_minute, 60):
        raise HTTPException(status_code=429, detail="Too many requests")
    row = conn.execute("SELECT * FROM share_links WHERE token_hash = ?", (hash_token(token),)).fetchone()
    if row is None:  # AUTHZ-CHECK[share-link-token-must-exist]
        _refuse(conn, ctx, request, action, None, "unknown_token")
    link = dict(row)
    now = now_iso()
    if link["revoked_at"] is not None:  # AUTHZ-CHECK[share-link-not-revoked]
        _refuse(conn, ctx, request, action, link, "revoked")
    if link["expires_at"] <= now:  # AUTHZ-CHECK[share-link-not-expired]
        _refuse(conn, ctx, request, action, link, "expired")
    if link["use_count"] >= link["max_uses"]:  # AUTHZ-CHECK[share-link-uses-left]
        _refuse(conn, ctx, request, action, link, "used_up")
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (link["document_id"],)).fetchone()
    if doc is None or doc["deleted_at"] is not None or doc["purged_at"] is not None:  # AUTHZ-CHECK[share-link-document-live]
        _refuse(conn, ctx, request, action, link, "document_deleted")
    creator = conn.execute("SELECT id, is_active FROM users WHERE id = ?", (link["created_by"],)).fetchone()
    if creator is None or not creator["is_active"] or doc["owner_id"] != creator["id"]:  # AUTHZ-CHECK[share-link-creator-still-owner]
        _refuse(conn, ctx, request, action, link, "creator_lost_access")
    return link, dict(doc)


@router.post("/info", summary="What a share link points to (anyone holding a valid token)")
def link_info(body: ShareTokenRequest, request: Request, conn: sqlite3.Connection = Depends(get_db),
              ctx: AppContext = Depends(app_ctx)):
    link, doc = _resolve(conn, ctx, request, body.token, "share_link.view")
    version = get_version(conn, doc["current_version_id"])
    with transaction(conn) as tx:
        ctx.audit.append(tx, _ctx_for(request, link), "share_link.view", "allowed", document_id=doc["id"],
                         details={"link_id": link["id"]})
    return {"name": doc["name"], "filename": version["original_filename"], "size_bytes": version["size_bytes"],
            "expires_at": link["expires_at"], "uses_left": link["max_uses"] - link["use_count"]}


@router.post("/download", summary="Download through a share link (anyone holding a valid token)")
def link_download(body: ShareTokenRequest, request: Request, conn: sqlite3.Connection = Depends(get_db),
                  ctx: AppContext = Depends(app_ctx)):
    link, doc = _resolve(conn, ctx, request, body.token, "share_link.download")
    version = get_version(conn, doc["current_version_id"])
    try:
        data = read_version(ctx, version)
    except IntegrityError as exc:
        with transaction(conn) as tx:
            ctx.audit.append(tx, _ctx_for(request, link), "share_link.download", "error", document_id=doc["id"],
                             details={"reason": "integrity", "error": str(exc), "link_id": link["id"]})
        raise HTTPException(status_code=500, detail="Stored file failed its integrity check")
    with transaction(conn) as tx:
        cur = tx.execute(
            """UPDATE share_links SET use_count = use_count + 1
               WHERE id = ? AND revoked_at IS NULL AND use_count < max_uses AND expires_at > ?""",
            (link["id"], now_iso()),
        )
        if cur.rowcount != 1:
            raise HTTPException(status_code=404, detail=INVALID)  # lost a race for the last use
        ctx.audit.append(tx, _ctx_for(request, link), "share_link.download", "allowed", document_id=doc["id"],
                         details={"link_id": link["id"], "version_id": version["id"], "sha256": version["sha256"],
                                  "use": link["use_count"] + 1, "max_uses": link["max_uses"]})
    return download_response(data, version)
