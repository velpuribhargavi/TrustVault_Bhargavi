"""Sharing: time-limited grants, 5-minute share links, access suggestions and
the user directory owners pick people from.

Audit events written here
    access.granted / access.changed / access.extended / access.revoked
        (access.expired is written by expiry.py when a grant runs out)
    link.created / link.opened / link.revoked_all
    ai.suggestion.generated / .accepted / .dismissed
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException

from .. import classification as labels
from ..authz import _RANK, Action, Decision, record_denial, require_access
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, app_ctx, current_principal, get_db, require_role
from ..errors import no_access
from ..expiry import log_expired_grants
from ..links import BadLink, issue, verify_signature
from ..models import ExtendGrantRequest, GrantRequest, LinkOpenRequest, LinkRequest
from ..suggestions import suggest_readers
from ..utils import is_valid_id, iso, new_id, now_iso, parse_iso, utcnow

router = APIRouter(tags=["sharing"])


# ---------------------------------------------------------------- directory --
@router.get("/api/users/directory", summary="People that can be granted access (role: owner)")
def user_directory(principal: Principal = Depends(require_role("owner")), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(
        """SELECT id, username, display_name, is_external FROM users
           WHERE is_active = 1 AND role != 'admin' AND id != ? ORDER BY display_name COLLATE NOCASE""",
        (principal.id,),
    ).fetchall()
    return {"items": [{**dict(r), "is_external": bool(r["is_external"])} for r in rows]}


# ------------------------------------------------------------------- grants --
def _grant_expiry(ctx: AppContext, body, label: str) -> str:
    """Every grant expires. Default: DEFAULT_GRANT_MINUTES from now - or
    CONFIDENTIAL_GRANT_MINUTES (1 hour) for a Confidential document."""
    now = utcnow()
    limit = now + timedelta(days=ctx.settings.max_grant_days)
    if body.duration_minutes is not None and body.expires_at is not None:
        raise HTTPException(status_code=400, detail="Send either duration_minutes or expires_at, not both")
    if body.expires_at is not None:
        exp = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=timezone.utc)
    else:
        exp = now + timedelta(minutes=body.duration_minutes or labels.default_grant_minutes(ctx.settings, label))
    if exp <= now:
        raise HTTPException(status_code=400, detail="Expiry must be in the future")
    if exp > limit:
        raise HTTPException(status_code=400, detail=f"Access can be given for at most {ctx.settings.max_grant_days} days")
    return iso(exp)


def _grant_out(row: dict, now: str) -> dict:
    item = dict(row)
    for key in ("is_external", "is_active"):
        if key in item:
            item[key] = bool(item[key])
    item["expired"] = item["expires_at"] <= now
    item["seconds_left"] = max(0, int((parse_iso(item["expires_at"]) - parse_iso(now)).total_seconds()))
    item.pop("expiry_logged_at", None)
    return item


@router.get("/api/documents/{doc_id}/grants", summary="Who has access, and until when (owner only)")
def list_grants(doc_id: str, principal: Principal = Depends(current_principal),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="access.list").doc
    log_expired_grants(conn, ctx.audit, document_id=doc["id"])
    rows = conn.execute(
        """SELECT g.id, g.permission, g.created_at, g.expires_at, g.source,
                  u.id AS user_id, u.username, u.display_name, u.is_external, u.is_active,
                  gb.username AS granted_by
           FROM grants g JOIN users u ON u.id = g.user_id JOIN users gb ON gb.id = g.granted_by
           WHERE g.document_id = ? ORDER BY g.expires_at <= ?, u.display_name COLLATE NOCASE""",
        (doc["id"], now_iso()),
    ).fetchall()
    now = now_iso()
    return {"items": [_grant_out(dict(r), now) for r in rows], "server_time": now,
            "classification": doc["classification"],
            "default_grant_minutes": labels.default_grant_minutes(ctx.settings, doc["classification"]),
            "default_permission": labels.default_permission(doc["classification"])}


@router.post("/api/documents/{doc_id}/grants", status_code=201,
             summary="Give or change a person's access, for a limited time (owner only)")
def grant_access(doc_id: str, body: GrantRequest, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="access.granted").doc
    return give_access(conn, ctx, principal, doc, body)


def give_access(conn, ctx: AppContext, principal: Principal, doc: dict, body: GrantRequest, *,
                refuse_action: str = "access.granted", in_tx=None) -> dict:
    """Give or change one person's access to ``doc``, which the caller has
    already been authorised to share (require_access, Action.SHARE). Used by the
    grant endpoint and by approving a request. ``in_tx(tx, grant)`` runs inside
    the same transaction as the grant and its audit event."""
    permission = body.permission or labels.default_permission(doc["classification"])

    def refuse(status: int, message: str, reason: str, target_id: str | None = None):
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, refuse_action, "denied", document_id=doc["id"],
                             target_user_id=target_id, details={"reason": reason, "username": body.username[:64]})
        raise HTTPException(status_code=status, detail=message)

    target = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    if target is None:
        refuse(404, "No such user", "unknown_user")
    if target["id"] == doc["owner_id"]:
        refuse(400, "The owner already has full access", "target_is_owner", target["id"])
    if not target["is_active"]:  # AUTHZ-CHECK[grant-target-must-be-active]
        refuse(400, "That account is deactivated", "target_inactive", target["id"])
    if target["role"] == "admin":  # AUTHZ-CHECK[grant-target-not-admin]
        refuse(400, "Administrators cannot be given document access (separation of duties)", "target_admin", target["id"])

    try:
        expires_at = _grant_expiry(ctx, body, doc["classification"])
    except HTTPException as exc:
        refuse(exc.status_code, exc.detail, "invalid_duration", target["id"])

    suggestion = None
    if body.suggestion_id is not None:
        suggestion = conn.execute("SELECT * FROM suggestions WHERE id = ?", (body.suggestion_id,)).fetchone()
        mismatch = (suggestion is None or suggestion["document_id"] != doc["id"]
                    or suggestion["suggested_user_id"] != target["id"] or suggestion["status"] != "pending")
        if mismatch:  # AUTHZ-CHECK[suggestion-matches-document]
            refuse(400, "Suggestion does not match this document and person, or was already decided",
                   "suggestion_mismatch", target["id"])

    existing = conn.execute("SELECT * FROM grants WHERE document_id = ? AND user_id = ?",
                            (doc["id"], target["id"])).fetchone()
    now = now_iso()
    source = "suggestion" if suggestion else "manual"
    details = {"permission": permission, "expires_at": expires_at, "target_username": target["username"],
               "target_external": bool(target["is_external"]), "source": source}
    with transaction(conn) as tx:
        if existing:
            live = existing["expires_at"] > now
            tx.execute("""UPDATE grants SET permission = ?, expires_at = ?, expiry_logged_at = NULL, granted_by = ?,
                          source = ? WHERE id = ?""",
                       (permission, expires_at, principal.id, source, existing["id"]))
            grant_id = existing["id"]
            action = "access.changed" if live else "access.granted"
            details["previous"] = {"permission": existing["permission"], "expires_at": existing["expires_at"],
                                   "was_expired": not live}
            # Lowering a level also kills any share link already issued for this document.
            if live and _RANK[permission] < _RANK[existing["permission"]]:
                tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (doc["id"],))
                details["links_invalidated"] = True
        else:
            grant_id, action = new_id(), "access.granted"
            tx.execute(
                """INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (grant_id, doc["id"], target["id"], permission, principal.id, now, expires_at, source),
            )
        if suggestion:
            tx.execute("UPDATE suggestions SET status = 'accepted', decided_at = ? WHERE id = ?",
                       (now, suggestion["id"]))
            details["suggestion_id"] = suggestion["id"]
            details["suggested_permission"] = suggestion["permission"]
            ctx.audit.append(tx, principal.audit_ctx, "ai.suggestion.accepted", "allowed", document_id=doc["id"],
                             target_user_id=target["id"],
                             details={"suggestion_id": suggestion["id"], "decided_permission": permission,
                                      "decided_by": principal.user["username"]})
        details["grant_id"] = grant_id
        if in_tx is not None:
            in_tx(tx, {"id": grant_id, "permission": permission, "expires_at": expires_at, "user_id": target["id"]})
        ctx.audit.append(tx, principal.audit_ctx, action, "allowed", document_id=doc["id"],
                         target_user_id=target["id"], details=details)
    return {"id": grant_id, "permission": permission, "expires_at": expires_at, "source": source,
            "server_time": now}


def _grant_of_document(conn, ctx: AppContext, principal: Principal, doc: dict, grant_id: str,
                       audit_action: str) -> dict:
    """Load a grant id and make sure it belongs to the document just checked."""
    grant = conn.execute("SELECT * FROM grants WHERE id = ?", (grant_id,)).fetchone() if is_valid_id(grant_id) else None
    if grant is None or grant["document_id"] != doc["id"]:  # AUTHZ-CHECK[grant-belongs-to-document]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, audit_action, "denied", document_id=doc["id"],
                             details={"reason": "grant_not_in_document", "grant_id": grant_id[:64]})
        raise HTTPException(status_code=404, detail="Grant not found")
    return dict(grant)


@router.post("/api/documents/{doc_id}/grants/{grant_id}/extend",
             summary="Add time to a grant - also revives an expired one (owner only)")
def extend_grant(doc_id: str, grant_id: str, body: ExtendGrantRequest, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="access.extended").doc
    grant = _grant_of_document(conn, ctx, principal, doc, grant_id, "access.extended")
    target = conn.execute("SELECT username, is_active, role FROM users WHERE id = ?", (grant["user_id"],)).fetchone()

    def refuse(message: str, reason: str):
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "access.extended", "denied", document_id=doc["id"],
                             target_user_id=grant["user_id"],
                             details={"reason": reason, "grant_id": grant["id"], "minutes": body.minutes})
        raise HTTPException(status_code=400, detail=message)

    if not target["is_active"]:
        refuse("That account is deactivated", "target_inactive")
    now = utcnow()
    start = max(now, parse_iso(grant["expires_at"]))
    new_expiry = start + timedelta(minutes=body.minutes)
    if new_expiry > now + timedelta(days=ctx.settings.max_grant_days):
        refuse(f"Access can be given for at most {ctx.settings.max_grant_days} days", "invalid_duration")
    with transaction(conn) as tx:
        tx.execute("UPDATE grants SET expires_at = ?, expiry_logged_at = NULL WHERE id = ?", (iso(new_expiry), grant["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "access.extended", "allowed", document_id=doc["id"],
                         target_user_id=grant["user_id"],
                         details={"grant_id": grant["id"], "permission": grant["permission"],
                                  "from": grant["expires_at"], "to": iso(new_expiry), "added_minutes": body.minutes,
                                  "was_expired": grant["expires_at"] <= iso(now), "target_username": target["username"]})
    return {"id": grant["id"], "expires_at": iso(new_expiry), "server_time": iso(now)}


@router.delete("/api/documents/{doc_id}/grants/{grant_id}", summary="Revoke a grant (owner only). Immediate.")
def revoke_grant(doc_id: str, grant_id: str, principal: Principal = Depends(current_principal),
                 conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="access.revoked").doc
    grant = _grant_of_document(conn, ctx, principal, doc, grant_id, "access.revoked")
    target = conn.execute("SELECT username FROM users WHERE id = ?", (grant["user_id"],)).fetchone()
    with transaction(conn) as tx:
        tx.execute("DELETE FROM grants WHERE id = ?", (grant["id"],))
        # Any share link already issued for this document dies with it.
        tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (doc["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "access.revoked", "allowed", document_id=doc["id"],
                         target_user_id=grant["user_id"],
                         details={"grant_id": grant["id"], "permission": grant["permission"],
                                  "expires_at": grant["expires_at"], "target_username": target["username"]})
    return {"ok": True}


# -------------------------------------------------------------- share links --
@router.post("/api/documents/{doc_id}/links", status_code=201,
             summary="Make a signed share link for one named person who already has access, valid LINK_TTL_SECONDS (owner only)")
def create_link(doc_id: str, body: LinkRequest, principal: Principal = Depends(current_principal),
                conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="link.created").doc

    def refuse(status: int, message: str, reason: str, target_id: str | None = None):
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "link.created", "denied", document_id=doc["id"],
                             target_user_id=target_id, details={"reason": reason, "username": body.username[:64]})
        raise HTTPException(status_code=status, detail=message)

    target = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    if target is None:
        refuse(404, "No such user", "unknown_user")
    if target["id"] == doc["owner_id"]:
        refuse(400, "You already own this document", "target_is_owner", target["id"])
    if not target["is_active"]:  # AUTHZ-CHECK[link-recipient-must-be-active]
        refuse(400, "That account is deactivated", "target_inactive", target["id"])
    if target["role"] == "admin":  # AUTHZ-CHECK[link-recipient-not-admin]
        refuse(400, "Administrators cannot be given document access (separation of duties)", "target_admin", target["id"])
    # A link never gives access on its own: the person must already hold a live
    # grant, and the link can be at most their level (it is re-checked on every use).
    grant = conn.execute("SELECT permission, expires_at FROM grants WHERE document_id = ? AND user_id = ?",
                         (doc["id"], target["id"])).fetchone()
    if grant is None or grant["expires_at"] <= now_iso():  # AUTHZ-CHECK[link-recipient-needs-grant]
        refuse(400, "Give this person access first - a link only works for someone who already has access",
               "no_grant", target["id"])
    if _RANK[body.permission] > _RANK[grant["permission"]]:  # AUTHZ-CHECK[link-not-above-grant]
        refuse(400, "A link cannot give more than the person's own access (they have View only)",
               "link_above_grant", target["id"])

    now = utcnow()
    token, claims = issue(ctx.keyring, document_id=doc["id"], recipient_id=target["id"], creator_id=principal.id,
                          permission=body.permission, access_version=doc["access_version"],
                          now_ts=int(now.timestamp()), ttl_seconds=ctx.settings.link_ttl_seconds)
    expires_at = iso(datetime.fromtimestamp(claims.expires_at, tz=timezone.utc))
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "link.created", "allowed", document_id=doc["id"],
                         target_user_id=target["id"],
                         details={"link_id": claims.link_id, "permission": body.permission,
                                  "recipient": target["username"], "expires_at": expires_at,
                                  "access_version": doc["access_version"], "ttl_seconds": ctx.settings.link_ttl_seconds})
    # The token goes in the URL *fragment*: browsers never send it to the server
    # in the page request, so it stays out of access logs and Referer headers.
    return {"link_id": claims.link_id, "token": token, "path": f"/#/l/{token}", "recipient": target["username"],
            "permission": body.permission, "expires_at": expires_at, "ttl_seconds": ctx.settings.link_ttl_seconds,
            "server_time": iso(now)}


@router.get("/api/documents/{doc_id}/links", summary="Links made in the last few minutes and their state (owner only)")
def list_links(doc_id: str, principal: Principal = Depends(current_principal),
               conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="link.list").doc
    now = utcnow()
    since = iso(now - timedelta(seconds=ctx.settings.link_ttl_seconds * 3))
    # Links are not stored; the audit trail is the record of what was issued.
    rows = conn.execute(
        """SELECT ts, details FROM audit_log WHERE document_id = ? AND action = 'link.created'
           AND outcome = 'allowed' AND ts >= ? ORDER BY seq DESC LIMIT 50""", (doc["id"], since)).fetchall()
    opened = {json.loads(r["details"]).get("link_id") for r in conn.execute(
        """SELECT details FROM audit_log WHERE document_id = ? AND action = 'link.opened'
           AND outcome = 'allowed' AND ts >= ?""", (doc["id"], since))}
    items = []
    for r in rows:
        d = json.loads(r["details"])
        status = ("expired" if d["expires_at"] <= iso(now)
                  else "revoked" if d.get("access_version") != doc["access_version"] else "active")
        items.append({"link_id": d["link_id"], "recipient": d["recipient"], "permission": d["permission"],
                      "created_at": r["ts"], "expires_at": d["expires_at"], "status": status,
                      "opened": d["link_id"] in opened})
    return {"items": items, "server_time": iso(now), "ttl_seconds": ctx.settings.link_ttl_seconds}


@router.post("/api/documents/{doc_id}/links/revoke-all",
             summary="Invalidate every outstanding share link for this document at once (owner only)")
def revoke_all_links(doc_id: str, principal: Principal = Depends(current_principal),
                     conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="link.revoked_all").doc
    with transaction(conn) as tx:
        tx.execute("UPDATE documents SET access_version = access_version + 1 WHERE id = ?", (doc["id"],))
        ctx.audit.append(tx, principal.audit_ctx, "link.revoked_all", "allowed", document_id=doc["id"],
                         details={"from_version": doc["access_version"], "to_version": doc["access_version"] + 1})
    return {"ok": True}


@router.post("/api/links/open", summary="Open a share link made for you (any signed-in user; the named recipient only)")
def open_link(body: LinkOpenRequest, principal: Principal = Depends(current_principal),
              conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    if not ctx.limiter.allow(f"link-open:{principal.id}", ctx.settings.link_rate_per_user_per_minute, 60):
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "link.opened", "denied", details={"reason": "rate_limited"})
        raise HTTPException(status_code=429, detail="Too many attempts. Wait a minute and try again.")
    try:
        doc_id = verify_signature(ctx.keyring, body.token).document_id
    except BadLink:
        # Not even a valid signature: refuse without touching any document.
        record_denial(conn, ctx, principal.audit_ctx, Decision(False, "link_invalid", Action.VIEW), "", "link.opened")
        raise no_access()
    d = require_access(conn, ctx, principal, doc_id, Action.VIEW, link_token=body.token, audit_action="link.opened")
    with transaction(conn) as tx:
        ctx.audit.append(tx, principal.audit_ctx, "link.opened", "allowed", document_id=d.doc["id"],
                         details={"link_id": d.link.link_id, "permission": d.link.permission,
                                  "effective_permission": d.permission, "via": d.via})
    return {"document_id": d.doc["id"], "name": d.doc["name"], "link_permission": d.link.permission,
            "permission": d.permission, "via": d.via,
            "expires_at": iso(datetime.fromtimestamp(d.link.expires_at, tz=timezone.utc)), "server_time": now_iso()}


# -------------------------------------------------------------- suggestions --
@router.get("/api/documents/{doc_id}/suggestions",
            summary="Suggest people who may need view access (owner only). Never grants anything.")
def get_suggestions(doc_id: str, principal: Principal = Depends(current_principal),
                    conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="ai.suggestion.generated").doc
    proposals = suggest_readers(conn, principal.id, doc)
    now = now_iso()
    with transaction(conn) as tx:
        # Older undecided suggestions for this document are superseded.
        tx.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? WHERE document_id = ? AND status = 'pending'",
                   (now, doc["id"]))
        for p in proposals:
            p["suggestion_id"] = new_id()
            tx.execute(
                """INSERT INTO suggestions (id, document_id, owner_id, suggested_user_id, permission, score, reasons,
                                            status, created_at) VALUES (?, ?, ?, ?, 'view', ?, ?, 'pending', ?)""",
                (p["suggestion_id"], doc["id"], principal.id, p["user_id"], p["score"], json.dumps(p["reasons"]), now),
            )
        ctx.audit.append(tx, principal.audit_ctx, "ai.suggestion.generated", "info", document_id=doc["id"],
                         details={"engine": "local-heuristic-v1",
                                  "suggestions": [{"suggestion_id": p["suggestion_id"], "username": p["username"],
                                                   "permission": p["permission"], "score": p["score"]}
                                                  for p in proposals]})
    return {"items": proposals,
            "note": "Suggestions never change access. Confirm a person to give them view-only access "
                    f"for {ctx.settings.default_grant_minutes} minutes (you can choose a higher level or longer time instead)."}


@router.post("/api/documents/{doc_id}/suggestions/{suggestion_id}/dismiss", summary="Dismiss a suggestion (owner only)")
def dismiss_suggestion(doc_id: str, suggestion_id: str, principal: Principal = Depends(current_principal),
                       conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc = require_access(conn, ctx, principal, doc_id, Action.SHARE, audit_action="ai.suggestion.dismissed").doc
    sug = conn.execute("SELECT * FROM suggestions WHERE id = ?", (suggestion_id,)).fetchone() \
        if is_valid_id(suggestion_id) else None
    if sug is None or sug["document_id"] != doc["id"]:  # AUTHZ-CHECK[dismiss-suggestion-belongs-to-document]
        raise HTTPException(status_code=404, detail="Suggestion not found")
    if sug["status"] != "pending":
        raise HTTPException(status_code=409, detail="Suggestion already decided")
    with transaction(conn) as tx:
        tx.execute("UPDATE suggestions SET status = 'dismissed', decided_at = ? WHERE id = ?", (now_iso(), sug["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "ai.suggestion.dismissed", "info", document_id=doc["id"],
                         target_user_id=sug["suggested_user_id"], details={"suggestion_id": sug["id"]})
    return {"ok": True}
