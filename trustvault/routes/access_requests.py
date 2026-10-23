"""Requests for access: a person asks, the document's owner approves (choosing
level and duration) or denies with an optional reason, and the person sees
what happened.

Why this is not a ``/api/documents/{id}/...`` route: every route under a
document id starts with the access check, and the person asking has, by
definition, no access. More importantly, asking must not become a way to find
out what exists. So ``POST /api/access-requests`` gives **the same answer for
any document id** - existing or not, shareable or not - and stores the request
either way. Only the owner of a real document ever sees a request; one for an
id that does not exist simply lapses after ACCESS_REQUEST_DAYS. The requester
does not see the document's name until the owner approves.

Approving goes through the one access check (``require_access``, Action.SHARE)
on the request's document, and then through the same code as giving access by
hand (``sharing.give_access``): same target checks, same expiry rules, same
audit events - plus ``access.request_approved``.

Audit events: access.requested, access.request_approved, access.request_denied,
access.request_withdrawn (and access.granted / access.changed on approval).
"""
from __future__ import annotations

import sqlite3
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status

from .. import classification as labels
from ..authz import _RANK, Action, require_access
from ..context import AppContext
from ..db import transaction
from ..deps import Principal, app_ctx, current_principal, get_db, require_role
from ..models import AccessRequestCreate, ApproveRequest, DenyRequest, GrantRequest
from ..utils import clean_line, clean_text, is_valid_id, iso, new_id, now_iso, utcnow
from .sharing import give_access

router = APIRouter(prefix="/api/access-requests", tags=["access requests"])
not_admin = require_role("owner", "viewer")  # administrators are never given document access

SENT = ("Request sent. If this document exists and its owner can share it, they will see your request; "
        "its status appears under My requests.")
ENDED_ACCESS_DAYS = 90

# A person's own requests only. The requester line is what stops one person
# from reading or withdrawing another's requests (mutation-tested).
_MY_REQUESTS_SQL = (
    "SELECT r.*, d.name AS document_name, d.classification FROM access_requests r "
    "LEFT JOIN documents d ON d.id = r.document_id AND d.purged_at IS NULL WHERE 1 = 1 "
    "AND r.requester_id = :uid "  # AUTHZ-SQL[requests-are-own-only]
)
# Requests waiting for the caller: only for documents the caller owns.
_INCOMING_SQL = (
    "SELECT r.*, d.name AS document_name, d.classification, d.deleted_at, "
    "u.username, u.display_name, u.is_external, u.is_active "
    "FROM access_requests r JOIN documents d ON d.id = r.document_id JOIN users u ON u.id = r.requester_id "
    "WHERE r.status = 'pending' AND r.expires_at > :now AND d.purged_at IS NULL "
    "AND d.owner_id = :uid "  # AUTHZ-SQL[incoming-requests-own-documents-only]
)

# Grants of mine that ran out recently. Revoked grants are deleted, so they never
# show here: the owner meant to remove them.
_ENDED_SQL = (
    "SELECT d.id, d.name, d.classification, g.permission, g.expires_at, u.display_name AS owner "
    "FROM grants g JOIN documents d ON d.id = g.document_id JOIN users u ON u.id = d.owner_id "
    "WHERE g.expires_at <= :now AND g.expires_at > :since AND d.deleted_at IS NULL AND d.purged_at IS NULL "
    "AND g.user_id = :uid "  # AUTHZ-SQL[ended-access-own-only]
)


def _status(row) -> str:
    return "expired" if row["status"] == "pending" and row["expires_at"] <= now_iso() else row["status"]


def _mine_out(row) -> dict:
    st = _status(row)
    approved = st == "approved"
    return {
        "id": row["id"], "document_id": row["document_id"],
        # The name is shown only once the owner has said yes.
        "document_name": row["document_name"] if approved else None,
        "classification": row["classification"] if approved else None,
        "permission": row["permission"], "note": row["note"], "status": st,
        "created_at": row["created_at"], "expires_at": row["expires_at"], "decided_at": row["decided_at"],
        "owner_reason": row["decision_note"] if st == "denied" else None,
        "granted_permission": row["granted_permission"], "grant_expires_at": row["grant_expires_at"],
    }


def _current_level(conn, user_id: str, doc) -> str | None:
    if doc["owner_id"] == user_id:
        return "owner"
    g = conn.execute("SELECT permission FROM grants WHERE document_id = ? AND user_id = ? AND expires_at > ?",
                     (doc["id"], user_id, now_iso())).fetchone()
    return g["permission"] if g else None


# ------------------------------------------------------------------- asking --
@router.post("", status_code=status.HTTP_202_ACCEPTED,
             summary="Ask for access to a document (owner or viewer role; never an administrator). The same answer "
                     "whether or not the document exists.")
def create_request(body: AccessRequestCreate, principal: Principal = Depends(not_admin),
                   conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    doc_id = body.document_id.strip()
    note = clean_text(body.note, 500)

    def refuse(code: int, message: str, reason: str):
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, "access.requested", "denied",
                             details={"reason": reason, "requested_id": doc_id[:64]})
        raise HTTPException(status_code=code, detail=message)

    if not is_valid_id(doc_id):
        refuse(422, "That is not a TrustVault document link or id.", "invalid_id")
    if not ctx.limiter.allow(f"access-request:{principal.id}", 10, 60):
        refuse(429, "Too many requests. Wait a minute and try again.", "rate_limited")
    pending = conn.execute("SELECT COUNT(*) FROM access_requests WHERE requester_id = ? AND status = 'pending' "
                           "AND expires_at > ?", (principal.id, now_iso())).fetchone()[0]
    if pending >= ctx.settings.max_pending_requests:
        refuse(429, f"You already have {pending} open requests. Withdraw some or wait for answers.", "too_many_pending")

    doc = conn.execute("SELECT * FROM documents WHERE id = ? AND purged_at IS NULL", (doc_id,)).fetchone()
    if doc is not None:
        level = _current_level(conn, principal.id, doc)
        # Only someone who can already open it learns anything here - and they can see it anyway.
        if level is not None and _RANK[level] >= _RANK[body.permission]:
            refuse(409, "You already have this access to that document.", "already_has_access")

    existing = conn.execute("SELECT * FROM access_requests WHERE requester_id = ? AND document_id = ? "
                            "AND status = 'pending'", (principal.id, doc_id)).fetchone()
    now = utcnow()
    with transaction(conn) as tx:
        if existing is not None and existing["expires_at"] > iso(now):
            request_id = existing["id"]   # asking twice changes nothing; the same answer
        else:
            if existing is not None:      # a lapsed one makes room for the new one
                tx.execute("UPDATE access_requests SET status = 'withdrawn', decided_at = ? WHERE id = ?",
                           (iso(now), existing["id"]))
            request_id = new_id()
            tx.execute("""INSERT INTO access_requests (id, document_id, requester_id, permission, note, created_at,
                          expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                       (request_id, doc_id, principal.id, body.permission, note, iso(now),
                        iso(now + timedelta(days=ctx.settings.access_request_days))))
        # Recorded against the document only if it exists (so its owner sees it in
        # the document's activity); otherwise the id is kept in the details.
        ctx.audit.append(tx, principal.audit_ctx, "access.requested", "allowed",
                         document_id=doc["id"] if doc is not None else None,
                         details={"request_id": request_id, "permission": body.permission, "note": note,
                                  "requested_id": doc_id, "repeat": existing is not None})
    return {"id": request_id, "status": "pending", "message": SENT}


@router.get("/mine", summary="My requests and what happened to each (any signed-in user)")
def my_requests(principal: Principal = Depends(current_principal), conn: sqlite3.Connection = Depends(get_db)):
    rows = conn.execute(_MY_REQUESTS_SQL + "ORDER BY r.created_at DESC LIMIT 100", {"uid": principal.id}).fetchall()
    return {"items": [_mine_out(r) for r in rows], "server_time": now_iso()}


@router.post("/{request_id}/withdraw", summary="Withdraw one of my pending requests")
def withdraw(request_id: str = Path(..., max_length=64), principal: Principal = Depends(current_principal),
             conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    row = conn.execute(_MY_REQUESTS_SQL + "AND r.id = :rid", {"uid": principal.id, "rid": request_id}).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No such request")
    if _status(row) != "pending":
        raise HTTPException(status_code=409, detail=f"This request is already {_status(row)}")
    with transaction(conn) as tx:
        tx.execute("UPDATE access_requests SET status = 'withdrawn', decided_at = ? WHERE id = ?",
                   (now_iso(), row["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "access.request_withdrawn", "allowed",
                         document_id=row["document_id"] if row["document_name"] else None,
                         details={"request_id": row["id"]})
    return {"ok": True, "status": "withdrawn"}


@router.get("/ended", summary="Documents whose access I had has run out (last 90 days) - to ask again")
def ended_access(principal: Principal = Depends(current_principal), conn: sqlite3.Connection = Depends(get_db)):
    now = utcnow()
    rows = conn.execute(_ENDED_SQL + "ORDER BY g.expires_at DESC",
                        {"uid": principal.id, "now": iso(now),
                         "since": iso(now - timedelta(days=ENDED_ACCESS_DAYS))}).fetchall()
    pending = {r["document_id"] for r in conn.execute(
        "SELECT document_id FROM access_requests WHERE requester_id = ? AND status = 'pending' AND expires_at > ?",
        (principal.id, iso(now)))}
    return {"items": [{**dict(r), "request_pending": r["id"] in pending} for r in rows]}


# ------------------------------------------------------------------ deciding --
@router.get("/incoming", summary="Requests waiting for me, on documents I own (role: owner)")
def incoming(principal: Principal = Depends(require_role("owner")), conn: sqlite3.Connection = Depends(get_db),
             ctx: AppContext = Depends(app_ctx)):
    rows = conn.execute(_INCOMING_SQL + "ORDER BY r.created_at ASC", {"uid": principal.id, "now": now_iso()}).fetchall()
    items = []
    for r in rows:
        label = r["classification"]
        items.append({
            "id": r["id"], "document_id": r["document_id"], "document_name": r["document_name"],
            "classification": label, "in_trash": bool(r["deleted_at"]),
            "requester": {"username": r["username"], "display_name": r["display_name"],
                          "is_external": bool(r["is_external"]), "is_active": bool(r["is_active"])},
            "permission": r["permission"], "note": r["note"], "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            # What the approve form starts with: View only for Confidential, else what was asked.
            "default_permission": "view" if label == "confidential" else r["permission"],
            "default_minutes": labels.default_grant_minutes(ctx.settings, label),
        })
    return {"items": items, "server_time": now_iso()}


def _pending_request(conn, ctx: AppContext, principal: Principal, request_id: str, audit_action: str):
    """Load a request and authorise the caller on its document - through the
    one access check. Only that document's owner gets past it."""
    req = conn.execute("SELECT * FROM access_requests WHERE id = ?", (request_id,)).fetchone() \
        if is_valid_id(request_id) else None
    if req is None:
        raise HTTPException(status_code=404, detail="No such request")
    doc = require_access(conn, ctx, principal, req["document_id"], Action.SHARE, audit_action=audit_action).doc
    if _status(req) != "pending":  # AUTHZ-CHECK[request-must-be-pending]
        with transaction(conn) as tx:
            ctx.audit.append(tx, principal.audit_ctx, audit_action, "denied", document_id=doc["id"],
                             target_user_id=req["requester_id"],
                             details={"reason": "request_not_pending", "request_id": req["id"], "status": _status(req)})
        raise HTTPException(status_code=409, detail=f"This request is already {_status(req)}")
    return req, doc


@router.post("/{request_id}/approve", summary="Approve: give the requester access at the level and for the time "
                                               "you choose (the document's owner only)")
def approve(body: ApproveRequest, request_id: str = Path(..., max_length=64),
            principal: Principal = Depends(current_principal),
            conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    req, doc = _pending_request(conn, ctx, principal, request_id, "access.request_approved")
    requester = conn.execute("SELECT username FROM users WHERE id = ?", (req["requester_id"],)).fetchone()
    permission = body.permission or ("view" if doc["classification"] == "confidential" else req["permission"])
    grant_body = GrantRequest(username=requester["username"], permission=permission,
                              duration_minutes=body.duration_minutes, expires_at=body.expires_at)

    def mark_approved(tx, grant):
        tx.execute("""UPDATE access_requests SET status = 'approved', decided_at = ?, decided_by = ?,
                      granted_permission = ?, grant_expires_at = ? WHERE id = ? AND status = 'pending'""",
                   (now_iso(), principal.id, grant["permission"], grant["expires_at"], req["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "access.request_approved", "allowed", document_id=doc["id"],
                         target_user_id=req["requester_id"],
                         details={"request_id": req["id"], "requested_permission": req["permission"],
                                  "permission": grant["permission"], "expires_at": grant["expires_at"],
                                  "target_username": requester["username"]})

    # Same checks and events as giving access by hand: active, not an admin, not the owner, valid duration.
    grant = give_access(conn, ctx, principal, doc, grant_body, refuse_action="access.request_approved",
                        in_tx=mark_approved)
    return {"ok": True, "status": "approved", "grant": grant}


@router.post("/{request_id}/deny", summary="Deny, with an optional reason the requester will see (the document's "
                                            "owner only)")
def deny(body: DenyRequest, request_id: str = Path(..., max_length=64), principal: Principal = Depends(current_principal),
         conn: sqlite3.Connection = Depends(get_db), ctx: AppContext = Depends(app_ctx)):
    req, doc = _pending_request(conn, ctx, principal, request_id, "access.request_denied")
    reason = clean_line(body.reason, 300) if body.reason.strip() else None
    with transaction(conn) as tx:
        tx.execute("""UPDATE access_requests SET status = 'denied', decided_at = ?, decided_by = ?, decision_note = ?
                      WHERE id = ?""", (now_iso(), principal.id, reason, req["id"]))
        ctx.audit.append(tx, principal.audit_ctx, "access.request_denied", "allowed", document_id=doc["id"],
                         target_user_id=req["requester_id"],
                         details={"request_id": req["id"], "requested_permission": req["permission"],
                                  "owner_note": reason})
    return {"ok": True, "status": "denied"}
