"""Writing 'access.expired' to the audit trail.

A grant stops working the moment its expiry passes - ``authz.check_access``
compares the time on every request, so nothing has to run for access to end.
This module only makes the *record* complete: each expired grant gets exactly
one ``access.expired`` audit event. It runs

* when someone is refused because their grant expired (that grant, at once),
* when an owner or admin looks at a grant list, and
* at most every ``SWEEP_INTERVAL_SECONDS`` on any signed-in request, and at start-up.

``expiry_logged_at`` is set with a conditional UPDATE in the same transaction
as the audit row, so two requests can never log the same expiry twice.
"""
from __future__ import annotations

import sqlite3

from .audit import AuditContext, AuditLog
from .db import transaction
from .utils import now_iso

SWEEP_INTERVAL_SECONDS = 30
SYSTEM = AuditContext(actor_id=None, actor_name="system:expiry", ip=None, user_agent=None)


def log_expired_grants(conn: sqlite3.Connection, audit: AuditLog, *, grant_id: str | None = None,
                       document_id: str | None = None, limit: int = 500) -> int:
    now = now_iso()
    sql = ("SELECT g.id, g.document_id, g.user_id, g.permission, g.expires_at, u.username "
           "FROM grants g JOIN users u ON u.id = g.user_id "
           "WHERE g.expiry_logged_at IS NULL AND g.expires_at <= :now")
    params: dict = {"now": now, "limit": limit}
    if grant_id is not None:
        sql += " AND g.id = :gid"
        params["gid"] = grant_id
    if document_id is not None:
        sql += " AND g.document_id = :doc"
        params["doc"] = document_id
    rows = conn.execute(sql + " ORDER BY g.expires_at LIMIT :limit", params).fetchall()
    if not rows:
        return 0
    logged = 0
    with transaction(conn) as tx:
        for g in rows:
            claimed = tx.execute("UPDATE grants SET expiry_logged_at = ? WHERE id = ? AND expiry_logged_at IS NULL",
                                 (now, g["id"])).rowcount
            if claimed != 1:
                continue
            audit.append(tx, SYSTEM, "access.expired", "info", document_id=g["document_id"],
                         target_user_id=g["user_id"],
                         details={"grant_id": g["id"], "permission": g["permission"], "expired_at": g["expires_at"],
                                  "target_username": g["username"]})
            logged += 1
    return logged
