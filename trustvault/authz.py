"""The permission model - the single place where document access is decided.

``check_access()`` is the ONE function that decides whether a person may do
something to a document. Every endpoint that touches a document - and in
particular every endpoint that returns file content (metadata, preview, page
images, downloads, version downloads) - calls ``require_access()``, which runs
``check_access()``, writes a ``denied`` audit row with the internal reason
when the answer is no, and then raises the one uniform error:

    403  "You don't have access to this file."

Nothing is cached: every call reads the user, the document, the grant and the
link state from the database, so revoking, expiring or deactivating takes
effect on the very next request.

Permission levels (per document, per named person)
---------------------------------------------------
* ``view``     - open it in the browser. The server sends a watermarked
  rendering (page images / extracted text), never the file.
* ``download`` - view + download the original file (any version).
* ``edit``     - download + upload a new version + change name/category/description.
* ``owner``    - the uploader. Everything, plus delete / restore / purge,
  manage grants and links, see the document's audit trail, ask for suggestions.

A person reaches a document in one of three ways: they own it, they hold a
grant that has not expired (every grant expires), or they present a share link
that was made for them (5 minutes, signed, see ``links.py``).

Global roles
------------
* ``admin``  - manages users and reads the audit log. **Never** gets document
  content, through a grant or a link (separation of duties).
* ``owner``  - may upload documents (and so become their owner).
* ``viewer`` - may only use documents that were explicitly shared with them.

Lines tagged ``AUTHZ-CHECK`` / ``AUTHZ-SQL`` are mutated one at a time by
``tools/mutation_check.py``; the test suite must fail for every mutant.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from .context import AppContext
from .db import transaction
from .errors import no_access
from .expiry import log_expired_grants
from .links import BadLink, LinkClaims, verify_signature
from .utils import is_valid_id, iso, utcnow


class Action(str, Enum):
    VIEW = "view"            # metadata, version list, watermarked in-browser rendering
    DOWNLOAD = "download"    # the original file
    EDIT = "edit"
    DELETE = "delete"
    RESTORE = "restore"
    PURGE = "purge"
    SHARE = "share"
    AUDIT = "audit"
    CLASSIFY = "classify"    # change the Public / Internal / Confidential label (owner only)


PERMISSION_LEVELS = ("view", "download", "edit")  # lowest to highest
_RANK = {None: 0, "view": 1, "download": 2, "edit": 3, "owner": 4}

PERMISSION_ACTIONS: dict[str, frozenset[Action]] = {
    "view": frozenset({Action.VIEW}),
    "download": frozenset({Action.VIEW, Action.DOWNLOAD}),
    "edit": frozenset({Action.VIEW, Action.DOWNLOAD, Action.EDIT}),
    "owner": frozenset(Action),
}

# What the owner may still do while a document is in the trash.
TRASH_ACTIONS = frozenset({Action.VIEW, Action.RESTORE, Action.PURGE})

# The internal reasons for a refusal, in the order check_access() tests them.
# The caller only ever sees "You don't have access to this file."; the reason
# goes to the audit trail, where only administrators can read it.
DENIAL_REASONS = (
    "not_found",                  # no such document, never existed, or destroyed
    "user_inactive",              # deactivated or deleted account (defence in depth)
    "admin_never_reads_content",  # separation of duties
    "in_trash",                   # only the owner may look at / restore / destroy it
    # -- the request came through a share link: whose link is it?
    "link_invalid",               # malformed, or the signature does not match (tampered)
    "link_wrong_document",        # a link for another document
    "wrong_user",                 # made for somebody else (forwarded)
    # -- the person's own access
    "no_grant",                   # never shared with this person
    "grant_revoked",              # the owner (or an admin) took the access away
    "grant_expired",
    "view_only",                  # a View-only person asking for more (e.g. a download);
                                  # other levels: "<level>_cannot_<action>", e.g. download_cannot_edit
    # -- the share link itself
    "link_expired",               # older than LINK_TTL_SECONDS
    "link_revoked",               # access_version changed since it was made
    "link_owner_changed",         # its maker is no longer the active owner
    "version_not_in_document",    # a version id that belongs to another document
)

_GRANT_LOOKUP_SQL = (
    "SELECT id, permission, expires_at FROM grants WHERE 1 = 1 "
    "AND document_id = :doc_id "  # AUTHZ-SQL[grant-matches-document]
    "AND user_id = :user_id "  # AUTHZ-SQL[grant-matches-user]
)

# Search/listing scope: a document is visible when I own it or hold a live grant.
ACCESS_SCOPE_SQL = (
    "(d.owner_id = :uid OR EXISTS (SELECT 1 FROM grants g WHERE g.document_id = d.id AND g.user_id = :uid "
    "AND g.expires_at > :now "  # AUTHZ-SQL[search-grant-expiry]
    "))"
)


def level_reason(perm: str | None, action: Action) -> str:
    return "view_only" if perm == "view" else f"{perm}_cannot_{action.value}"


@dataclass
class Decision:
    allowed: bool
    reason: str                      # "ok" when allowed, else one of DENIAL_REASONS
    action: Action
    doc: dict | None = None
    permission: str | None = None    # owner / edit / download / view
    via: str | None = None           # owner / grant / link
    grant: dict | None = None
    link: LinkClaims | None = None
    version: dict | None = None

    @property
    def access_expires_at(self) -> str | None:
        """When the access used for this request ends (None for the owner).
        Through a link: whichever ends first, the link or the grant."""
        ends = []
        if self.grant:
            ends.append(self.grant["expires_at"])
        if self.via == "link" and self.link:
            ends.append(iso(datetime.fromtimestamp(self.link.expires_at, tz=timezone.utc)))
        return min(ends) if ends else None


def _was_revoked(conn: sqlite3.Connection, doc_id: str, user_id: str) -> bool:
    """For the audit reason only: was this person's last grant taken away?"""
    row = conn.execute(
        """SELECT action FROM audit_log WHERE document_id = ? AND target_user_id = ?
           AND outcome = 'allowed' AND action IN ('access.granted', 'access.changed', 'access.revoked')
           ORDER BY seq DESC LIMIT 1""",
        (doc_id, user_id)).fetchone()
    return row is not None and row["action"] == "access.revoked"


def _parse_link(keyring, token: str) -> LinkClaims | None:
    try:
        return verify_signature(keyring, token)
    except BadLink:
        return None


def check_access(conn: sqlite3.Connection, keyring, user: dict, doc_id: str, action: Action, *,
                 version_id: str | None = None, link_token: str | None = None,
                 now: datetime | None = None) -> Decision:
    """Decide - without side effects - whether ``user`` may do ``action`` on ``doc_id``.

    Order (see DENIAL_REASONS): the document exists and is not in the trash ->
    [link: signed, for this document, for this person] -> the person owns it or
    holds a grant -> the grant has not expired -> the level allows the action ->
    [link: not expired, not revoked, maker still the owner, its level allows it]
    -> the requested version belongs to the document.

    ``link_token``  a share link sent with the request (X-Link-Token header). A
                    request that comes through a link needs a valid link AND a
                    live grant: a link never gives access on its own.
    ``version_id``  the request targets this version, which must belong to the document.
    """
    now = now or utcnow()
    now_s = iso(now)

    def deny(reason: str, **kw) -> Decision:
        return Decision(False, reason, action, **kw)

    doc = None
    if is_valid_id(doc_id):
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    if doc is None:  # AUTHZ-CHECK[document-must-exist]
        return deny("not_found")
    doc = dict(doc)
    if doc["purged_at"] is not None:  # AUTHZ-CHECK[destroyed-document-unreachable]
        return deny("not_found", doc=doc)
    if not user["is_active"]:  # AUTHZ-CHECK[inactive-user-has-no-access]
        return deny("user_inactive", doc=doc)
    if user["role"] == "admin":  # AUTHZ-CHECK[admin-has-no-content-access]
        return deny("admin_never_reads_content", doc=doc)
    is_owner = doc["owner_id"] == user["id"]
    if doc["deleted_at"] is not None and (not is_owner or action not in TRASH_ACTIONS):  # AUTHZ-CHECK[trashed-document-locked]
        return deny("in_trash", doc=doc)

    # A request through a share link: first, whose link is it?
    claims = None
    if link_token is not None:
        claims = _parse_link(keyring, link_token)
        if claims is None:
            return deny("link_invalid", doc=doc)
        if claims.document_id != doc["id"]:  # AUTHZ-CHECK[link-matches-document]
            return deny("link_wrong_document", doc=doc, link=claims)
        if claims.recipient_id != user["id"]:  # AUTHZ-CHECK[link-bound-to-recipient]
            return deny("wrong_user", doc=doc, link=claims)

    # The person's own access: ownership, or a grant that has not expired.
    grant = None
    if is_owner:
        perm, via = "owner", "owner"
    else:
        row = conn.execute(_GRANT_LOOKUP_SQL, {"doc_id": doc["id"], "user_id": user["id"]}).fetchone()
        grant = dict(row) if row is not None else None
        perm, via = (grant["permission"], "grant") if grant else (None, None)
    if perm is None:  # AUTHZ-CHECK[no-permission-no-access]
        return deny("grant_revoked" if _was_revoked(conn, doc["id"], user["id"]) else "no_grant", doc=doc, link=claims)
    if grant is not None and grant["expires_at"] <= now_s:  # AUTHZ-CHECK[expired-grant-ignored]
        return deny("grant_expired", doc=doc, grant=grant, link=claims)
    common = dict(doc=doc, permission=perm, via=via, grant=grant, link=claims)
    if action not in PERMISSION_ACTIONS.get(perm, frozenset()):  # AUTHZ-CHECK[permission-allows-action]
        return deny(level_reason(perm, action), **common)

    # The link itself: 5 minutes, not revoked, its maker still the owner, its level.
    if claims is not None:
        if claims.expires_at <= now.timestamp():  # AUTHZ-CHECK[link-not-expired]
            return deny("link_expired", **common)
        if claims.access_version != doc["access_version"]:  # AUTHZ-CHECK[link-not-revoked]
            return deny("link_revoked", **common)
        maker = conn.execute("SELECT id, is_active FROM users WHERE id = ?", (claims.creator_id,)).fetchone()
        lost = maker is None or not maker["is_active"] or doc["owner_id"] != claims.creator_id
        if lost:  # AUTHZ-CHECK[link-creator-still-owner]
            return deny("link_owner_changed", **common)
        if action not in PERMISSION_ACTIONS[claims.permission]:  # AUTHZ-CHECK[link-level-caps-action]
            return deny(level_reason(claims.permission, action), **common)
        common["via"] = "link"
        common["permission"] = claims.permission if _RANK[claims.permission] < _RANK[perm] else perm

    version = None
    if version_id is not None:
        row = conn.execute("SELECT * FROM document_versions WHERE id = ?", (version_id,)).fetchone() \
            if is_valid_id(version_id) else None
        # A version id from another document must not ride on this document's access.
        if row is None or row["document_id"] != doc["id"]:  # AUTHZ-CHECK[version-belongs-to-document]
            return deny("version_not_in_document", **common)
        version = dict(row)
    return Decision(True, "ok", action, version=version, **common)


def record_denial(conn: sqlite3.Connection, ctx: AppContext, audit_ctx, decision: Decision, requested_id: str,
                  audit_action: str, *, version_id: str | None = None) -> None:
    """Write the refusal, with its internal reason, to the audit trail."""
    details = {"reason": decision.reason, "requested_id": (requested_id or "")[:64]}
    if version_id is not None:
        details["requested_version"] = version_id[:64]
    if decision.link is not None:
        details["link_id"] = decision.link.link_id
    if decision.permission:
        details["permission"] = decision.permission
    doc_id = decision.doc["id"] if decision.doc else None
    if decision.reason == "grant_expired" and decision.grant:
        log_expired_grants(conn, ctx.audit, grant_id=decision.grant["id"])
    with transaction(conn) as tx:
        ctx.audit.append(tx, audit_ctx, audit_action, "denied", document_id=doc_id, details=details)


def require_access(conn: sqlite3.Connection, ctx: AppContext, principal, doc_id: str, action: Action, *,
                   version_id: str | None = None, link_token: str | None = None,
                   audit_action: str | None = None) -> Decision:
    """check_access() + audit the refusal + the uniform 403. Returns the Decision when allowed."""
    decision = check_access(conn, ctx.keyring, principal.user, doc_id, action, version_id=version_id,
                            link_token=link_token)
    if not decision.allowed:
        record_denial(conn, ctx, principal.audit_ctx, decision, doc_id, audit_action or f"document.{action.value}",
                      version_id=version_id)
        raise no_access()
    return decision


def visible_documents_clause(user: dict) -> str | None:
    """SQL clause restricting a document query to what ``user`` may see, or
    None when the user may see nothing at all."""
    if user["role"] == "admin":  # AUTHZ-CHECK[admin-search-sees-nothing]
        return None
    return ACCESS_SCOPE_SQL
