"""Audit events in plain language, for the admin audit page and the CSV export.

``describe(event)`` turns one row into a sentence, e.g.

    auth.login  allowed  {"mode": "cookie"}
      -> "Signed in (browser session)"
    document.download  denied  {"reason": "view_only", ...}
      -> "Refused to download “Salary letter”: their access is View only"

The raw row (and its JSON details) is always kept next to the sentence, so
nothing is lost in translation. Internal denial reasons appear here, which is
fine: this text is only ever shown to administrators (owners see a filtered
activity list without reasons, see routes/documents.py).
"""
from __future__ import annotations

import re
from typing import Any

from .utils import parse_iso

# Shown as option groups in the action dropdown.
GROUPS = {
    "auth": "Sign-in and sessions",
    "document": "Documents",
    "access": "Access",
    "link": "Share links",
    "ai": "Suggestions",
    "user": "Users",
    "audit": "Audit trail",
    "legacy": "Imported",
}

ACTION_LABELS = {
    "auth.login": "Sign in",
    "auth.logout": "Sign out",
    "auth.session_expired": "Signed out automatically",
    "auth.session_extended": "Stay signed in",
    "auth.password_change": "Change own password",
    "auth.forbidden": "Role not allowed",
    "auth.2fa_required": "Password accepted, code next",
    "auth.2fa_failed": "Two-step code refused",
    "auth.2fa_setup": "Two-step set-up started",
    "auth.2fa_enrolled": "Two-step sign-in set up",
    "auth.2fa_disabled": "Two-step sign-in turned off",
    "auth.2fa_backup_codes_renewed": "New backup codes",
    "auth.account_locked": "Account locked",
    "auth.session_revoked": "Sign out a session",
    "auth.signed_out_everywhere": "Sign out everywhere",
    "document.view": "Open document",
    "document.preview": "View in browser",
    "document.preview_page": "View a page",
    "document.download": "Download",
    "document.version_download": "Download older version",
    "document.upload": "Upload",
    "document.version_upload": "Upload new version",
    "document.update": "Change details",
    "document.delete": "Move to trash",
    "document.restore": "Restore from trash",
    "document.purge": "Destroy",
    "document.activity": "Document activity",
    "document.classified": "Change classification",
    "access.granted": "Give access",
    "access.changed": "Change access",
    "access.extended": "Extend access",
    "access.revoked": "Remove access",
    "access.expired": "Access expired",
    "access.list": "List who has access",
    "access.bulk_revoked": "Remove unused access (bulk)",
    "access.requested": "Request access",
    "access.request_approved": "Approve access request",
    "access.request_denied": "Deny access request",
    "access.request_withdrawn": "Withdraw access request",
    "link.created": "Create share link",
    "link.opened": "Open share link",
    "link.revoked_all": "Stop all share links",
    "link.list": "List share links",
    "ai.suggestion.generated": "Suggest people",
    "ai.suggestion.accepted": "Accept suggestion",
    "ai.suggestion.dismissed": "Dismiss suggestion",
    "user.create": "Create user",
    "user.update": "Change user",
    "user.delete": "Delete user",
    "user.password_reset": "Reset password",
    "user.unlock": "Unlock account",
    "user.sessions_revoked": "Sign out everywhere",
    "user.2fa_reset": "Reset two-step sign-in",
    "audit.verify": "Verify integrity",
    "audit.export": "Export audit trail",
    "audit.migrated": "Database upgrade",
    "legacy.unknown": "Imported event",
}

LEVELS = {"view": "View only", "download": "View + download", "edit": "Edit", "owner": "Owner"}

REASON_TEXT = {
    # the single access check - authz.DENIAL_REASONS
    "not_found": "the document does not exist (or was destroyed)",
    "user_inactive": "their account is deactivated",
    "admin_never_reads_content": "administrators can never open document content",
    "in_trash": "the document is in the trash",
    "link_invalid": "the share link was altered or made up (signature does not match)",
    "link_wrong_document": "the share link is for a different document",
    "wrong_user": "the share link was made for someone else",
    "no_grant": "it was never shared with them",
    "grant_revoked": "their access had been removed",
    "grant_expired": "their access had expired",
    "view_only": "their access is View only",
    "link_expired": "the share link had expired",
    "link_revoked": "the share link had been cancelled",
    "link_owner_changed": "the person who made the link no longer owns the document",
    "version_not_in_document": "that version belongs to a different document",
    # sign-in and account
    "unknown_user": "there is no such user",
    "bad_password": "wrong password",
    "account_locked": "the account is locked after repeated failures",
    "inactive_user": "the account is deactivated",
    "bad_current_password": "the current password was wrong",
    "rate_limited": "too many attempts in a short time",
    "role_required": "their role does not allow it",
    "session_not_found": "it is not one of their sessions",
    # two-step sign-in
    "bad_code": "the code was wrong",
    "code_reused": "that code had already been used",
    "bad_backup_code": "the backup code was wrong or already used",
    "not_enrolled": "two-step sign-in is not set up",
    "secret_unreadable": "the stored two-step key does not belong to this account (tampering?)",
    "challenge_invalid": "the sign-in had expired or was never started",
    "required_for_role": "two-step sign-in is required for their role",
    "own_account": "administrators change their own two-step sign-in on the Account page",
    "too_many_failures": "too many failed attempts",
    # access requests
    "invalid_id": "that is not a valid document link or id",
    "too_many_pending": "they already had too many open requests",
    "already_has_access": "they already have that access",
    "request_not_pending": "the request had already been answered, withdrawn or had lapsed",
    # sharing
    "invalid_duration": "the time limit was not valid",
    "target_inactive": "that person's account is deactivated",
    "target_admin": "administrators cannot be given document access",
    "target_is_owner": "that person already owns it",
    "suggestion_mismatch": "it did not match the suggestion",
    "link_above_grant": "a link cannot give more than the person's own access",
    "grant_not_in_document": "that access entry belongs to a different document",
    # files and housekeeping
    "validation": "the file was not accepted",
    "integrity": "the stored file failed its integrity check",
    "retention": "its time in the trash ran out",
    "too_many_rows": "too many events matched",
    # sessions (informational)
    "idle": "no activity for too long",
    "max_lifetime": "the sign-in reached its maximum length",
}

_CANNOT = re.compile(r"(view|download|edit)_cannot_([a-z]+)")
_CANNOT_WORDS = {"view": "open it", "download": "download it", "edit": "change it", "delete": "delete it",
                 "restore": "restore it", "purge": "destroy it", "share": "share it", "audit": "see its activity",
                 "classify": "change its classification"}

# What was attempted, for "Refused to ...". {doc} is the quoted document name.
_ATTEMPTS = {
    "document.view": "open {doc}",
    "document.preview": "view {doc} in the browser",
    "document.preview_page": "view a page of {doc}",
    "document.download": "download {doc}",
    "document.version_download": "download an older version of {doc}",
    "document.upload": "upload a file",
    "document.version_upload": "upload a new version of {doc}",
    "document.update": "change the details of {doc}",
    "document.delete": "move {doc} to the trash",
    "document.restore": "restore {doc}",
    "document.purge": "destroy {doc}",
    "document.activity": "see the activity of {doc}",
    "access.granted": "give access to {doc}",
    "access.changed": "change access to {doc}",
    "access.extended": "extend access to {doc}",
    "access.revoked": "remove access to {doc}",
    "access.list": "see who has access to {doc}",
    "link.created": "create a share link to {doc}",
    "link.opened": "open a share link to {doc}",
    "link.revoked_all": "stop the share links of {doc}",
    "link.list": "see the share links of {doc}",
    "ai.suggestion.generated": "get sharing suggestions for {doc}",
    "audit.export": "export the audit trail",
    "auth.2fa_setup": "start setting up two-step sign-in",
    "auth.2fa_disabled": "turn two-step sign-in off",
    "auth.session_revoked": "sign out a session",
    "user.2fa_reset": "reset the two-step sign-in of {target}",
    "access.requested": "ask for access to {doc}",
    "access.request_approved": "approve a request for {doc}",
    "access.request_denied": "deny a request for {doc}",
    "document.classified": "change the classification of {doc}",
}


def action_label(action: str) -> str:
    return ACTION_LABELS.get(action) or action


def action_group(action: str) -> str:
    return action.split(".", 1)[0]


def reason_text(code: str | None) -> str | None:
    """Plain words for an internal reason code; None if the code is unknown."""
    if not code:
        return None
    if code in REASON_TEXT:
        return REASON_TEXT[code]
    m = _CANNOT.fullmatch(code)
    if m:
        return f"their access ({LEVELS[m.group(1)]}) does not let them {_CANNOT_WORDS.get(m.group(2), m.group(2))}"
    return None


def _level(p: str | None) -> str:
    return LEVELS.get(p or "", p or "unknown")


def _plural(n: Any, word: str) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return f"{n} {word}s"
    return f"{n} {word}" + ("" if n == 1 else "s")


def _duration(seconds: float) -> str:
    minutes = round(seconds / 60)
    if minutes < 1:
        return "less than a minute"
    if minutes < 120:
        return _plural(minutes, "minute")
    hours = round(minutes / 60)
    if hours < 48:
        return _plural(hours, "hour")
    return _plural(round(hours / 24), "day")


def _span(start: str | None, end: str | None) -> str | None:
    try:
        return _duration((parse_iso(end) - parse_iso(start)).total_seconds())
    except (TypeError, ValueError, AttributeError):
        return None


def _size(n: Any) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "?"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1048576:.1f} MB"


def _changes(changes: dict) -> str:
    words = {"is_active": "active", "is_external": "external", "display_name": "name"}
    parts = []
    for k, v in (changes or {}).items():
        if isinstance(v, dict) and "from" in v:
            a, b = v.get("from"), v.get("to")
            if k in ("is_active", "is_external"):
                a, b = ("yes" if a else "no"), ("yes" if b else "no")
            parts.append(f"{words.get(k, k)} {a} → {b}")
        else:
            parts.append(words.get(k, k))
    return ", ".join(parts)


def describe(e: dict) -> str:
    """One sentence for an audit row (``details`` already parsed to a dict)."""
    action, outcome = e.get("action") or "", e.get("outcome") or ""
    d = e.get("details") if isinstance(e.get("details"), dict) else {}
    name = e.get("document_name") or d.get("name")
    doc = f"“{name}”" if name else "a document"
    target = e.get("target_username") or d.get("target_username") or d.get("username") or d.get("recipient") \
        or "someone"
    why = reason_text(d.get("reason")) or (d.get("reason") or "").replace("_", " ") or None

    if outcome in ("denied", "error"):
        if action == "auth.login":
            return f"Sign-in refused: {why or 'unknown reason'}"
        if action == "auth.password_change":
            return f"Password change refused: {why or 'unknown reason'}"
        if action == "auth.forbidden":
            return (f"Refused to use an {('administrator' if 'admin' in (d.get('required') or []) else 'owner')}-only "
                    f"function ({d.get('method', '')} {d.get('path', '')}): their role ({d.get('role', '?')}) "
                    "does not allow it")
        if action == "auth.2fa_failed":
            stage = {"verify": "", "enroll": " during first-time set-up", "enable": " while setting up",
                     "backup_codes": " while renewing backup codes"}.get(d.get("stage"), "")
            return f"Two-step code refused{stage}: {why or 'unknown reason'}"
        attempt = _ATTEMPTS.get(action, action_label(action).lower()).format(doc=doc, target=target)
        if action in ("access.granted", "link.created") and d.get("username"):
            attempt += f" for {d['username']}"
        verb = "Failed to" if outcome == "error" else "Refused to"
        extra = f" ({d['error']})" if d.get("error") and d.get("reason") == "validation" else ""
        return f"{verb} {attempt}: {why or 'no reason recorded'}{extra}"

    if action == "auth.login":
        base = {"cookie": "Signed in (browser session)", "bearer": "Signed in (API token)"}.get(d.get("mode"), "Signed in")
        factor = d.get("second_factor")
        if factor == "totp":
            return base + (" after setting up two-step sign-in" if d.get("enrolled") else " with an authenticator code")
        if factor == "backup_code":
            return base + f" with a backup code ({_plural(d.get('backup_codes_left', 0), 'code')} left)"
        return base
    if action == "auth.2fa_required":
        if d.get("stage") == "enroll":
            return "Password accepted; asked to set up two-step sign-in (required for their role)"
        return "Password accepted; asked for the authenticator code"
    if action == "auth.2fa_setup":
        return "Started setting up two-step sign-in" + (" on a new authenticator" if d.get("replacing") else "")
    if action == "auth.2fa_enrolled":
        where = "while signing in" if d.get("via") == "sign_in" else "from the Account page"
        moved = " (moved to a new authenticator)" if d.get("replaced") else ""
        ended = d.get("other_sessions_revoked") or 0
        return (f"Set up two-step sign-in {where}{moved}; {_plural(d.get('backup_codes', 0), 'backup code')} issued"
                + (f"; {_plural(ended, 'other sign-in')} ended" if ended else ""))
    if action == "auth.2fa_disabled":
        return "Turned two-step sign-in off"
    if action == "auth.2fa_backup_codes_renewed":
        return f"Replaced their backup codes ({_plural(d.get('backup_codes', 0), 'new code')})"
    if action == "auth.account_locked":
        via = {"second_factor": "wrong two-step codes"}.get(d.get("via"), "wrong passwords")
        return (f"Account {target if target != 'someone' else ''} locked for "
                f"{_plural(d.get('lockout_minutes', 0), 'minute')} after {d.get('failures', '?')} {via}").replace("  ", " ")
    if action == "auth.session_revoked":
        here = " - the one in use" if d.get("this_session") else ""
        return f"Signed out a session ({d.get('device', 'unknown device')}, {d.get('ip') or 'no IP'}){here}"
    if action == "auth.signed_out_everywhere":
        return f"Signed out everywhere ({_plural(d.get('sessions', 0), 'session')} ended)"
    if action == "auth.logout":
        return "Signed out"
    if action == "auth.session_expired":
        base = ("Signed out automatically: the sign-in reached its maximum length" if d.get("reason") == "max_lifetime"
                else "Signed out automatically after a period without activity")
        noticed = {"browser": " (noticed by the browser)", "start-up": " (noticed when the server started)"}
        return base + noticed.get(d.get("detected"), "")
    if action == "auth.session_extended":
        return "Chose “Stay signed in”"
    if action == "auth.password_change":
        n = d.get("other_sessions_revoked") or 0
        return "Changed their password" + (f"; {_plural(n, 'other sign-in')} ended" if n else "")
    if action == "document.view":
        via = " through a share link" if d.get("via") == "link" else ""
        return f"Opened {doc} ({_level(d.get('permission'))}){via}"
    if action == "document.preview":
        pages = f", {_plural(d['pages'], 'page')}" if d.get("pages") else ""
        return f"Viewed {doc} in the browser (watermarked{pages})"
    if action == "document.preview_page":
        return f"Viewed page {d.get('page', '?')} of {doc}"
    if action == "document.download":
        return f"Downloaded {doc}" + (f" ({_size(d['size'])})" if d.get("size") else "")
    if action == "document.version_download":
        return f"Downloaded version {d.get('version_no', '?')} of {doc}"
    if action == "document.upload":
        demo = " (demo data)" if d.get("seeded") else ""
        label = f", {d['classification']}" if d.get("classification") else ""
        return f"Uploaded {doc} ({_size(d.get('size'))}, {d.get('category', 'no category')}{label}){demo}"
    if action == "document.version_upload":
        return f"Uploaded version {d.get('version_no', '?')} of {doc} ({_size(d.get('size'))})"
    if action == "access.requested":
        what = doc if e.get("document_id") else \
            f"a document id that does not exist (or is not theirs to know about): {str(d.get('requested_id', ''))[:10]}…"
        note = f' - "{d["note"]}"' if d.get("note") else ""
        again = " (again; still pending)" if d.get("repeat") else ""
        return f"Asked for {_level(d.get('permission'))} access to {what}{note}{again}"
    if action == "access.request_approved":
        span = _span(e.get("ts"), d.get("expires_at"))
        return (f"Approved {target}'s request: {_level(d.get('permission'))} access to {doc}"
                + (f" for {span}" if span else "")
                + (f" (asked for {_level(d.get('requested_permission'))})"
                   if d.get("requested_permission") and d.get("requested_permission") != d.get("permission") else ""))
    if action == "access.request_denied":
        return f"Denied {target}'s request for {doc}" + (f' - "{d["owner_note"]}"' if d.get("owner_note") else "")
    if action == "access.request_withdrawn":
        return f"Withdrew their request for {doc if e.get('document_id') else 'a document'}"
    if action == "document.classified":
        names = {"public": "Public", "internal": "Internal", "confidential": "Confidential"}
        return (f"Changed the classification of {doc}: {names.get(d.get('from'), d.get('from'))} → "
                f"{names.get(d.get('to'), d.get('to'))}"
                + ("; its outstanding share links were cancelled" if d.get("links_invalidated") else ""))
    if action == "document.update":
        return f"Changed the details of {doc}" + (f": {_changes(d.get('changes'))}" if d.get("changes") else "")
    if action == "document.delete":
        days = d.get("retention_days")
        return f"Moved {doc} to the trash" + (f" (destroyed after {_plural(days, 'day')})" if days else "")
    if action == "document.restore":
        return f"Restored {doc} from the trash"
    if action == "document.purge":
        if d.get("reason") == "retention":
            return f"Destroyed {doc} automatically: its time in the trash ran out"
        return f"Destroyed {doc} permanently ({_plural(d.get('versions_shredded', 0), 'version')} shredded)"
    if action == "document.activity":
        return f"Looked at the activity of {doc}"
    if action in ("access.granted", "access.changed"):
        span = _span(e.get("ts"), d.get("expires_at"))
        span = f" for {span}" if span else ""
        if action == "access.changed":
            prev = (d.get("previous") or {}).get("permission")
            return f"Changed {target}'s access to {doc}: {_level(prev)} → {_level(d.get('permission'))}{span}"
        via = " (from a suggestion)" if d.get("source") == "suggestion" else ""
        return f"Gave {target} {_level(d.get('permission'))} access to {doc}{span}{via}"
    if action == "access.extended":
        added = _duration(int(d.get("added_minutes") or 0) * 60)
        return f"Extended {target}'s access to {doc} by {added}" + (" (it had expired)" if d.get("was_expired") else "")
    if action == "access.revoked":
        if d.get("bulk"):
            return (f"Removed {target}'s access to {doc} (administrator, unused review: "
                    f"no use in {_plural(d.get('unused_days', 0), 'day')})")
        return f"Removed {target}'s access to {doc}" + (" (administrator)" if d.get("by_admin") else "")
    if action == "access.bulk_revoked":
        return (f"Removed {_plural(d.get('grants', 0), 'unused grant')} on {_plural(len(d.get('documents') or []), 'document')}"
                f" (no use in {_plural(d.get('unused_days', 0), 'day')}); their share links stopped too")
    if action == "access.expired":
        return f"{target}'s {_level(d.get('permission'))} access to {doc} expired"
    if action == "access.list":
        return f"Looked at who has access to {doc}"
    if action == "link.created":
        ttl = _duration(int(d.get("ttl_seconds") or 0))
        return f"Made a {ttl} share link to {doc} for {d.get('recipient', target)} ({_level(d.get('permission'))})"
    if action == "link.opened":
        return f"Opened {doc} through a share link ({_level(d.get('effective_permission') or d.get('permission'))})"
    if action == "link.revoked_all":
        return f"Stopped every share link to {doc}" + (" (administrator)" if d.get("by_admin") else "")
    if action == "link.list":
        return f"Looked at the share links of {doc}"
    if action == "ai.suggestion.generated":
        n = d.get("suggestions")
        n = len(n) if isinstance(n, list) else (n or 0)
        return f"Asked who else might need {doc} ({_plural(n, 'suggestion')})"
    if action == "ai.suggestion.accepted":
        return f"Accepted a suggestion: {target} gets {_level(d.get('decided_permission'))} access to {doc}"
    if action == "ai.suggestion.dismissed":
        return f"Dismissed a sharing suggestion for {doc}"
    if action == "user.create":
        ext = ", external" if d.get("is_external") else ""
        demo = " (demo data)" if d.get("seeded") else ""
        return f"Created user {d.get('username', target)} ({d.get('role', '?')}{ext}){demo}"
    if action == "user.update":
        ended = d.get("sessions_revoked") or 0
        return (f"Changed user {d.get('username', target)}: {_changes(d.get('changes')) or 'no changes'}"
                + (f"; {_plural(ended, 'sign-in')} ended" if ended else ""))
    if action == "user.delete":
        return (f"Deleted user {d.get('username', target)} "
                f"({_plural(d.get('grants_removed', 0), 'grant')} removed, "
                f"{_plural(d.get('sessions_revoked', 0), 'sign-in')} ended)")
    if action == "user.password_reset":
        return (f"Reset the password of {d.get('username', target)}; "
                f"{_plural(d.get('sessions_revoked', 0), 'sign-in')} ended")
    if action == "user.unlock":
        return f"Unlocked {d.get('username', target)}"
    if action == "user.2fa_reset":
        return (f"Reset the two-step sign-in of {d.get('username', target)}; "
                f"{_plural(d.get('sessions_revoked', 0), 'sign-in')} ended")
    if action == "user.sessions_revoked":
        return (f"Signed {d.get('username', target)} out everywhere "
                f"({_plural(d.get('sessions_revoked', 0), 'sign-in')} ended)")
    if action == "audit.verify":
        if d.get("ok"):
            return f"Verified the audit trail: chain intact ({_plural(d.get('entries_checked', 0), 'event')})"
        return f"Verified the audit trail: BROKEN at event #{d.get('first_bad_seq')}"
    if action == "audit.export":
        sha = (d.get("sha256") or "")[:12]
        return f"Exported {_plural(d.get('rows', 0), 'audit event')} to CSV (SHA-256 {sha}…)"
    if action == "audit.migrated":
        back = d.get("backfilled_rows") or 0
        return (f"Upgraded the database from schema v{d.get('from_version')} to v{d.get('to_version')}"
                + (f"; hashes backfilled for {_plural(back, 'earlier event')}" if back else ""))
    return action_label(action)
