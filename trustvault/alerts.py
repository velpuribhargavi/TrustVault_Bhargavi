"""What counts as "something worth noticing" for the administrator.

Rules run over the audit trail itself, so an alert is always backed by
evidence an investigator can open. Thresholds are deliberately simple and
documented; each alert names the rule, the actor and the time window.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import timedelta

from .utils import iso, parse_iso, utcnow

WINDOW_PROBE = timedelta(minutes=10)
WINDOW_LOGIN = timedelta(minutes=15)
WINDOW_BULK = timedelta(minutes=10)

PROBE_THRESHOLD = 5          # denied document requests by one user
LOGIN_USER_THRESHOLD = 5     # failed logins for one username
LOGIN_IP_THRESHOLD = 10      # failed logins from one IP
BULK_THRESHOLD = 10          # distinct documents downloaded by one user
LINK_FORGERY_THRESHOLD = 3   # links with a bad signature presented by one user
WRONG_CODE_THRESHOLD = 3     # wrong two-step codes after a correct password, one account

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _burst(events: list[dict], window: timedelta, threshold: int, distinct_key: str | None = None):
    """Return (start, end, count) of the first window holding >= threshold
    events (or distinct values of ``distinct_key``), else None."""
    times = [(parse_iso(e["ts"]), e) for e in events]
    start = 0
    for end in range(len(times)):
        while times[end][0] - times[start][0] > window:
            start += 1
        chunk = [e for _, e in times[start:end + 1]]
        count = len({e.get(distinct_key) for e in chunk}) if distinct_key else len(chunk)
        if count >= threshold:
            return chunk[0]["ts"], chunk[-1]["ts"], count
    return None


def compute_alerts(conn: sqlite3.Connection, hours: int = 24, verify_result: dict | None = None) -> list[dict]:
    since = iso(utcnow() - timedelta(hours=hours))
    rows = conn.execute(
        """SELECT seq, ts, actor_id, actor_name, action, outcome, document_id, target_user_id, ip, details
           FROM audit_log WHERE ts >= ? ORDER BY seq ASC LIMIT 50000""",
        (since,),
    ).fetchall()
    events = []
    for r in rows:
        e = dict(r)
        try:
            e["details"] = json.loads(e["details"] or "{}")
        except ValueError:
            e["details"] = {}
        events.append(e)

    alerts: list[dict] = []

    def add(rule, severity, title, detail, actor=None, first=None, last=None, count=None):
        alerts.append({"rule": rule, "severity": severity, "title": title, "detail": detail,
                       "actor": actor, "first_seen": first, "last_seen": last, "count": count})

    if verify_result is not None and not verify_result.get("ok", True):
        add("audit_integrity", "critical", "Audit trail integrity check FAILED",
            "; ".join(verify_result.get("problems", [])) or "chain broken")

    denied_by_actor = defaultdict(list)
    failed_login_by_user = defaultdict(list)
    failed_login_by_ip = defaultdict(list)
    downloads_by_actor = defaultdict(list)
    forged_links_by_actor = defaultdict(list)

    resets: dict[str, dict] = {}  # target user id -> the admin password-reset event
    wrong_codes_by_user = defaultdict(list)  # password was right, the two-step code was not

    for e in events:
        action, outcome, d = e["action"], e["outcome"], e["details"]
        # Admins cannot open documents - but an admin who resets someone's
        # password could sign in *as* them. Every reset is surfaced; a sign-in
        # to that account from the resetting admin's own address is flagged high.
        if action == "user.password_reset" and outcome == "allowed":
            resets[e["target_user_id"]] = e
            add("admin_password_reset", "medium", "Administrator reset a user's password",
                f"{e['actor_name']} reset the password of '{d.get('username')}' - confirm the user asked for it",
                e["actor_name"], e["ts"], e["ts"], 1)
        if action == "user.2fa_reset" and outcome == "allowed":
            resets[e["target_user_id"]] = e
            add("admin_2fa_reset", "medium", "Administrator reset someone's two-step sign-in",
                f"{e['actor_name']} turned off the two-step sign-in of '{d.get('username')}' - confirm they lost "
                "their phone and asked for it", e["actor_name"], e["ts"], e["ts"], 1)
        if action == "auth.2fa_failed" and d.get("reason") in ("bad_code", "code_reused", "bad_backup_code",
                                                               "secret_unreadable") and e["actor_id"]:
            wrong_codes_by_user[e["actor_name"] or e["actor_id"]].append(e)
        if action == "auth.login" and outcome == "allowed" and e["actor_id"] in resets:
            reset = resets[e["actor_id"]]
            if e["ip"] and e["ip"] == reset["ip"]:
                add("possible_impersonation", "high", "Account used from the address of the admin who reset it",
                    f"'{e['actor_name']}' signed in from {e['ip']} after {reset['actor_name']} reset their password "
                    f"from the same address", e["actor_name"], reset["ts"], e["ts"], 1)
        # Probing = being refused access to documents. A rejected *upload*
        # (bad file type) is the uploader's own content, not probing.
        if action.startswith("document.") and outcome == "denied" and e["actor_id"] \
                and d.get("reason") != "validation":
            denied_by_actor[e["actor_name"] or e["actor_id"]].append(e)
        if action == "auth.login" and outcome == "denied":
            if d.get("reason") == "inactive_user":
                add("inactive_account_login", "medium", "Deactivated account tried to sign in",
                    f"Account '{e['actor_name']}' is deactivated but attempted to sign in from {e['ip']}",
                    e["actor_name"], e["ts"], e["ts"], 1)
            failed_login_by_user[(e["actor_name"] or "").lower()].append(e)
            failed_login_by_ip[e["ip"]].append(e)
        if action in ("document.download", "document.version_download", "document.preview") \
                and outcome == "allowed" and e["actor_id"]:
            downloads_by_actor[e["actor_name"] or e["actor_id"]].append(e)
        if action.startswith("document.") and outcome == "error" and d.get("reason") == "integrity":
            add("integrity_failure", "critical", "Stored file failed its integrity check",
                f"Document {e['document_id']} could not be verified ({d.get('reason')}) - possible tampering with storage",
                e["actor_name"], e["ts"], e["ts"], 1)
        # A share link only works for the person it was made for. Someone else
        # presenting it means it was forwarded (or stolen).
        if outcome == "denied" and d.get("reason") == "wrong_user":
            add("forwarded_link", "medium", "Share link used by someone it was not made for",
                f"'{e['actor_name']}' tried to open link {d.get('link_id')} made for another person "
                f"(document {e['document_id']}) - it may have been forwarded", e["actor_name"], e["ts"], e["ts"], 1)
        if outcome == "denied" and d.get("reason") == "link_invalid" and e["actor_id"]:
            forged_links_by_actor[e["actor_name"] or e["actor_id"]].append(e)
        if action == "user.create" and d.get("role") == "admin" and not d.get("seeded"):
            add("privilege_change", "high", "New administrator account created",
                f"{e['actor_name']} created administrator '{d.get('username')}'", e["actor_name"], e["ts"], e["ts"], 1)
        if action == "user.update" and d.get("changes", {}).get("role", {}).get("to") == "admin":
            add("privilege_change", "high", "User promoted to administrator",
                f"{e['actor_name']} promoted '{d.get('username')}' to administrator", e["actor_name"], e["ts"], e["ts"], 1)
        if action in ("access.granted", "access.changed") and outcome == "allowed" \
                and d.get("permission") == "edit" and d.get("target_external"):
            add("external_edit_grant", "medium", "Edit access granted to an external user",
                f"{e['actor_name']} gave '{d.get('target_username')}' edit access to document {e['document_id']}",
                e["actor_name"], e["ts"], e["ts"], 1)

    for actor, evs in denied_by_actor.items():
        hit = _burst(evs, WINDOW_PROBE, PROBE_THRESHOLD)
        if hit:
            add("access_probing", "high", "Repeated refused document access",
                f"'{actor}' was refused {hit[2]}+ document requests within 10 minutes - possible id probing",
                actor, hit[0], hit[1], hit[2])
    for user, evs in failed_login_by_user.items():
        hit = _burst(evs, WINDOW_LOGIN, LOGIN_USER_THRESHOLD)
        if hit:
            add("password_guessing", "medium", "Repeated failed sign-ins for one account",
                f"{hit[2]} failed sign-ins for '{user}' within 15 minutes", user, hit[0], hit[1], hit[2])
    for ip, evs in failed_login_by_ip.items():
        hit = _burst(evs, WINDOW_LOGIN, LOGIN_IP_THRESHOLD)
        if hit:
            add("credential_stuffing", "high", "Many failed sign-ins from one address",
                f"{hit[2]} failed sign-ins from {ip} within 15 minutes", ip, hit[0], hit[1], hit[2])
    for actor, evs in downloads_by_actor.items():
        hit = _burst(evs, WINDOW_BULK, BULK_THRESHOLD, distinct_key="document_id")
        if hit:
            add("bulk_download", "high", "Bulk download",
                f"'{actor}' downloaded or opened {hit[2]} different documents within 10 minutes - possible exfiltration",
                actor, hit[0], hit[1], hit[2])
    for actor, evs in wrong_codes_by_user.items():
        hit = _burst(evs, WINDOW_LOGIN, WRONG_CODE_THRESHOLD)
        if hit:
            add("password_known_second_factor_failing", "high", "Right password, wrong two-step codes",
                f"Someone signed in to '{actor}' with the right password but entered {hit[2]} wrong codes within "
                "15 minutes - the password is probably known to someone else. Ask them to change it.",
                actor, hit[0], hit[1], hit[2])
    for actor, evs in forged_links_by_actor.items():
        if len(evs) >= LINK_FORGERY_THRESHOLD:
            add("link_tampering", "high", "Tampered or made-up share links",
                f"'{actor}' presented {len(evs)} share links whose signature does not match - "
                "someone is editing or guessing link tokens", actor, evs[0]["ts"], evs[-1]["ts"], len(evs))

    alerts.sort(key=lambda a: a["last_seen"] or "", reverse=True)       # newest first...
    alerts.sort(key=lambda a: SEVERITY_ORDER.get(a["severity"], 9))     # ...within each severity (stable sort)
    return alerts
