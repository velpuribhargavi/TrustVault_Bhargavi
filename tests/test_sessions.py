"""Sessions end after 15 idle minutes or 8 hours, whatever happens, and the
end is recorded. "Stay signed in" restarts only the idle timer.

THREATS.md: T24 (stolen session), T68 (unattended screen).
"""
from __future__ import annotations

import json

from conftest import audit_rows
from trustvault.errors import SESSION_EXPIRED_MESSAGE
from trustvault.main import create_app
from trustvault.utils import parse_iso, utcnow


def expired_rows(db, who_id):
    return [r for r in audit_rows(db, action="auth.session_expired") if r["actor_id"] == who_id]


def test_idle_for_15_minutes_signs_you_out_and_is_recorded_once(world, db, clock):
    carol = world["carol"]
    clock.advance(minutes=14, seconds=50)
    assert carol.get("/api/auth/me").status_code == 200   # still inside the window; this request slides it
    clock.advance(minutes=15, seconds=1)
    r = carol.get(f"/api/documents/{world.doc_a}")
    assert r.status_code == 401
    assert r.json() == {"detail": SESSION_EXPIRED_MESSAGE, "code": "session_expired"}
    assert carol.get("/api/auth/me").status_code == 401   # the session row is gone
    rows = expired_rows(db, world.ids["carol"])
    assert len(rows) == 1 and json.loads(rows[0]["details"])["reason"] == "idle"


def test_activity_keeps_the_session_alive(world, clock):
    carol = world["carol"]
    for _ in range(4):                      # 4 x 10 minutes = 40 minutes of steady use
        clock.advance(minutes=10)
        assert carol.get("/api/documents").status_code == 200


def test_eight_hours_is_the_end_however_active(world, db, clock):
    carol = world["carol"]
    for _ in range(47):                     # a request every 10 minutes for 7 h 50 min
        clock.advance(minutes=10)
        assert carol.get("/api/documents").status_code == 200
    clock.advance(minutes=10, seconds=1)    # 8 h 00 min 01 s after sign-in
    r = carol.get("/api/documents")
    assert r.status_code == 401 and r.json()["code"] == "session_expired"
    assert json.loads(expired_rows(db, world.ids["carol"])[-1]["details"])["reason"] == "max_lifetime"


def test_stay_signed_in_restarts_the_idle_timer_but_not_the_8_hours(world, db, clock):
    carol = world["carol"]
    clock.advance(minutes=13)
    r = carol.post("/api/auth/keepalive")
    assert r.status_code == 200
    session = r.json()["session"]
    assert session["idle_timeout_seconds"] == 15 * 60
    clock.advance(minutes=13)                # 26 minutes since sign-in, 13 since "stay signed in"
    assert carol.get("/api/auth/me").status_code == 200
    assert audit_rows(db, action="auth.session_extended")
    me = carol.get("/api/auth/me").json()["session"]
    assert me["expires_at"] == session["expires_at"]  # the absolute end never moves


def test_session_limits_are_reported_to_the_ui(world):
    r = world["carol"].get("/api/auth/me").json()["session"]
    assert r["idle_timeout_seconds"] == 900 and r["warning_seconds"] == 120
    lasts = (parse_iso(r["expires_at"]) - utcnow()).total_seconds()
    assert 7.9 * 3600 < lasts <= 8 * 3600
    login = world.anon().login("gina").json()
    assert login["session"]["idle_timeout_seconds"] == 900


def test_keepalive_needs_csrf_and_a_live_session(world, clock):
    assert world["carol"].post("/api/auth/keepalive", csrf=False).status_code == 403
    clock.advance(minutes=16)
    assert world["carol"].post("/api/auth/keepalive").status_code == 401


def test_bearer_sessions_expire_the_same_way(world, clock):
    token = world.anon().login("carol", mode="bearer").json()["token"]
    c = world.anon()
    assert c.http.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    clock.advance(minutes=16)
    assert c.http.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_sessions_that_ended_while_the_server_was_down_are_recorded_at_start_up(world, db, clock, settings):
    clock.advance(minutes=20)
    create_app(settings)   # restart
    ended = {r["actor_name"] for r in audit_rows(db, action="auth.session_expired")}
    assert {"alice", "carol", "admin"} <= ended
    assert json.loads(audit_rows(db, action="auth.session_expired")[-1]["details"])["detected"] == "start-up"


def test_the_browser_can_end_an_idle_session_and_it_is_recorded(world, db):
    """When the page's own idle timer runs out first, it ends the session on the
    server too, so a later request cannot quietly revive it."""
    r = world["carol"].post("/api/auth/logout", json={"reason": "idle"})
    assert r.status_code == 200
    assert world["carol"].get("/api/auth/me").status_code == 401
    row = expired_rows(db, world.ids["carol"])[-1]
    assert json.loads(row["details"])["detected"] == "browser"
    assert world["gina"].post("/api/auth/logout", json={"reason": "because"}).status_code == 422
