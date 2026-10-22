"""Time-limited access: every grant expires, owners can extend or revoke, and
every step - including the expiry itself - is in the audit trail.

The server clock is moved with the ``clock`` fixture; nothing sleeps.
THREATS.md: T10 (expired grant), T65 (forgotten access), T67 (one config).
"""
from __future__ import annotations

import json

import pytest

from conftest import audit_rows
from trustvault import config
from trustvault.config import Settings
from trustvault.utils import parse_iso, utcnow


def grant(world, who="frank", permission="download", **extra):
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                            json={"username": who, "permission": permission, **extra})
    assert r.status_code == 201, r.text
    return r.json()


def later(world, clock, who, **delta):
    """Move the clock and sign ``who`` in again: jumps past SESSION_IDLE_MINUTES
    (15 min) end every session, exactly as they would for a real person."""
    clock.advance(**delta)
    return world.fresh(who)


def reason_of_last_denial(db, actor_id):
    rows = [r for r in audit_rows(db, outcome="denied") if r["actor_id"] == actor_id]
    return json.loads(rows[-1]["details"])["reason"]


# ------------------------------------------------------------- one config
def test_all_time_limits_come_from_one_config():
    s = Settings()
    assert config.LINK_TTL_SECONDS == 300 and s.link_ttl_seconds == 300
    assert config.DEFAULT_GRANT_MINUTES == 30 and s.default_grant_minutes == 30
    assert config.SESSION_IDLE_MINUTES == 15 and s.session_idle_minutes == 15
    assert config.SESSION_MAX_HOURS == 8 and s.session_absolute_hours == 8


def test_time_limits_can_be_overridden_by_environment(monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_LINK_TTL_SECONDS", "60")
    monkeypatch.setenv("TRUSTVAULT_DEFAULT_GRANT_MINUTES", "5")
    s = Settings()
    assert s.link_ttl_seconds == 60 and s.default_grant_minutes == 5


def test_meta_tells_the_ui_the_limits(world):
    meta = world["carol"].get("/api/meta").json()
    assert meta["link_ttl_seconds"] == 300 and meta["default_grant_minutes"] == 30
    assert meta["session_idle_minutes"] == 15 and meta["session_max_hours"] == 8


# ---------------------------------------------------------- grant expiry
def test_grant_without_a_duration_lasts_the_default_30_minutes(world, db, clock):
    g = grant(world)
    lasts = (parse_iso(g["expires_at"]) - utcnow()).total_seconds()
    assert 29 * 60 < lasts <= 30 * 60
    frank = later(world, clock, "frank", minutes=29)
    assert frank.get(f"/api/documents/{world.doc_a}/download").status_code == 200
    clock.advance(minutes=1, seconds=1)
    r = frank.get(f"/api/documents/{world.doc_a}/download")
    assert r.status_code == 403 and r.json()["code"] == "no_access"
    assert reason_of_last_denial(db, world.ids["frank"]) == "grant_expired"


def test_chosen_duration_and_absolute_expiry(world, clock):
    g = grant(world, duration_minutes=240)
    assert 239 * 60 < (parse_iso(g["expires_at"]) - utcnow()).total_seconds() <= 240 * 60
    frank = later(world, clock, "frank", hours=3, minutes=59)
    assert frank.get(f"/api/documents/{world.doc_a}").status_code == 200
    clock.advance(minutes=2)
    assert frank.get(f"/api/documents/{world.doc_a}").status_code == 403


def test_grant_duration_validation(world):
    a = world["alice"]
    url = f"/api/documents/{world.doc_a}/grants"
    both = {"username": "frank", "permission": "view", "duration_minutes": 10, "expires_at": "2099-01-01T00:00:00Z"}
    assert a.post(url, json=both).status_code == 400
    assert a.post(url, json={"username": "frank", "permission": "view",
                             "expires_at": "2000-01-01T00:00:00Z"}).status_code == 400
    assert a.post(url, json={"username": "frank", "permission": "view", "duration_minutes": 0}).status_code == 422
    too_long = {"username": "frank", "permission": "view", "duration_minutes": 367 * 24 * 60}
    assert a.post(url, json=too_long).status_code in (400, 422)


def test_expired_grant_disappears_from_search_and_shows_as_expired_to_the_owner(world, clock):
    grant(world, duration_minutes=10)
    assert "Salary letter - Carol.pdf" in {d["name"] for d in world["frank"].get("/api/documents").json()["items"]}
    item = world["frank"].get("/api/documents").json()["items"][0]
    assert item["my_access_expires_at"]  # the UI shows a countdown
    clock.advance(minutes=11)
    assert world["frank"].get("/api/documents").json()["items"] == []
    rows = {g["username"]: g for g in world["alice"].get(f"/api/documents/{world.doc_a}/grants").json()["items"]}
    assert rows["frank"]["expired"] is True and rows["frank"]["seconds_left"] == 0
    assert rows["carol"]["expired"] is False and rows["carol"]["seconds_left"] > 0


def test_expiry_is_written_to_the_audit_trail_exactly_once(world, db, clock):
    grant(world, duration_minutes=5)
    clock.advance(minutes=6)
    frank = world["frank"]
    for _ in range(3):
        assert frank.get(f"/api/documents/{world.doc_a}").status_code == 403
    world["alice"].get(f"/api/documents/{world.doc_a}/grants")
    rows = [r for r in audit_rows(db, action="access.expired") if r["target_user_id"] == world.ids["frank"]]
    assert len(rows) == 1
    d = json.loads(rows[0]["details"])
    assert d["permission"] == "download" and rows[0]["actor_name"] == "system:expiry"


def test_expiry_is_recorded_even_if_nobody_tries_to_use_the_grant(world, db, clock):
    grant(world, duration_minutes=5)
    clock.advance(minutes=6)
    world["bob"].get("/api/documents")  # any signed-in request runs the periodic sweep
    assert [r for r in audit_rows(db, action="access.expired") if r["target_user_id"] == world.ids["frank"]]


# --------------------------------------------------------------- extend
def test_extend_adds_time_to_a_live_grant(world, db, clock):
    g = grant(world, duration_minutes=10)
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants/{g['id']}/extend", json={"minutes": 60})
    assert r.status_code == 200
    assert (parse_iso(r.json()["expires_at"]) - parse_iso(g["expires_at"])).total_seconds() == pytest.approx(3600, abs=1)
    assert later(world, clock, "frank", minutes=65).get(f"/api/documents/{world.doc_a}/download").status_code == 200
    ext = audit_rows(db, action="access.extended", outcome="allowed")[-1]
    assert json.loads(ext["details"])["added_minutes"] == 60 and ext["actor_name"] == "alice"


def test_extend_revives_an_expired_grant_from_now(world, db, clock):
    g = grant(world, duration_minutes=5)
    frank = later(world, clock, "frank", minutes=30)
    alice = world.fresh("alice")
    assert frank.get(f"/api/documents/{world.doc_a}").status_code == 403
    r = alice.post(f"/api/documents/{world.doc_a}/grants/{g['id']}/extend", json={"minutes": 15})
    assert r.status_code == 200
    assert 14 * 60 < (parse_iso(r.json()["expires_at"]) - utcnow()).total_seconds() <= 15 * 60
    assert frank.get(f"/api/documents/{world.doc_a}").status_code == 200
    assert json.loads(audit_rows(db, action="access.extended")[-1]["details"])["was_expired"] is True
    # ... and when it runs out again, that expiry is recorded again.
    later(world, clock, "alice", minutes=16).get(f"/api/documents/{world.doc_a}/grants")
    assert len([r for r in audit_rows(db, action="access.expired") if r["target_user_id"] == world.ids["frank"]]) == 2


def test_only_the_owner_can_extend(world):
    url = f"/api/documents/{world.doc_a}/grants/{world.grant_carol}/extend"
    for who in ("carol", "dave", "gina", "bob", "admin"):
        assert world[who].post(url, json={"minutes": 600}).status_code == 403, who
    assert world["alice"].post(url, json={"minutes": 0}).status_code == 422


def test_extend_cannot_go_past_the_maximum(world):
    url = f"/api/documents/{world.doc_a}/grants/{world.grant_carol}/extend"
    assert world["alice"].post(url, json={"minutes": 366 * 24 * 60}).status_code == 400


# ---------------------------------------------------- grant lifecycle audit
def test_grant_lifecycle_events(world, db, clock):
    g = grant(world, permission="view", duration_minutes=5)
    grant(world, permission="download", duration_minutes=60)        # change while live
    world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{g['id']}")
    g2 = grant(world, permission="view", duration_minutes=1)
    clock.advance(minutes=2)
    grant(world, permission="view", duration_minutes=10)            # re-grant after it expired
    events = [r["action"] for r in audit_rows(db, document_id=world.doc_a)
              if r["target_user_id"] == world.ids["frank"] and r["outcome"] in ("allowed", "info")]
    assert events == ["access.granted", "access.changed", "access.revoked", "access.granted", "access.expired",
                      "access.granted"], events
    last = json.loads(audit_rows(db, action="access.granted")[-1]["details"])
    assert last["previous"]["was_expired"] is True and g2["id"]


def test_refused_grants_are_audited_with_their_reason(world, db):
    world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "admin", "permission": "view"})
    row = audit_rows(db, action="access.granted", outcome="denied")[-1]
    assert json.loads(row["details"])["reason"] == "target_admin"


def test_refused_durations_and_extensions_are_audited(world, db):
    a = world["alice"]
    assert a.post(f"/api/documents/{world.doc_a}/grants",
                  json={"username": "frank", "permission": "view", "expires_at": "2000-01-01T00:00:00Z"}).status_code == 400
    assert json.loads(audit_rows(db, action="access.granted", outcome="denied")[-1]["details"])["reason"] == "invalid_duration"
    url = f"/api/documents/{world.doc_a}/grants/{world.grant_carol}/extend"
    assert a.post(url, json={"minutes": 366 * 24 * 60}).status_code == 400
    world["admin"].patch(f"/api/admin/users/{world.ids['carol']}", json={"is_active": False})
    assert a.post(url, json={"minutes": 30}).status_code == 400
    reasons = [json.loads(r["details"])["reason"] for r in audit_rows(db, action="access.extended", outcome="denied")]
    assert reasons == ["invalid_duration", "target_inactive"]
