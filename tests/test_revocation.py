"""Taking access away works immediately - on the very next request, using
whatever the person was issued before.  THREATS.md: T11, T12, T24, T25."""
from __future__ import annotations

from datetime import timedelta

from conftest import PASSWORDS, Client
from trustvault.db import transaction
from trustvault.utils import iso, utcnow


def test_revoked_grant_stops_the_same_session_at_once(world):
    carol = world["carol"]
    assert carol.get(f"/api/documents/{world.doc_a}/download").status_code == 200
    assert world["alice"].delete(f"/api/documents/{world.doc_a}/grants/{world.grant_carol}").status_code == 200
    assert carol.get(f"/api/documents/{world.doc_a}/download").status_code == 404
    assert carol.get(f"/api/documents/{world.doc_a}").status_code == 404


def test_downgrade_from_edit_to_download_is_immediate(world):
    dave = world["dave"]
    assert dave.patch(f"/api/documents/{world.doc_a}", json={"description": "ok"}).status_code == 200
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "dave", "permission": "download"})
    assert r.status_code == 201
    assert dave.patch(f"/api/documents/{world.doc_a}", json={"description": "nope"}).status_code == 403
    assert dave.get(f"/api/documents/{world.doc_a}/download").status_code == 200


def test_downgrade_from_download_to_view_stops_downloads_at_once(world):
    carol = world["carol"]
    assert carol.get(f"/api/documents/{world.doc_a}/download").status_code == 200
    r = world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "carol", "permission": "view"})
    assert r.status_code == 201
    assert carol.get(f"/api/documents/{world.doc_a}/download").status_code == 403
    assert carol.get(f"/api/documents/{world.doc_a}/preview").status_code == 200  # can still read it in the browser


def test_upgrade_from_view_to_download_works_at_once(world):
    gina = world["gina"]
    assert gina.get(f"/api/documents/{world.doc_a}/download").status_code == 403
    world["alice"].post(f"/api/documents/{world.doc_a}/grants", json={"username": "gina", "permission": "download"})
    assert gina.get(f"/api/documents/{world.doc_a}/download").status_code == 200


def test_deactivated_user_is_locked_out_of_every_session_and_link(world, db):
    second_session = world.fresh("carol")
    bearer = Client(world.app)
    token = bearer.login("carol", mode="bearer").json()["token"]
    link_token = world["alice"].post(f"/api/documents/{world.doc_a}/share-links",
                                     json={"expires_in_hours": 1, "max_uses": 5}).json()["token"]

    r = world["admin"].patch(f"/api/admin/users/{world.ids['carol']}", json={"is_active": False})
    assert r.status_code == 200 and r.json()["sessions_revoked"] == 3

    assert world["carol"].get(f"/api/documents/{world.doc_a}").status_code == 401
    assert second_session.get("/api/documents").status_code == 401
    assert bearer.http.get("/api/documents", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert Client(world.app).login("carol").status_code == 401

    # alice leaves the company: her share link dies with her account.
    world["admin"].patch(f"/api/admin/users/{world.ids['alice']}", json={"is_active": False})
    assert world.anon().post("/api/public/share/download", json={"token": link_token}).status_code == 404


def test_inactive_user_with_surviving_session_row_is_rejected(world, db):
    """Defence in depth: even if a session row survived deactivation
    (e.g. written by an old code path), the request is refused."""
    with transaction(db) as tx:
        tx.execute("UPDATE users SET is_active = 0 WHERE id = ?", (world.ids["carol"],))
    assert world["carol"].get("/api/auth/me").status_code == 401


def test_password_change_ends_other_sessions(world):
    other = world.fresh("carol")
    r = world["carol"].post("/api/auth/change-password",
                            json={"current_password": PASSWORDS["carol"], "new_password": "A-much-better-pass-2026"})
    assert r.status_code == 200
    assert other.get("/api/auth/me").status_code == 401
    assert world["carol"].get("/api/auth/me").status_code == 200  # the session that changed it survives


def test_admin_password_reset_ends_all_sessions(world):
    r = world["admin"].post(f"/api/admin/users/{world.ids['dave']}/reset-password",
                            json={"new_password": "Reset-by-admin-2026"})
    assert r.status_code == 200
    assert world["dave"].get("/api/auth/me").status_code == 401


def test_logout_kills_the_token(world):
    carol = world["carol"]
    cookie = carol.http.cookies.get("tv_session")
    assert carol.post("/api/auth/logout").status_code == 200
    replay = Client(world.app)
    replay.http.cookies.set("tv_session", cookie)
    assert replay.get("/api/auth/me").status_code == 401


def test_idle_session_expires(world, db):
    with transaction(db) as tx:
        tx.execute("UPDATE sessions SET last_seen_at = ? WHERE user_id = ?",
                   (iso(utcnow() - timedelta(minutes=31)), world.ids["carol"]))
    assert world["carol"].get("/api/auth/me").status_code == 401


def test_absolute_session_lifetime(world, db):
    with transaction(db) as tx:
        tx.execute("UPDATE sessions SET expires_at = ? WHERE user_id = ?",
                   (iso(utcnow() - timedelta(seconds=1)), world.ids["carol"]))
    assert world["carol"].get("/api/auth/me").status_code == 401


def test_trash_suspends_grants_and_restore_brings_them_back(world):
    assert world["alice"].delete(f"/api/documents/{world.doc_a}").status_code == 200
    assert world["carol"].get(f"/api/documents/{world.doc_a}/download").status_code == 404
    assert world["dave"].patch(f"/api/documents/{world.doc_a}", json={"name": "x"}).status_code == 404
    # even the owner can only view / restore / purge while it is in the trash
    assert world["alice"].get(f"/api/documents/{world.doc_a}/download").status_code == 404
    assert world["alice"].post(f"/api/documents/{world.doc_a}/grants",
                               json={"username": "frank", "permission": "view"}).status_code == 404
    assert world["alice"].post(f"/api/documents/{world.doc_a}/restore").status_code == 200
    assert world["carol"].get(f"/api/documents/{world.doc_a}/download").status_code == 200


def test_role_change_takes_effect_on_next_request(world):
    assert world["admin"].patch(f"/api/admin/users/{world.ids['frank']}", json={"role": "viewer"}).status_code == 200
    r = world["frank"].post("/api/documents", files={"file": ("x.txt", b"hello", "text/plain")},
                            data={"category": "general"})
    assert r.status_code == 403
