"""Authentication, sessions and CSRF.  THREATS.md: T19-T26."""
from __future__ import annotations

from conftest import PASSWORDS, Client, audit_rows


def test_wrong_password_and_unknown_user_look_identical(world):
    a = Client(world.app).login("carol", "wrong-password-123")
    b = Client(world.app).login("nobody-here", "wrong-password-123")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_failed_logins_are_audited_with_reason(world, db):
    Client(world.app).login("carol", "wrong-password-123")
    Client(world.app).login("ghost", "wrong-password-123")
    reasons = [r["details"] for r in audit_rows(db, action="auth.login", outcome="denied")]
    assert any('"bad_password"' in d for d in reasons)
    assert any('"unknown_user"' in d for d in reasons)


def test_account_locks_after_repeated_failures_even_for_right_password(world, db):
    for _ in range(5):
        assert Client(world.app).login("carol", "wrong-password-123").status_code == 401
    assert Client(world.app).login("carol").status_code == 401  # correct password, still locked
    assert any('"account_locked"' in r["details"] for r in audit_rows(db, action="auth.login", outcome="denied"))
    # an admin can unlock
    assert world["admin"].post(f"/api/admin/users/{world.ids['carol']}/unlock").status_code == 200
    assert Client(world.app).login("carol").status_code == 200


def test_login_rate_limit_per_ip(settings, tmp_path):
    from trustvault.main import create_app
    app = create_app(settings.with_overrides(instance_dir=tmp_path / "rl", login_rate_per_ip_per_minute=3))
    codes = [Client(app).login("nobody", "wrong-password-123").status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401] and codes[3:] == [429, 429]


def test_forwarded_for_header_is_ignored_by_default(app, world, db):
    """An attacker must not be able to pick their own IP (to dodge rate limits
    or to frame someone else in the audit trail)."""
    c = Client(app)
    c.http.post("/api/auth/login", json={"username": "carol", "password": "nope-nope-nope"},
                headers={"X-Forwarded-For": "6.6.6.6"})
    assert audit_rows(db, action="auth.login", outcome="denied")[-1]["ip"] != "6.6.6.6"


def test_deactivated_user_cannot_sign_in_and_it_is_flagged(world, db):
    world["admin"].patch(f"/api/admin/users/{world.ids['dave']}", json={"is_active": False})
    assert Client(world.app).login("dave").status_code == 401
    assert any('"inactive_user"' in r["details"] for r in audit_rows(db, action="auth.login", outcome="denied"))
    alerts = world["admin"].get("/api/admin/alerts").json()["items"]
    assert any(a["rule"] == "inactive_account_login" for a in alerts)


def test_cookie_is_httponly_samesite_strict(app):
    from conftest import create_user
    create_user(app, "carol", "viewer")
    r = Client(app).login("carol")
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert "token" not in r.json()  # cookie mode never exposes the token to JavaScript


def test_new_session_on_every_login(world):
    first = world["carol"].http.cookies.get("tv_session")
    again = Client(world.app)
    again.http.cookies.set("tv_session", first)  # attacker-planted / old cookie
    r = again.login("carol")
    issued = r.headers["set-cookie"].split(";")[0].split("=", 1)[1]
    assert issued and issued != first


def test_csrf_token_required_for_cookie_requests(world, db):
    carol_grants = db.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
    alice = world["alice"]
    r = alice.post(f"/api/documents/{world.doc_a}/grants", csrf=False, json={"username": "frank", "permission": "view"})
    assert r.status_code == 403
    r = alice.post(f"/api/documents/{world.doc_a}/grants", csrf=False, headers={"X-CSRF-Token": "forged"},
                   json={"username": "frank", "permission": "view"})
    assert r.status_code == 403
    # another user's CSRF token is not valid for alice's session either
    r = alice.post(f"/api/documents/{world.doc_a}/grants", csrf=False, headers={"X-CSRF-Token": world["carol"].csrf},
                   json={"username": "frank", "permission": "view"})
    assert r.status_code == 403
    assert db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == carol_grants
    assert alice.delete(f"/api/documents/{world.doc_a}", csrf=False).status_code == 403


def test_bearer_tokens_work_without_csrf(world):
    c = Client(world.app)
    token = c.login("alice", mode="bearer").json()["token"]
    h = {"Authorization": f"Bearer {token}"}
    assert c.http.get("/api/auth/me", headers=h).status_code == 200
    r = c.http.patch(f"/api/documents/{world.doc_a}", json={"description": "via api"}, headers=h)
    assert r.status_code == 200
    assert c.http.get("/api/auth/me", headers={"Authorization": "Bearer not-a-real-token"}).status_code == 401


def test_change_password_requires_current_password(world):
    r = world["carol"].post("/api/auth/change-password",
                            json={"current_password": "wrong-password", "new_password": "Totally-new-pass-2026"})
    assert r.status_code == 400
    assert Client(world.app).login("carol", "Totally-new-pass-2026").status_code == 401
    assert Client(world.app).login("carol").status_code == 200


def test_change_password_cannot_be_used_to_brute_force(world, db):
    """A stolen session must not be able to guess the real password through
    the change-password endpoint: failures count towards the sign-in lockout,
    and reaching it ends every session of the account."""
    carol = world["carol"]
    other = world.fresh("carol")
    for i in range(5):
        r = carol.post("/api/auth/change-password",
                       json={"current_password": f"guess-number-{i}", "new_password": "Whatever-new-2026"})
        assert r.status_code in (400, 401)
    assert carol.get("/api/auth/me").status_code == 401
    assert other.get("/api/auth/me").status_code == 401
    assert Client(world.app).login("carol").status_code == 401  # locked, even with the right password


def test_password_policy(world):
    for weak in ["short", "password1234", "carolcarol123!", "aaaaaaaaaaaaaaa"]:
        r = world["carol"].post("/api/auth/change-password",
                                json={"current_password": PASSWORDS["carol"], "new_password": weak})
        assert r.status_code == 400, weak


def test_unauthenticated_requests_get_401(world):
    anon = world.anon()
    for url in ["/api/documents", "/api/auth/me", "/api/admin/users", "/api/users/directory", "/api/meta"]:
        assert anon.get(url).status_code == 401, url


def test_passwords_are_argon2id_hashed(db, world):
    h = db.execute("SELECT password_hash FROM users WHERE username = 'carol'").fetchone()[0]
    assert h.startswith("$argon2id$") and PASSWORDS["carol"] not in h


def test_session_tokens_are_stored_hashed(db, world):
    cookie = world["carol"].http.cookies.get("tv_session")
    stored = [r[0] for r in db.execute("SELECT token_hash FROM sessions")]
    assert cookie not in stored and len(stored[0]) == 64
