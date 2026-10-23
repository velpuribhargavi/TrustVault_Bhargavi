"""Two-step sign-in (TOTP): enrolment with a QR code, backup codes, enforcement
at sign-in for administrators and owners, and an audit event for every
enrolment and every failure. All through the API.
THREATS.md: T22, T75-T78.
"""
from __future__ import annotations

import hashlib
import json
import re

import pytest

from conftest import PASSWORDS, Client, audit_rows, create_user
from trustvault import totp
from trustvault.main import create_app
from trustvault.twofactor import CHALLENGE_GONE, CODE_REFUSED
from trustvault.utils import utcnow


def code(secret: str, steps_ahead: int = 0) -> str:
    """The code an authenticator app shows now (server clock)."""
    return totp.code_at(secret, utcnow().timestamp() + steps_ahead * totp.STEP_SECONDS)


@pytest.fixture
def strict(settings):
    """The real policy: administrators and owners must use two-step sign-in."""
    app = create_app(settings.with_overrides(totp_required_roles=("admin", "owner")))
    for name, role in (("admin", "admin"), ("alice", "owner"), ("bob", "owner"), ("carol", "viewer")):
        create_user(app, name, role)
    return app


def wrong(secret: str) -> str:
    """Six digits that are not the code of this step or the ones next to it."""
    near = {code(secret, k) for k in (-1, 0, 1)}
    return next(c for c in ("000000", "111111", "222222", "333333") if c not in near)


def password_step(app, username: str, **extra) -> tuple[Client, dict]:
    c = Client(app)
    r = c.http.post("/api/auth/login", json={"username": username, "password": PASSWORDS[username], **extra})
    assert r.status_code == 200, r.text
    return c, r.json()


def enroll(app, username: str) -> tuple[Client, str, list[str]]:
    """Sign in for the first time as someone who must set it up. Returns (client, secret, backup codes)."""
    c, first = password_step(app, username)
    assert first["two_factor"] == "enroll"
    r = c.http.post("/api/auth/login/enroll", json={"challenge": first["challenge"], "code": code(first["secret"])})
    assert r.status_code == 200, r.text
    c.csrf = r.json()["csrf_token"]
    return c, first["secret"], r.json()["backup_codes"]


def second_step(c: Client, challenge: str, value: str):
    r = c.http.post("/api/auth/login/verify", json={"challenge": challenge, "code": value})
    if r.status_code == 200:
        c.csrf = r.json()["csrf_token"]
    return r


def db_of(app):
    from trustvault.db import connect
    return connect(app.state.ctx.settings.db_path, durable=False)


# ------------------------------------------------------------- the codes --
def test_codes_match_the_rfc_6238_test_vectors():
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of "12345678901234567890"
    for t, expected in ((59, "287082"), (1111111109, "081804"), (1234567890, "005924"), (2000000000, "279037")):
        assert totp.code_at(secret, t) == expected
    assert totp.find_step(secret, "287082", 59 + 30) == 1          # one step of clock drift is accepted
    assert totp.find_step(secret, "287082", 59 + 90) is None        # three steps is not


# -------------------------------------------------- enforcement at sign-in --
def test_an_administrator_must_set_it_up_before_any_session_exists(strict):
    db = db_of(strict)
    c, first = password_step(strict, "admin")
    assert first["two_factor"] == "enroll" and first["required_for_role"] is True
    assert "csrf_token" not in first and "set-cookie" not in {k.lower() for k in c.http.cookies.keys()}
    assert first["qr"].startswith("data:image/png;base64,")
    assert first["otpauth_uri"].startswith("otpauth://totp/TrustVault%3Aadmin?") and first["secret"] in first["otpauth_uri"]
    assert re.fullmatch(r"[A-Z2-7]{32}", first["secret"])
    assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    assert c.get("/api/auth/me").status_code == 401                         # the password alone gave nothing

    r = c.http.post("/api/auth/login/enroll", json={"challenge": first["challenge"], "code": code(first["secret"])})
    assert r.status_code == 200 and r.json()["user"]["username"] == "admin"
    codes = r.json()["backup_codes"]
    assert len(codes) == 10 == len(set(codes)) and all(re.fullmatch(r"[a-z2-9]{4}-[a-z2-9]{4}", x) for x in codes)
    assert c.get("/api/auth/me").status_code == 200
    events = [(r["action"], r["outcome"]) for r in audit_rows(db, actor_name="admin")]
    assert events == [("auth.2fa_required", "info"), ("auth.2fa_enrolled", "allowed"), ("auth.login", "allowed")]
    login = json.loads(audit_rows(db, action="auth.login", outcome="allowed")[-1]["details"])
    assert login == {"mode": "cookie", "second_factor": "totp", "enrolled": True}


def test_first_time_set_up_needs_a_working_code(strict):
    """A wrong first code turns nothing on and opens no session (found missing by the mutation check)."""
    db = db_of(strict)
    c, first = password_step(strict, "admin")
    r = c.http.post("/api/auth/login/enroll", json={"challenge": first["challenge"], "code": wrong(first["secret"])})
    assert r.status_code == 401 and r.json()["code"] == "code_refused"
    assert c.get("/api/auth/me").status_code == 401
    assert db.execute("SELECT totp_enabled_at, totp_secret FROM users WHERE username = 'admin'").fetchone()[0] is None
    assert db.execute("SELECT COUNT(*) FROM backup_codes").fetchone()[0] == 0
    failed = json.loads(audit_rows(db, action="auth.2fa_failed")[-1]["details"])
    assert failed["stage"] == "enroll" and failed["reason"] == "bad_code"
    r = c.http.post("/api/auth/login/enroll", json={"challenge": first["challenge"], "code": code(first["secret"])})
    assert r.status_code == 200 and len(r.json()["backup_codes"]) == 10     # the right code, same attempt


def test_owners_too_but_viewers_only_if_they_choose(strict):
    assert password_step(strict, "alice")[1]["two_factor"] == "enroll"
    assert "csrf_token" in password_step(strict, "carol")[1]                  # viewer: password is enough


def test_once_set_up_the_password_alone_never_opens_a_session(strict):
    enroll(strict, "admin")
    c, first = password_step(strict, "admin")
    assert first == {"two_factor": "verify", "challenge": first["challenge"], "expires_at": first["expires_at"],
                     "required_for_role": True}
    assert c.get("/api/auth/me").status_code == 401
    r = second_step(c, first["challenge"], code(secret_of(strict, "admin"), steps_ahead=1))
    assert r.status_code == 200 and c.get("/api/auth/me").status_code == 200


def secret_of(app, username: str) -> str:
    from trustvault.twofactor import open_secret
    db = db_of(app)
    row = db.execute("SELECT id, totp_secret FROM users WHERE username = ?", (username,)).fetchone()
    return open_secret(app.state.ctx, row["id"], row["totp_secret"])


def test_a_viewer_who_turns_it_on_is_asked_for_a_code_too(world, db):
    """Default test settings: nobody is required. Turning it on is what makes it apply."""
    carol, other = world["carol"], world.fresh("carol")
    offer = carol.post("/api/auth/2fa/setup", json={"password": PASSWORDS["carol"]}).json()
    r = carol.post("/api/auth/2fa/enable", json={"code": code(offer["secret"])})
    assert r.status_code == 200 and len(r.json()["backup_codes"]) == 10 and r.json()["other_sessions_revoked"] >= 1
    assert other.get("/api/auth/me").status_code == 401                     # signed in without it: ended
    assert carol.get("/api/auth/2fa").json() == {"enabled": True, "enabled_at": carol.get("/api/auth/2fa").json()["enabled_at"],
                                                 "required": False, "backup_codes_left": 10}
    c, first = password_step(world.app, "carol")
    assert first["two_factor"] == "verify"
    assert second_step(c, first["challenge"], code(offer["secret"], 1)).status_code == 200
    assert json.loads(audit_rows(db, action="auth.2fa_enrolled")[-1]["details"])["via"] == "account"


# ------------------------------------------------------------- failures --
def test_a_wrong_code_is_refused_recorded_and_counts_towards_the_lockout(strict):
    enroll(strict, "admin")
    db = db_of(strict)
    c, first = password_step(strict, "admin")
    r = second_step(c, first["challenge"], wrong(secret_of(strict, "admin")))
    assert r.status_code == 401 and r.json() == {"detail": CODE_REFUSED, "code": "code_refused"}
    row = audit_rows(db, action="auth.2fa_failed")[-1]
    assert row["actor_name"] == "admin" and row["outcome"] == "denied"
    assert json.loads(row["details"])["reason"] == "bad_code"
    assert db.execute("SELECT failed_logins FROM users WHERE username = 'admin'").fetchone()[0] == 1
    assert c.get("/api/auth/me").status_code == 401


def test_a_code_never_works_twice(strict, clock):
    c, secret, _ = enroll(strict, "admin")
    used = code(secret)
    c2, first = password_step(strict, "admin")
    r = second_step(c2, first["challenge"], used)                            # same 30 seconds, same code
    assert r.status_code == 401
    assert json.loads(audit_rows(db_of(strict), action="auth.2fa_failed")[-1]["details"])["reason"] == "code_reused"
    clock.advance(seconds=30)
    assert second_step(c2, first["challenge"], code(secret)).status_code == 200


def test_the_sign_in_attempt_ends_after_three_wrong_codes(strict):
    enroll(strict, "admin")
    secret = secret_of(strict, "admin")
    c, first = password_step(strict, "admin")
    good = code(secret, 1)
    for _ in range(3):
        assert second_step(c, first["challenge"], wrong(secret)).status_code == 401
    r = second_step(c, first["challenge"], good)                            # right code, too late
    assert r.status_code == 401 and r.json() == {"detail": CHALLENGE_GONE, "code": "sign_in_expired"}
    assert json.loads(audit_rows(db_of(strict), action="auth.2fa_failed")[-1]["details"])["reason"] == "challenge_invalid"
    # Not locked yet (3 of 5): starting again with the password works.
    c, first = password_step(strict, "admin")
    assert second_step(c, first["challenge"], good).status_code == 200


def test_the_code_must_follow_within_five_minutes(strict, clock):
    enroll(strict, "admin")
    c, first = password_step(strict, "admin")
    clock.advance(seconds=301)
    r = second_step(c, first["challenge"], code(secret_of(strict, "admin")))
    assert r.status_code == 401 and r.json()["detail"] == CHALLENGE_GONE


def test_five_failures_lock_the_account_and_say_so_in_the_audit_trail(strict):
    enroll(strict, "admin")
    db = db_of(strict)
    for _ in range(2):
        assert Client(strict).login("admin", "wrong-password-123").status_code == 401
    c, first = password_step(strict, "admin")
    for _ in range(3):
        second_step(c, first["challenge"], wrong(secret_of(strict, "admin")))
    locked = audit_rows(db, action="auth.account_locked")
    assert len(locked) == 1 and json.loads(locked[0]["details"])["via"] == "second_factor"
    assert json.loads(locked[0]["details"])["failures"] == 5
    assert Client(strict).login("admin").status_code == 401                  # right password, still locked
    assert json.loads(audit_rows(db, action="auth.login", outcome="denied")[-1]["details"])["reason"] == "account_locked"


def test_an_unknown_challenge_is_refused_and_recorded(strict):
    r = Client(strict).http.post("/api/auth/login/verify", json={"challenge": "x" * 43, "code": "123456"})
    assert r.status_code == 401 and r.json()["detail"] == CHALLENGE_GONE
    assert json.loads(audit_rows(db_of(strict), action="auth.2fa_failed")[-1]["details"])["reason"] == "challenge_invalid"


def test_a_challenge_is_only_for_its_own_step(strict):
    c, first = password_step(strict, "admin")                                # an 'enroll' challenge
    r = c.http.post("/api/auth/login/verify", json={"challenge": first["challenge"], "code": code(first["secret"])})
    assert r.status_code == 401 and c.get("/api/auth/me").status_code == 401


def test_deactivated_between_the_two_steps_means_no_session(strict):
    _, secret, _ = enroll(strict, "alice")
    admin, _, _ = enroll(strict, "admin")
    c, first = password_step(strict, "alice")
    alice_id = db_of(strict).execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    assert admin.patch(f"/api/admin/users/{alice_id}", json={"is_active": False}).status_code == 200
    assert second_step(c, first["challenge"], code(secret, 1)).status_code == 401


# ----------------------------------------------------------- backup codes --
def test_a_backup_code_signs_in_once(strict):
    _, _, codes = enroll(strict, "admin")
    c, first = password_step(strict, "admin")
    r = second_step(c, first["challenge"], codes[3].upper().replace("-", " "))   # forgiving about case and spaces
    assert r.status_code == 200 and r.json()["backup_codes_left"] == 9
    details = json.loads(audit_rows(db_of(strict), action="auth.login", outcome="allowed")[-1]["details"])
    assert details["second_factor"] == "backup_code" and details["backup_codes_left"] == 9
    c, first = password_step(strict, "admin")
    assert second_step(c, first["challenge"], codes[3]).status_code == 401
    assert json.loads(audit_rows(db_of(strict), action="auth.2fa_failed")[-1]["details"])["reason"] == "bad_backup_code"


def test_backup_codes_belong_to_one_person(strict):
    _, _, admin_codes = enroll(strict, "admin")
    enroll(strict, "alice")
    c, first = password_step(strict, "alice")
    assert second_step(c, first["challenge"], admin_codes[0]).status_code == 401


def test_new_backup_codes_replace_the_old_ones(strict, clock):
    c, secret, old = enroll(strict, "admin")
    clock.advance(seconds=30)
    r = c.post("/api/auth/2fa/backup-codes", json={"code": code(secret)})
    assert r.status_code == 200 and set(r.json()["backup_codes"]).isdisjoint(old)
    c2, first = password_step(strict, "admin")
    assert second_step(c2, first["challenge"], old[0]).status_code == 401
    assert second_step(c2, first["challenge"], r.json()["backup_codes"][0]).status_code == 200
    assert c.post("/api/auth/2fa/backup-codes", json={"code": wrong(secret)}).status_code == 401


# ----------------------------------------------------- storage of secrets --
def test_secrets_and_backup_codes_are_never_stored_in_clear(strict):
    _, secret, codes = enroll(strict, "admin")
    db = db_of(strict)
    row = db.execute("SELECT id, totp_secret FROM users WHERE username = 'admin'").fetchone()
    assert secret.encode() not in row["totp_secret"] and len(row["totp_secret"]) > len(secret)
    stored = {r[0] for r in db.execute("SELECT code_hash FROM backup_codes")}
    for c in codes:
        plain = c.replace("-", "")
        assert plain not in stored and hashlib.sha256(plain.encode()).hexdigest() not in stored
    # And none of it ever leaves the server, not even to an administrator.
    listing = Client(strict)
    first = listing.http.post("/api/auth/login", json={"username": "admin", "password": PASSWORDS["admin"]}).json()
    second_step(listing, first["challenge"], codes[0])
    users = listing.get("/api/admin/users").json()["items"]
    assert all(set(u) & {"totp_secret", "totp_pending", "password_hash"} == set() for u in users)
    assert {u["username"]: u["two_factor"] for u in users}["admin"] is True


def test_a_seed_copied_onto_another_account_does_not_work(strict):
    """Someone with database access copies the admin's sealed seed onto alice's row,
    hoping the admin's authenticator now signs in as alice. The seal is bound to the user."""
    _, secret, _ = enroll(strict, "admin")
    enroll(strict, "alice")
    db = db_of(strict)
    sealed = db.execute("SELECT totp_secret FROM users WHERE username = 'admin'").fetchone()[0]
    db.execute("UPDATE users SET totp_secret = ? WHERE username = 'alice'", (sealed,))
    c, first = password_step(strict, "alice")
    assert second_step(c, first["challenge"], code(secret, 1)).status_code == 401
    assert json.loads(audit_rows(db, action="auth.2fa_failed")[-1]["details"])["reason"] == "secret_unreadable"


# ------------------------------------------------- managing it afterwards --
def test_roles_that_require_it_cannot_turn_it_off(strict):
    c, secret, _ = enroll(strict, "admin")
    r = c.post("/api/auth/2fa/disable", json={"password": PASSWORDS["admin"], "code": code(secret, 1)})
    assert r.status_code == 403
    row = audit_rows(db_of(strict), action="auth.2fa_disabled")[-1]
    assert row["outcome"] == "denied" and json.loads(row["details"])["reason"] == "required_for_role"
    assert c.get("/api/auth/2fa").json()["enabled"] is True


def test_turning_it_off_needs_the_password_and_a_code(world, db, clock):
    carol = world["carol"]
    offer = carol.post("/api/auth/2fa/setup", json={"password": PASSWORDS["carol"]}).json()
    carol.post("/api/auth/2fa/enable", json={"code": code(offer["secret"])})
    clock.advance(seconds=30)
    assert carol.post("/api/auth/2fa/disable", json={"password": "wrong-password-1", "code": code(offer["secret"])}
                      ).status_code == 400
    assert carol.post("/api/auth/2fa/disable", json={"password": PASSWORDS["carol"], "code": wrong(offer["secret"])}
                      ).status_code == 401
    assert carol.get("/api/auth/2fa").json()["enabled"] is True
    r = carol.post("/api/auth/2fa/disable", json={"password": PASSWORDS["carol"], "code": code(offer["secret"])})
    assert r.status_code == 200 and carol.get("/api/auth/2fa").json()["enabled"] is False
    assert "csrf_token" in world.anon().login("carol").json()                  # password alone again
    assert [r["outcome"] for r in audit_rows(db, action="auth.2fa_disabled")] == ["denied", "denied", "allowed"]


def test_setting_it_up_needs_the_password_and_a_working_code(world, db):
    carol = world["carol"]
    assert carol.post("/api/auth/2fa/setup", json={"password": "wrong-password-1"}).status_code == 400
    assert json.loads(audit_rows(db, action="auth.2fa_setup", outcome="denied")[-1]["details"])["reason"] == \
        "bad_current_password"
    offer = carol.post("/api/auth/2fa/setup", json={"password": PASSWORDS["carol"]}).json()
    assert carol.post("/api/auth/2fa/enable", json={"code": wrong(offer["secret"])}).status_code == 401
    assert carol.get("/api/auth/2fa").json()["enabled"] is False
    assert json.loads(audit_rows(db, action="auth.2fa_failed")[-1]["details"])["stage"] == "enable"
    assert carol.post("/api/auth/2fa/enable", json={"code": code(offer["secret"])}).status_code == 200


def test_moving_to_a_new_phone_retires_the_old_one(strict, clock):
    c, old_secret, _ = enroll(strict, "admin")
    offer = c.post("/api/auth/2fa/setup", json={"password": PASSWORDS["admin"]}).json()
    assert offer["secret"] != old_secret
    clock.advance(seconds=30)
    assert c.post("/api/auth/2fa/enable", json={"code": code(offer["secret"])}).status_code == 200
    c2, first = password_step(strict, "admin")
    clock.advance(seconds=30)
    assert second_step(c2, first["challenge"], code(old_secret)).status_code == 401
    assert second_step(c2, first["challenge"], code(offer["secret"])).status_code == 200


def test_an_administrator_can_reset_someone_who_lost_their_phone(strict):
    admin, _, _ = enroll(strict, "admin")
    alice, _, _ = enroll(strict, "alice")
    db = db_of(strict)
    alice_id = db.execute("SELECT id FROM users WHERE username = 'alice'").fetchone()[0]
    r = admin.post(f"/api/admin/users/{alice_id}/reset-2fa")
    assert r.status_code == 200 and r.json()["sessions_revoked"] == 1
    assert alice.get("/api/auth/me").status_code == 401
    assert password_step(strict, "alice")[1]["two_factor"] == "enroll"         # owner: must set it up again
    assert audit_rows(db, action="user.2fa_reset")[-1]["outcome"] == "allowed"
    alerts = admin.get("/api/admin/alerts").json()["items"]
    assert any(a["rule"] == "admin_2fa_reset" for a in alerts)
    # Not their own (a stolen admin session must not strip its own second factor), and never a non-admin.
    admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()[0]
    assert admin.post(f"/api/admin/users/{admin_id}/reset-2fa").status_code == 400
    assert json.loads(audit_rows(db, action="user.2fa_reset")[-1]["details"])["reason"] == "own_account"
    carol = Client(strict)
    carol.login("carol")
    assert carol.post(f"/api/admin/users/{alice_id}/reset-2fa").status_code == 403


def test_api_clients_get_a_bearer_token_after_the_second_step(strict):
    enroll(strict, "admin")
    c, first = password_step(strict, "admin", mode="bearer")
    r = c.http.post("/api/auth/login/verify", json={"challenge": first["challenge"],
                                                    "code": code(secret_of(strict, "admin"), 1)})
    assert r.status_code == 200 and r.json()["token"] and "set-cookie" not in r.headers
    assert Client(strict).http.get("/api/auth/me", headers={"Authorization": f"Bearer {r.json()['token']}"}
                                    ).status_code == 200


def test_repeated_wrong_codes_after_a_right_password_raise_an_alert(strict):
    """A right password followed by wrong codes means someone else knows the password."""
    enroll(strict, "alice")
    admin, _, _ = enroll(strict, "admin")
    for _ in range(3):
        c, first = password_step(strict, "alice")
        second_step(c, first["challenge"], wrong(secret_of(strict, "alice")))
    alerts = admin.get("/api/admin/alerts").json()["items"]
    hit = [a for a in alerts if a["rule"] == "password_known_second_factor_failing"]
    assert hit and hit[0]["severity"] == "high" and hit[0]["actor"] == "alice"
