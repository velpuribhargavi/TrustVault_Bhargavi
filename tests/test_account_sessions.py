"""Account page: where am I signed in, sign out one session or everywhere -
ended on the server, at once. Plus the session cookie's flags and the lockout
and rate-limit audit events. THREATS.md: T24, T26, T79.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from conftest import PASSWORDS, Client, audit_rows
from trustvault.main import create_app
from trustvault.security import hash_token, session_ref
from trustvault.utils import describe_device


def browser(world, username: str, user_agent: str) -> Client:
    c = Client(world.app)
    c.http.headers["User-Agent"] = user_agent
    assert c.login(username).status_code == 200
    return c


CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
SAFARI_IOS = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"


def test_my_sessions_show_device_ip_and_last_seen_and_only_mine(world):
    laptop = browser(world, "carol", CHROME_WIN)
    phone = browser(world, "carol", SAFARI_IOS)
    items = laptop.get("/api/auth/sessions").json()["items"]
    assert items[0]["current"] is True and items[0]["device"] == "Chrome on Windows"
    devices = {i["device"] for i in items}
    assert {"Chrome on Windows", "Safari on iOS"} <= devices
    assert all(set(i) >= {"id", "device", "ip", "created_at", "last_seen_at", "expires_at", "current"} for i in items)
    assert sum(i["current"] for i in items) == 1
    # Only carol's: alice's sessions never appear, and no token or token hash is shown.
    alice_refs = {session_ref(r[0]) for r in _db(world).execute(
        "SELECT token_hash FROM sessions s JOIN users u ON u.id = s.user_id WHERE u.username = 'alice'")}
    assert alice_refs and alice_refs.isdisjoint({i["id"] for i in items})
    token = phone.http.cookies.get("tv_session")
    assert all(token not in json.dumps(i) and hash_token(token) not in json.dumps(i) for i in items)


def _db(world):
    from trustvault.db import connect
    return connect(world.app.state.ctx.settings.db_path, durable=False)


def test_sign_out_another_session_ends_it_on_the_server_at_once(world, db):
    laptop = browser(world, "carol", CHROME_WIN)
    phone = browser(world, "carol", SAFARI_IOS)
    target = next(i for i in laptop.get("/api/auth/sessions").json()["items"] if i["device"] == "Safari on iOS")
    r = laptop.delete(f"/api/auth/sessions/{target['id']}")
    assert r.status_code == 200 and r.json()["signed_out_here"] is False
    assert phone.get("/api/auth/me").status_code == 401                         # the very next request
    assert laptop.get("/api/auth/me").status_code == 200
    row = audit_rows(db, action="auth.session_revoked")[-1]
    details = json.loads(row["details"])
    assert row["outcome"] == "allowed" and details["session"] == target["id"] and details["device"] == "Safari on iOS"


def test_sign_out_this_session(world):
    laptop = browser(world, "carol", CHROME_WIN)
    mine = laptop.get("/api/auth/sessions").json()["items"][0]
    r = laptop.delete(f"/api/auth/sessions/{mine['id']}")
    assert r.status_code == 200 and r.json()["signed_out_here"] is True
    assert "tv_session=" in r.headers["set-cookie"] and "max-age=0" in r.headers["set-cookie"].lower()
    assert laptop.get("/api/auth/me").status_code == 401


def test_nobody_can_sign_out_someone_elses_session(world, db):
    alice_ref = session_ref(db.execute("SELECT token_hash FROM sessions s JOIN users u ON u.id = s.user_id "
                                       "WHERE u.username = 'alice'").fetchone()[0])
    r = world["carol"].delete(f"/api/auth/sessions/{alice_ref}")
    assert r.status_code == 404
    assert world["alice"].get("/api/auth/me").status_code == 200
    row = audit_rows(db, action="auth.session_revoked")[-1]
    assert row["outcome"] == "denied" and json.loads(row["details"])["reason"] == "session_not_found"
    assert world["carol"].delete("/api/auth/sessions/not-a-ref").status_code == 422
    assert world["carol"].delete(f"/api/auth/sessions/{alice_ref}", csrf=False).status_code == 403


def test_sign_out_everywhere_ends_every_session_including_this_one(world, db):
    laptop = browser(world, "carol", CHROME_WIN)
    phone = browser(world, "carol", SAFARI_IOS)
    r = laptop.post("/api/auth/sessions/sign-out-everywhere")
    assert r.status_code == 200 and r.json()["sessions_ended"] >= 3               # fixture + laptop + phone
    for c in (laptop, phone, world["carol"]):
        assert c.get("/api/auth/me").status_code == 401
    assert world["alice"].get("/api/auth/me").status_code == 200                  # nobody else
    assert json.loads(audit_rows(db, action="auth.signed_out_everywhere")[-1]["details"])["sessions"] >= 3
    assert db.execute("SELECT COUNT(*) FROM sessions s JOIN users u ON u.id = s.user_id "
                      "WHERE u.username = 'carol'").fetchone()[0] == 0


def test_device_names():
    assert describe_device(CHROME_WIN) == "Chrome on Windows"
    assert describe_device(SAFARI_IOS) == "Safari on iOS"
    assert describe_device("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0") == "Firefox on Linux"
    assert describe_device("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Version/17.5 Safari/605.1.15") \
        == "Safari on macOS"
    assert describe_device("Mozilla/5.0 (Windows NT 10.0) Chrome/130.0 Safari/537.36 Edg/130.0") == "Edge on Windows"
    assert describe_device("python-httpx/0.27") == "Script / API client"
    assert describe_device(None) == "Unknown device"


# ------------------------------------------------------------- the cookie --
def _cookie(response) -> str:
    return response.headers["set-cookie"].lower()


def test_the_session_cookie_is_httponly_samesite_and_secure_over_https(settings):
    app = create_app(settings)
    from conftest import create_user
    create_user(app, "carol", "viewer")
    body = {"username": "carol", "password": PASSWORDS["carol"]}
    plain = TestClient(app, base_url="http://testserver").post("/api/auth/login", json=body)
    assert "httponly" in _cookie(plain) and "samesite=strict" in _cookie(plain) and "secure" not in _cookie(plain)
    https = TestClient(app, base_url="https://testserver").post("/api/auth/login", json=body)
    assert "httponly" in _cookie(https) and "samesite=strict" in _cookie(https) and "; secure" in _cookie(https)


def test_behind_a_trusted_proxy_x_forwarded_proto_counts(settings):
    from conftest import create_user
    body = {"username": "carol", "password": PASSWORDS["carol"]}
    trusting = create_app(settings.with_overrides(trust_proxy=True))
    create_user(trusting, "carol", "viewer")
    r = TestClient(trusting).post("/api/auth/login", json=body, headers={"X-Forwarded-Proto": "https"})
    assert "; secure" in _cookie(r)
    # ...but never from an untrusted client: anyone can send that header.
    untrusting = create_app(settings.with_overrides(trust_proxy=False, instance_dir=settings.instance_dir.parent / "b"))
    create_user(untrusting, "carol", "viewer")
    r = TestClient(untrusting).post("/api/auth/login", json=body, headers={"X-Forwarded-Proto": "https"})
    assert "secure" not in _cookie(r)


def test_cookie_secure_setting_forces_secure_and_the_host_prefix(settings):
    from conftest import create_user
    app = create_app(settings.with_overrides(cookie_secure=True))
    create_user(app, "carol", "viewer")
    r = TestClient(app, base_url="https://testserver").post("/api/auth/login",
                                                            json={"username": "carol", "password": PASSWORDS["carol"]})
    assert r.headers["set-cookie"].startswith("__Host-tv_session=") and "; secure" in _cookie(r)
    assert "domain=" not in _cookie(r) and "path=/" in _cookie(r)


def test_security_headers_on_every_kind_of_response(world):
    for url in ("/", "/api/health", "/api/auth/me", "/api/documents/AAAAAAAAAAAAAAAAAAAAAA", "/static/app.js"):
        h = world["carol"].get(url).headers
        assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer", url


# ------------------------------------------------ rate limit and lockout --
def test_lockout_and_rate_limit_each_write_an_audit_event(settings):
    from conftest import create_user
    from trustvault.db import connect
    app = create_app(settings.with_overrides(login_rate_per_ip_per_minute=8))
    create_user(app, "carol", "viewer")
    c = Client(app)
    for _ in range(5):
        assert c.login("carol", "wrong-password-123").status_code == 401
    conn = connect(app.state.ctx.settings.db_path, durable=False)
    locked = audit_rows(conn, action="auth.account_locked")
    assert len(locked) == 1
    d = json.loads(locked[0]["details"])
    assert d["via"] == "password" and d["failures"] == 5 and d["locked_until"] and locked[0]["actor_name"] == "carol"
    assert c.login("carol").status_code == 401                                   # right password, locked
    for _ in range(3):
        c.login("carol")
    assert c.login("carol").status_code == 429                                   # 8 per minute per address
    assert json.loads(audit_rows(conn, action="auth.login", outcome="denied")[-1]["details"])["reason"] == "rate_limited"
