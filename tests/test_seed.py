"""The demo data must obey the rules the app enforces (PROMPTS.md entry 8)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

from trustvault.authz import PERMISSION_LEVELS
from trustvault.security import password_problems
from trustvault.validation import validate_upload

SEED = Path(__file__).resolve().parent.parent / "scripts" / "init_db.py"


def _seed_module():
    spec = importlib.util.spec_from_file_location("init_db", SEED)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_seed_passwords_pass_our_own_policy():
    for username, _, _, password, _ in _seed_module().USERS:
        assert password_problems(password, username) == [], username


def test_seed_has_exactly_one_login_per_role():
    assert sorted(role for _, _, role, _, _ in _seed_module().USERS) == ["admin", "owner", "viewer"]


def test_seed_documents_are_valid_and_cover_every_level():
    seed = _seed_module()
    levels = set()
    for _, filename, _, _, _, content, grants in seed.DOCUMENTS:
        validate_upload(filename, content, 10 * 1024 * 1024)  # raises if the demo file would be rejected
        levels |= {level for _, level, _ in grants}
    assert levels == set(PERMISSION_LEVELS)
    assert any(not grants for *_, grants in seed.DOCUMENTS)  # and one the viewer cannot reach


def test_demo_two_step_keys_cover_exactly_the_roles_that_need_them():
    from trustvault import totp
    from trustvault.config import TOTP_REQUIRED_ROLES
    seed = _seed_module()
    needing = {username for username, _, role, _, _ in seed.USERS if role in TOTP_REQUIRED_ROLES}
    assert needing == set(seed.DEMO_TOTP_KEYS) == {"admin", "owner"}
    assert len(set(seed.DEMO_TOTP_KEYS.values())) == 2
    assert all(len(totp._key(key)) == 20 for key in seed.DEMO_TOTP_KEYS.values())   # 160-bit keys


def test_the_seed_gives_the_unused_access_review_something_to_find():
    seed = _seed_module()
    names = {name for _, _, name, *_ in seed.DOCUMENTS}
    logins = {username for username, *_ in seed.USERS}
    for user, doc, level, ago, left in seed.STALE_GRANTS:
        assert doc in names and level in PERMISSION_LEVELS and ago >= 30 and left > 0
        assert user not in logins          # not a fourth login: the hand-in has exactly three


def test_a_fresh_seed_signs_in_with_the_published_demo_keys(tmp_path, monkeypatch, capsys):
    """End to end: init_db.py --seed, then sign in as the admin the way a judge would."""
    import sys
    from fastapi.testclient import TestClient

    from trustvault import totp
    from trustvault.config import load_settings
    from trustvault.main import create_app
    from trustvault.utils import utcnow

    for var in ("TRUSTVAULT_MASTER_KEY", "TRUSTVAULT_AUDIT_KEY", "TRUSTVAULT_TOTP_REQUIRED_ROLES"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("TRUSTVAULT_INSTANCE_DIR", str(tmp_path / "instance"))
    monkeypatch.setenv("TRUSTVAULT_ARGON2_MEMORY_KIB", "1024")
    monkeypatch.setenv("TRUSTVAULT_ARGON2_TIME_COST", "1")
    monkeypatch.setenv("TRUSTVAULT_DURABLE_WRITES", "0")
    monkeypatch.setenv("TRUSTVAULT_OFFICE_RENDERER", "off")
    seed = _seed_module()
    monkeypatch.setattr(sys, "argv", ["init_db.py", "--seed"])
    seed.main()
    assert "Two-step sign-in" in capsys.readouterr().out

    client = TestClient(create_app(load_settings()))
    step1 = client.post("/api/auth/login", json={"username": "admin", "password": "Keeper!Vault2026"}).json()
    assert step1["two_factor"] == "verify"
    code = totp.code_at(seed.DEMO_TOTP_KEYS["admin"], utcnow().timestamp())
    step2 = client.post("/api/auth/login/verify", json={"challenge": step1["challenge"], "code": code})
    assert step2.status_code == 200
    flagged = [i for i in client.get("/api/admin/access-review").json()["items"] if i["flagged"]]
    assert [(i["username"], i["document_name"]) for i in flagged] == [("ravi", "Q3 services contract - Acme Corp")]
    assert client.get("/api/admin/audit/verify").json()["ok"] is True
    viewer = client.post("/api/auth/login", json={"username": "viewer", "password": "Reader!Vault2026"}).json()
    assert "csrf_token" in viewer                              # viewers: password only


def test_every_seed_document_has_a_valid_label_and_all_three_are_used():
    from trustvault.classification import LABELS
    seed = _seed_module()
    names = {name for _, _, name, *_ in seed.DOCUMENTS}
    assert set(seed.SEED_LABELS) == names
    assert set(seed.SEED_LABELS.values()) == set(LABELS)
