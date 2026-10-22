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
