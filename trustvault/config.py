"""Runtime configuration.

Every setting can be overridden with an environment variable prefixed with
``TRUSTVAULT_`` (for example ``TRUSTVAULT_MAX_UPLOAD_MB=20``). Secrets (the
master encryption key and the audit HMAC key) are never stored in this file:
they come from environment variables or from key files that ``init_db.py``
generates inside the instance directory.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Time limits - the ONE place they are defined. Everything else (the access
# check, the session check, the grant and link endpoints, the UI via
# /api/meta and the tests) reads these values; nothing hard-codes a duration.
# Each can be overridden with TRUSTVAULT_<NAME> (e.g. TRUSTVAULT_LINK_TTL_SECONDS).
# ---------------------------------------------------------------------------
LINK_TTL_SECONDS = 300          # a share link works for 5 minutes, for one named person
DEFAULT_GRANT_MINUTES = 30      # access granted without a chosen duration lasts 30 minutes
SESSION_IDLE_MINUTES = 15       # signed out after 15 minutes without a request
SESSION_MAX_HOURS = 8           # signed out 8 hours after sign-in, whatever happens
MAX_GRANT_DAYS = 366            # the longest duration an owner may pick for a grant
SESSION_WARNING_SECONDS = 60    # the UI warns one minute before an idle sign-out
TWO_FACTOR_CHALLENGE_SECONDS = 300  # after the password, the 6-digit code must follow within 5 minutes
UNUSED_GRANT_DAYS = 30          # access review flags grants nobody has used for 30 days
CONFIDENTIAL_GRANT_MINUTES = 60 # access to a Confidential document defaults to 1 hour (and View only)
ACCESS_REQUEST_DAYS = 14        # an unanswered request for access lapses after 14 days
MAX_PENDING_REQUESTS = 20       # open requests one person may have at a time

# Roles that must use two-step sign-in (TOTP). Override with
# TRUSTVAULT_TOTP_REQUIRED_ROLES="admin,owner" (or "" to make it optional for everyone).
TOTP_REQUIRED_ROLES = ("admin", "owner")
TWO_FACTOR_MAX_ATTEMPTS = 3     # wrong codes per sign-in attempt before the password is asked again


def _env(name: str, default: str) -> str:
    return os.environ.get(f"TRUSTVAULT_{name}", default)


def _env_bool(name: str, default: bool) -> bool:
    return _env(name, "1" if default else "0").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # Where all mutable state lives (database, encrypted blobs, keys, anchors).
    instance_dir: Path = field(default_factory=lambda: Path(_env("INSTANCE_DIR", str(PROJECT_ROOT / "instance"))))

    # Upload limits.
    max_upload_bytes: int = field(default_factory=lambda: int(float(_env("MAX_UPLOAD_MB", "10")) * 1024 * 1024))

    # Sessions: idle timeout and absolute lifetime (see the constants above).
    session_idle_minutes: int = field(
        default_factory=lambda: int(_env("SESSION_IDLE_MINUTES", str(SESSION_IDLE_MINUTES))))
    session_absolute_hours: int = field(default_factory=lambda: int(_env("SESSION_MAX_HOURS", str(SESSION_MAX_HOURS))))
    session_warning_seconds: int = field(
        default_factory=lambda: int(_env("SESSION_WARNING_SECONDS", str(SESSION_WARNING_SECONDS))))

    # Access lifetimes (see the constants above).
    link_ttl_seconds: int = field(default_factory=lambda: int(_env("LINK_TTL_SECONDS", str(LINK_TTL_SECONDS))))
    default_grant_minutes: int = field(
        default_factory=lambda: int(_env("DEFAULT_GRANT_MINUTES", str(DEFAULT_GRANT_MINUTES))))
    max_grant_days: int = field(default_factory=lambda: int(_env("MAX_GRANT_DAYS", str(MAX_GRANT_DAYS))))

    # Cookies. Set TRUSTVAULT_COOKIE_SECURE=1 whenever the app is served over HTTPS.
    cookie_secure: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))

    # Two-step sign-in and access review (see the constants above).
    totp_required_roles: tuple = field(default_factory=lambda: tuple(
        r.strip() for r in _env("TOTP_REQUIRED_ROLES", ",".join(TOTP_REQUIRED_ROLES)).split(",") if r.strip()))
    two_factor_challenge_seconds: int = field(
        default_factory=lambda: int(_env("TWO_FACTOR_CHALLENGE_SECONDS", str(TWO_FACTOR_CHALLENGE_SECONDS))))
    unused_grant_days: int = field(default_factory=lambda: int(_env("UNUSED_GRANT_DAYS", str(UNUSED_GRANT_DAYS))))
    confidential_grant_minutes: int = field(
        default_factory=lambda: int(_env("CONFIDENTIAL_GRANT_MINUTES", str(CONFIDENTIAL_GRANT_MINUTES))))
    access_request_days: int = field(default_factory=lambda: int(_env("ACCESS_REQUEST_DAYS", str(ACCESS_REQUEST_DAYS))))
    max_pending_requests: int = field(
        default_factory=lambda: int(_env("MAX_PENDING_REQUESTS", str(MAX_PENDING_REQUESTS))))

    # Brute-force protection.
    login_max_failures: int = field(default_factory=lambda: int(_env("LOGIN_MAX_FAILURES", "5")))
    lockout_minutes: int = field(default_factory=lambda: int(_env("LOCKOUT_MINUTES", "15")))
    login_rate_per_ip_per_minute: int = field(default_factory=lambda: int(_env("LOGIN_RATE_PER_MINUTE", "20")))
    # Opening share links: refused attempts per user per minute before 429.
    link_rate_per_user_per_minute: int = field(default_factory=lambda: int(_env("LINK_RATE_PER_MINUTE", "30")))

    # View-only rendering of Word / PowerPoint / Excel files as page images.
    # "auto" = use LibreOffice when it is installed, otherwise show extracted
    # text; "off" = always text; anything else = path to soffice(.exe).
    office_renderer: str = field(default_factory=lambda: _env("OFFICE_RENDERER", "auto"))
    office_render_timeout_seconds: int = field(default_factory=lambda: int(_env("OFFICE_RENDER_TIMEOUT", "60")))

    # Audit CSV export: the most events one export may contain. A larger
    # selection is refused (and the refusal logged) rather than cut short.
    audit_export_max_rows: int = field(default_factory=lambda: int(_env("AUDIT_EXPORT_MAX_ROWS", "100000")))

    # Trash retention before a deleted document is crypto-shredded automatically.
    trash_retention_days: int = field(default_factory=lambda: int(_env("TRASH_RETENTION_DAYS", "30")))

    # Only trust X-Forwarded-For when the app really sits behind a proxy you control.
    trust_proxy: bool = field(default_factory=lambda: _env_bool("TRUST_PROXY", False))

    # fsync every commit, blob and audit anchor. Only the test suite turns this
    # off (fsync can cost >100 ms per call on slow or virtual disks).
    durable_writes: bool = field(default_factory=lambda: _env_bool("DURABLE_WRITES", True))

    # Interactive API docs at /api/docs.
    enable_api_docs: bool = field(default_factory=lambda: _env_bool("ENABLE_API_DOCS", True))

    # Argon2id cost. Defaults follow OWASP guidance; tests lower them for speed.
    argon2_time_cost: int = field(default_factory=lambda: int(_env("ARGON2_TIME_COST", "3")))
    argon2_memory_kib: int = field(default_factory=lambda: int(_env("ARGON2_MEMORY_KIB", "65536")))
    argon2_parallelism: int = field(default_factory=lambda: int(_env("ARGON2_PARALLELISM", "2")))

    @property
    def db_path(self) -> Path:
        return self.instance_dir / "trustvault.db"

    @property
    def blob_dir(self) -> Path:
        return self.instance_dir / "blobs"

    @property
    def keys_dir(self) -> Path:
        return self.instance_dir / "keys"

    @property
    def anchor_path(self) -> Path:
        # In production this file would be shipped to write-once storage or a
        # separate log server; locally it simply lives outside the database.
        return self.instance_dir / "audit_anchors.log"

    def with_overrides(self, **kwargs) -> "Settings":
        return replace(self, **kwargs)


def load_settings() -> Settings:
    return Settings()
