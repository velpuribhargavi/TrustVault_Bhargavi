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

    # Sessions: idle timeout and absolute lifetime.
    session_idle_minutes: int = field(default_factory=lambda: int(_env("SESSION_IDLE_MINUTES", "30")))
    session_absolute_hours: int = field(default_factory=lambda: int(_env("SESSION_ABSOLUTE_HOURS", "8")))

    # Cookies. Set TRUSTVAULT_COOKIE_SECURE=1 whenever the app is served over HTTPS.
    cookie_secure: bool = field(default_factory=lambda: _env_bool("COOKIE_SECURE", False))

    # Brute-force protection.
    login_max_failures: int = field(default_factory=lambda: int(_env("LOGIN_MAX_FAILURES", "5")))
    lockout_minutes: int = field(default_factory=lambda: int(_env("LOCKOUT_MINUTES", "15")))
    login_rate_per_ip_per_minute: int = field(default_factory=lambda: int(_env("LOGIN_RATE_PER_MINUTE", "20")))
    public_rate_per_ip_per_minute: int = field(default_factory=lambda: int(_env("PUBLIC_RATE_PER_MINUTE", "30")))

    # External share links.
    share_link_max_hours: int = field(default_factory=lambda: int(_env("SHARE_LINK_MAX_HOURS", "168")))
    share_link_max_uses: int = field(default_factory=lambda: int(_env("SHARE_LINK_MAX_USES", "50")))

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
