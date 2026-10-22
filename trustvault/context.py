"""Application-wide services, created once per app instance."""
from __future__ import annotations

from dataclasses import dataclass

from .audit import AuditLog
from .config import Settings
from .crypto import KeyRing
from .preview import OfficeRenderer
from .security import Passwords, RateLimiter
from .storage import BlobStore


@dataclass
class AppContext:
    settings: Settings
    keyring: KeyRing
    audit: AuditLog
    blobs: BlobStore
    passwords: Passwords
    limiter: RateLimiter
    office: OfficeRenderer
    last_expiry_sweep: float = 0.0  # see deps.maybe_log_expired_grants

    @classmethod
    def build(cls, settings: Settings, create_keys: bool = False) -> "AppContext":
        keyring = KeyRing.load(settings.keys_dir, create=create_keys)
        return cls(
            settings=settings,
            keyring=keyring,
            audit=AuditLog(keyring, settings.anchor_path, durable=settings.durable_writes),
            blobs=BlobStore(settings.blob_dir, durable=settings.durable_writes),
            passwords=Passwords(settings),
            limiter=RateLimiter(),
            office=OfficeRenderer.from_settings(settings),
        )
