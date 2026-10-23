"""Request bodies. ``extra='forbid'`` everywhere: a client cannot smuggle
fields such as ``owner_id`` or ``role`` into a request (mass assignment)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)


class LoginRequest(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    mode: Literal["cookie", "bearer"] = "cookie"


class LogoutRequest(Strict):
    """Sent by the browser when its own idle / end-of-day timer signs the user out."""
    reason: Optional[Literal["idle", "max_lifetime"]] = None


class TwoFactorLoginRequest(Strict):
    """Second step of signing in: the challenge from /login and a code."""
    challenge: str = Field(min_length=10, max_length=128)
    code: str = Field(min_length=6, max_length=32)


class PasswordConfirmRequest(Strict):
    password: str = Field(min_length=1, max_length=256)


class CodeRequest(Strict):
    code: str = Field(min_length=6, max_length=32)


class DisableTwoFactorRequest(Strict):
    password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=32)


class BulkRevokeRequest(Strict):
    grant_ids: list[str] = Field(min_length=1, max_length=500)


class ChangePasswordRequest(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class DocumentUpdate(Strict):
    name: Optional[str] = Field(default=None, max_length=300)
    category: Optional[str] = Field(default=None, max_length=40)
    description: Optional[str] = Field(default=None, max_length=2000)


# Upper bound for any duration field; the real limit (MAX_GRANT_DAYS) is
# checked in the endpoint so it can be configured.
_MAX_MINUTES = 366 * 24 * 60


class GrantRequest(Strict):
    """Give (or change) one person's access. Every grant expires: send either
    ``duration_minutes`` or an absolute ``expires_at``; with neither, the
    grant lasts DEFAULT_GRANT_MINUTES (config.py)."""
    username: str = Field(min_length=1, max_length=64)
    # Without a level: View only (least privilege; the rule for Confidential documents).
    permission: Optional[Literal["view", "download", "edit"]] = None
    duration_minutes: Optional[int] = Field(default=None, ge=1, le=_MAX_MINUTES)
    expires_at: Optional[datetime] = None
    suggestion_id: Optional[str] = Field(default=None, max_length=64)


class ClassificationRequest(Strict):
    classification: Literal["public", "internal", "confidential"]


class AccessRequestCreate(Strict):
    """Ask a document's owner for access. ``document_id`` comes from a link or
    the 'no access' page; the answer is the same whether or not it exists."""
    document_id: str = Field(min_length=1, max_length=64)
    permission: Literal["view", "download", "edit"] = "view"
    note: str = Field(default="", max_length=500)


class ApproveRequest(Strict):
    """The owner's decision: level and duration (defaults: the requested level,
    or View only for a Confidential document; 30 minutes, or 1 hour if Confidential)."""
    permission: Optional[Literal["view", "download", "edit"]] = None
    duration_minutes: Optional[int] = Field(default=None, ge=1, le=_MAX_MINUTES)
    expires_at: Optional[datetime] = None


class DenyRequest(Strict):
    reason: str = Field(default="", max_length=300)


class ExtendGrantRequest(Strict):
    """Add time to a grant (counted from its expiry, or from now if it already ran out)."""
    minutes: int = Field(ge=1, le=_MAX_MINUTES)


class LinkRequest(Strict):
    """A 5-minute share link for one named person."""
    username: str = Field(min_length=1, max_length=64)
    permission: Literal["view", "download"] = "view"


class LinkOpenRequest(Strict):
    token: str = Field(min_length=10, max_length=1024)


class CreateUserRequest(Strict):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9._-]+$")
    display_name: str = Field(min_length=1, max_length=80)
    role: Literal["admin", "owner", "viewer"]
    password: str = Field(min_length=1, max_length=256)
    is_external: bool = False


class UpdateUserRequest(Strict):
    display_name: Optional[str] = Field(default=None, min_length=1, max_length=80)
    role: Optional[Literal["admin", "owner", "viewer"]] = None
    is_active: Optional[bool] = None
    is_external: Optional[bool] = None


class ResetPasswordRequest(Strict):
    new_password: str = Field(min_length=1, max_length=256)
