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


class ChangePasswordRequest(Strict):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class DocumentUpdate(Strict):
    name: Optional[str] = Field(default=None, max_length=300)
    category: Optional[str] = Field(default=None, max_length=40)
    description: Optional[str] = Field(default=None, max_length=2000)


class GrantRequest(Strict):
    username: str = Field(min_length=1, max_length=64)
    permission: Literal["view", "download", "edit"]
    expires_at: Optional[datetime] = None
    suggestion_id: Optional[str] = Field(default=None, max_length=64)


class ShareLinkRequest(Strict):
    expires_in_hours: int = Field(ge=1, le=24 * 365)
    max_uses: int = Field(ge=1, le=10_000)
    label: str = Field(default="", max_length=100)


class ShareTokenRequest(Strict):
    token: str = Field(min_length=10, max_length=128)


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
