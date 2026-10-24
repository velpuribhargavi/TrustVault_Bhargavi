"""HTTP errors that carry a machine-readable ``code`` next to the message.

The UI uses the code to decide what to show (the "no access" page, the
"session expired" sign-in) without parsing English text.
"""
from __future__ import annotations

from fastapi import HTTPException

# The single answer to every refused file request. It is the same whether the
# document does not exist, was never shared, was revoked, has expired, is in
# the trash, or the level is too low - the real reason goes to the audit trail
# only, so probing reveals nothing.
NO_ACCESS_MESSAGE = "You don't have access to this file."
SESSION_EXPIRED_MESSAGE = "Your session has expired. Please sign in again."


class CodedHTTPException(HTTPException):
    def __init__(self, status_code: int, detail: str, code: str, headers: dict | None = None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


def no_access() -> CodedHTTPException:
    return CodedHTTPException(403, NO_ACCESS_MESSAGE, "no_access")


def session_expired() -> CodedHTTPException:
    return CodedHTTPException(401, SESSION_EXPIRED_MESSAGE, "session_expired")
