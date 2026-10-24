"""Share links: signed, 5-minute, for one named person.

A link is a capability token that the server can check without storing it:

    v1.<base64url(JSON claims)>.<base64url(HMAC-SHA256(link_key, "v1." + claims))>

Claims
    d    document id
    r    recipient user id   - the link only works while signed in as this person
    c    creator user id     - must still be the active owner of the document
    p    "view" or "download" (links never give edit)
    av   the document's access_version when the link was made
    iat  issued at (unix seconds)
    exp  expiry (unix seconds) = iat + LINK_TTL_SECONDS
    jti  random link id, for the audit trail

Why each check exists (they run inside ``authz.check_access``, in order):
    signature   - nobody can forge or edit a link (e.g. change "view" to "edit")
    document    - a link for one document cannot open another
    recipient   - a forwarded link is useless to anyone else, even signed in
    expiry      - 5 minutes, from config.LINK_TTL_SECONDS
    version     - revoking access or "revoke all links" bumps access_version,
                  so a link dies at once, not after 5 minutes
    creator     - a link dies when its creator stops being the active owner

Links live in the URL fragment (#/l/<token>), which browsers never send to the
server, and are sent back in an X-Link-Token header, never in a query string,
so they stay out of access logs and Referer headers.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import secrets
from dataclasses import dataclass

from .crypto import KeyRing

PREFIX = "v1"
LINK_LEVELS = ("view", "download")
MAX_TOKEN_LENGTH = 1024
HEADER = "X-Link-Token"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@dataclass(frozen=True)
class LinkClaims:
    document_id: str
    recipient_id: str
    creator_id: str
    permission: str
    access_version: int
    issued_at: int
    expires_at: int
    link_id: str


class BadLink(Exception):
    """The token is not a well-formed link carrying a valid signature."""


def issue(keyring: KeyRing, *, document_id: str, recipient_id: str, creator_id: str, permission: str,
          access_version: int, now_ts: int, ttl_seconds: int) -> tuple[str, LinkClaims]:
    if permission not in LINK_LEVELS:
        raise ValueError("links give view or download access only")
    claims = LinkClaims(document_id, recipient_id, creator_id, permission, int(access_version), int(now_ts),
                        int(now_ts) + int(ttl_seconds), secrets.token_urlsafe(12))
    body = _b64(json.dumps({"d": claims.document_id, "r": claims.recipient_id, "c": claims.creator_id,
                            "p": claims.permission, "av": claims.access_version, "iat": claims.issued_at,
                            "exp": claims.expires_at, "jti": claims.link_id},
                           separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signed = f"{PREFIX}.{body}"
    return f"{signed}.{_b64(keyring.link_mac(signed.encode('ascii')))}", claims


def verify_signature(keyring: KeyRing, token: str) -> LinkClaims:
    """Return the claims of a correctly signed token or raise BadLink.

    Only the signature and the shape are checked here; whether the link is
    still valid for *this* person, document and moment is decided by
    ``authz.check_access``.
    """
    if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH or token.count(".") != 2:
        raise BadLink("malformed")
    prefix, body, sig = token.split(".")
    if prefix != PREFIX:
        raise BadLink("unknown version")
    try:
        given = _unb64(sig)
    except (binascii.Error, ValueError) as exc:
        raise BadLink("malformed") from exc
    expected = keyring.link_mac(f"{prefix}.{body}".encode("ascii", errors="replace"))
    if not hmac.compare_digest(given, expected):  # AUTHZ-CHECK[link-signature-valid]
        raise BadLink("bad signature")
    try:
        raw = json.loads(_unb64(body))
        claims = LinkClaims(str(raw["d"]), str(raw["r"]), str(raw["c"]), str(raw["p"]), int(raw["av"]),
                            int(raw["iat"]), int(raw["exp"]), str(raw["jti"]))
    except (binascii.Error, ValueError, KeyError, TypeError) as exc:  # pragma: no cover - signed by us
        raise BadLink("malformed claims") from exc
    if claims.permission not in LINK_LEVELS:  # pragma: no cover - signed by us
        raise BadLink("bad level")
    return claims
