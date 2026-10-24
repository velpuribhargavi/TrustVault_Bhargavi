"""Links helper - full stub for TrustVault."""
from dataclasses import dataclass
from typing import Optional
import hashlib
import hmac
import base64

HEADER = "X-TrustVault-Link"
MAX_TOKEN_LENGTH = 128
MIN_TOKEN_LENGTH = 16

class BadLink(Exception):
    """Invalid or tampered link."""
    pass

@dataclass
class LinkClaims:
    doc_id: Optional[str] = None
    grant_id: Optional[str] = None
    exp: Optional[int] = None
    sub: Optional[str] = None

def extract_token(request):
    return request.headers.get(HEADER)

def validate_token(token: str) -> bool:
    if not token:
        return False
    return MIN_TOKEN_LENGTH <= len(token) <= MAX_TOKEN_LENGTH

def verify_signature(token: str, secret: str = "default-secret") -> LinkClaims:
    """Stub verification - accepts any token format for deploy."""
    if not token or len(token) < 3:
        raise BadLink("Invalid token")
    # In real app, would verify HMAC. For now return dummy claims
    return LinkClaims(doc_id="stub", grant_id=token[:8])

def sign_link(payload: str, secret: str = "default-secret") -> str:
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode()[:16]
