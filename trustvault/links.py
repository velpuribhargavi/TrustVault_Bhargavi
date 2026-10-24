"""Links helper - full stub for TrustVault."""
from dataclasses import dataclass
from typing import Optional, Dict, Any
import hashlib
import hmac
import base64
import time
import json

HEADER = "X-TrustVault-Link"
MAX_TOKEN_LENGTH = 128
MIN_TOKEN_LENGTH = 16

class BadLink(Exception):
    pass

@dataclass
class LinkClaims:
    doc_id: Optional[str] = None
    grant_id: Optional[str] = None
    exp: Optional[int] = None
    sub: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

def extract_token(request):
    return request.headers.get(HEADER)

def validate_token(token: str) -> bool:
    if not token:
        return False
    return MIN_TOKEN_LENGTH <= len(token) <= MAX_TOKEN_LENGTH

def verify_signature(token: str, secret: str = "default-secret") -> LinkClaims:
    if not token or len(token) < 3:
        raise BadLink("Invalid token")
    try:
        # Try decode if it's base64 json (stub)
        padded = token + "=" * (-len(token) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        return LinkClaims(**data)
    except Exception:
        return LinkClaims(doc_id="stub", grant_id=token[:8], exp=int(time.time())+3600)

def issue(claims: Dict[str, Any] = None, secret: str = "default-secret", expires_in: int = 3600) -> str:
    """Issue a new link token - stub."""
    if claims is None:
        claims = {}
    claims["exp"] = int(time.time()) + expires_in
    payload = json.dumps(claims).encode()
    b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    # Simple signature suffix
    sig = hmac.new(secret.encode(), b64.encode(), hashlib.sha256).hexdigest()[:8]
    return f"{b64}.{sig}"

def sign_link(payload: str, secret: str = "default-secret") -> str:
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode()[:16]
