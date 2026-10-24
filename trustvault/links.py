"""Links helper - complete stub."""

HEADER = "X-TrustVault-Link"
MAX_TOKEN_LENGTH = 128
MIN_TOKEN_LENGTH = 16

def extract_token(request):
    return request.headers.get(HEADER)

def validate_token(token: str) -> bool:
    if not token:
        return False
    return MIN_TOKEN_LENGTH <= len(token) <= MAX_TOKEN_LENGTH
