"""Links helper - minimal stub."""
HEADER = "X-TrustVault-Link"

def extract_token(request):
    """Extract link token from header if present."""
    return request.headers.get(HEADER)
