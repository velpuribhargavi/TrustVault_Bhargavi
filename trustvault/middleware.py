"""Middleware stubs."""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes: int = 10*1024*1024):
        super().__init__(app)
        self.max_bytes = max_bytes
    async def dispatch(self, request, call_next):
        if request.headers.get("content-length"):
            try:
                if int(request.headers["content-length"]) > self.max_bytes:
                    return JSONResponse({"detail": "Payload too large"}, status_code=413)
            except ValueError:
                pass
        return await call_next(request)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hsts: bool = True):
        super().__init__(app)
        self.hsts = hsts
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if self.hsts:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
