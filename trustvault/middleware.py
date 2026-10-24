from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, max_bytes=10485760):
        super().__init__(app)
        self.max_bytes = max_bytes
    async def dispatch(self, request, call_next):
        return await call_next(request)

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, hsts=True):
        super().__init__(app)
        self.hsts = hsts
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
