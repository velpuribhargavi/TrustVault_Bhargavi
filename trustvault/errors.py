from fastapi import HTTPException

def session_expired():
    raise HTTPException(status_code=401, detail="Session expired")

def unauthorized(detail="Unauthorized"):
    raise HTTPException(status_code=401, detail=detail)

def forbidden(detail="Forbidden"):
    raise HTTPException(status_code=403, detail=detail)

def not_found(detail="Not found"):
    raise HTTPException(status_code=404, detail=detail)
