from fastapi import HTTPException
class CodedHTTPException(HTTPException):
    def __init__(self, status_code: int, detail: str, code: str):
        super().__init__(status_code=status_code, detail=detail)
        self.code = code
def session_expired():
    raise CodedHTTPException(status_code=401, detail="Session expired", code="session_expired")
def no_access():
    raise CodedHTTPException(status_code=403, detail="No access", code="no_access")
