"""FastAPI application for the Kyros SOC web interface."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from kyros.database import list_analyses, save_analysis
from kyros.soc import MAX_FILE_SIZE, analyze_file, classify_domain, classify_ip

STATIC_DIR = Path(__file__).parent / "static"
security = HTTPBasic(auto_error=False)


def require_auth(\n    request: Request, credentials: HTTPBasicCredentials | None = Depends(security)\n) -> str:
    """Require configured HTTP Basic credentials for every application route."""
    expected_user = os.getenv("KYROS_AUTH_USERNAME", "")
    expected_password = os.getenv("KYROS_AUTH_PASSWORD", "")
    if not expected_user or len(expected_password) < 16:
        raise HTTPException(
            status_code=503,
            detail="La autenticación no está configurada correctamente.",
        )
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Autenticación requerida.",
            headers={"WWW-Authenticate": 'Basic realm="Kyros SOC", charset="UTF-8"'},
        )
    user_ok = secrets.compare_digest(credentials.username, expected_user)
    password_ok = secrets.compare_digest(credentials.password, expected_password)
    if not (user_ok and password_ok):
        raise HTTPException(
            status_code=401,
            detail="Credenciales incorrectas.",
            headers={"WWW-Authenticate": 'Basic realm="Kyros SOC", charset="UTF-8"'},
        )
    return credentials.username


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


is_production = os.getenv("KYROS_ENV", "development").lower() == "production"
app = FastAPI(
    title="Kyros SOC API",
    version="0.3.0",
    description="Defensive triage API. External lookups are disabled.",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
)
app.add_middleware(SecurityHeadersMiddleware)


class IndicatorRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=253)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Kyros SOC", "version": "0.3.0"}


@app.post("/api/analyze/ip", dependencies=[Depends(require_auth)])
async def analyze_ip(request: IndicatorRequest):
    try:
        result = classify_ip(request.indicator)
        result["history_id"] = save_analysis("ip", result["indicator"], result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/analyze/domain", dependencies=[Depends(require_auth)])
async def analyze_domain(request: IndicatorRequest):
    try:
        result = classify_domain(request.indicator)
        result["history_id"] = save_analysis("domain", result["indicator"], result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/analyze/file", dependencies=[Depends(require_auth)])
async def analyze_uploaded_file(file: UploadFile = File(...)):
    data = await file.read(MAX_FILE_SIZE + 1)
    await file.close()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="El tamaño máximo permitido es 10 MB.")
    try:
        result = analyze_file(data, file.filename)
        result["history_id"] = save_analysis("file", result["hashes"]["sha256"], result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/history", dependencies=[Depends(require_auth)])
async def history(limit: int = 50):
    return {"items": list_analyses(limit)}


@app.get("/", include_in_schema=False, dependencies=[Depends(require_auth)])
async def dashboard():
    index = STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Dashboard no disponible.")
    return FileResponse(index)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "kyros.web:app",
        host=os.getenv("KYROS_HOST", "127.0.0.1"),
        port=int(os.getenv("KYROS_PORT", "8000")),
        reload=False,
    )
