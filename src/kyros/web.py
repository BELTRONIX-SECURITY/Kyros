"""FastAPI application for the Kyros SOC web interface."""
from __future__ import annotations

import asyncio
import os
import secrets
from pathlib import Path
from typing import Literal

import httpx
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from kyros.database import (
    create_incident, dashboard_summary, list_analyses, list_incidents,
    save_analysis, update_incident_status,
)
from kyros.soc import MAX_FILE_SIZE, analyze_file, classify_domain, classify_email, classify_ip

STATIC_DIR = Path(__file__).parent / "static"
security = HTTPBasic(auto_error=False)


def require_auth(
    request: Request, credentials: HTTPBasicCredentials | None = Depends(security)
) -> str:
    """Require configured HTTP Basic credentials and reject cross-origin form posts."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.headers.get("x-kyros-request") != "1":
            raise HTTPException(status_code=403, detail="Solicitud de origen no validada.")
    expected_user = os.getenv("KYROS_AUTH_USERNAME", "")
    expected_password = os.getenv("KYROS_AUTH_PASSWORD", "")
    if not expected_user or len(expected_password) < 16:
        raise HTTPException(status_code=503, detail="La autenticación no está configurada correctamente.")
    if credentials is None:
        raise HTTPException(
            status_code=401, detail="Autenticación requerida.",
            headers={"WWW-Authenticate": 'Basic realm="Kyros SOC", charset="UTF-8"'},
        )
    user_ok = secrets.compare_digest(credentials.username, expected_user)
    password_ok = secrets.compare_digest(credentials.password, expected_password)
    if not (user_ok and password_ok):
        raise HTTPException(
            status_code=401, detail="Credenciales incorrectas.",
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
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


async def _fetch_ipapi(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        response = await client.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code != 200:
            return {"provider": "ipapi.co", "status": "unavailable"}
        data = response.json()
        if data.get("error"):
            return {"provider": "ipapi.co", "status": "unavailable"}
        return {"provider": "ipapi.co", "status": "ok", "data": {
            key: data.get(key) for key in (
                "city", "region", "country_name", "country", "asn", "org",
                "latitude", "longitude", "timezone"
            ) if data.get(key) is not None
        }}
    except (httpx.HTTPError, ValueError):
        return {"provider": "ipapi.co", "status": "unavailable"}


async def _fetch_freeipapi(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        response = await client.get(f"https://free.freeipapi.com/api/v1/json/{ip}")
        if response.status_code != 200:
            return {"provider": "FreeIPAPI", "status": "unavailable"}
        data = response.json()
        return {"provider": "FreeIPAPI", "status": "ok", "data": {
            key: data.get(key) for key in (
                "countryName", "countryCode", "cityName", "regionName",
                "asn", "asnOrganization", "latitude", "longitude", "isProxy"
            ) if data.get(key) is not None
        }}
    except (httpx.HTTPError, ValueError):
        return {"provider": "FreeIPAPI", "status": "unavailable"}


async def lookup_ip_external(ip: str) -> list[dict]:
    """Query fixed provider endpoints; never accept a caller-supplied URL."""
    timeout = httpx.Timeout(5.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return list(await asyncio.gather(_fetch_ipapi(client, ip), _fetch_freeipapi(client, ip)))


is_production = os.getenv("KYROS_ENV", "development").lower() == "production"
app = FastAPI(
    title="Kyros SOC API", version="0.5.0",
    description="Defensive triage API. External IP lookups require explicit opt-in.",
    docs_url=None if is_production else "/docs",
    redoc_url=None if is_production else "/redoc",
    openapi_url=None if is_production else "/openapi.json",
)
app.add_middleware(SecurityHeadersMiddleware)


class IndicatorRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=253)
    external_lookup: bool = False


class IncidentCreate(BaseModel):
    title: str = Field(min_length=4, max_length=160)
    description: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    source: str = Field(default="manual", max_length=60)
    indicator: str = Field(default="", max_length=253)


class IncidentUpdate(BaseModel):
    status: Literal["open", "acknowledged", "closed"]


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Kyros SOC", "version": "0.5.0"}


@app.get("/api/dashboard/summary", dependencies=[Depends(require_auth)])
async def dashboard_metrics():
    return dashboard_summary()


@app.post("/api/analyze/ip", dependencies=[Depends(require_auth)])
async def analyze_ip(request: IndicatorRequest):
    try:
        result = classify_ip(request.indicator)
        if request.external_lookup:
            if result["scope"] != "public":
                result["external_lookup_note"] = "Consulta externa omitida: solo se consultan direcciones IP públicas."
            else:
                result["external_lookup"] = True
                result["external_sources"] = await lookup_ip_external(result["indicator"])
                result["external_lookup_note"] = (
                    "Se transmitió únicamente la IP a los proveedores indicados. Los datos de "
                    "geolocalización y ASN son aproximados y no constituyen reputación ni evidencia "
                    "de actividad maliciosa."
                )
        result["history_id"] = save_analysis("ip", result["indicator"], result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/analyze/domain", dependencies=[Depends(require_auth)])
async def analyze_domain(request: IndicatorRequest):
    try:
        result = classify_domain(request.indicator)
        if request.external_lookup:
            result["external_lookup_note"] = (
                "La consulta DNS externa aún no está habilitada en esta versión; no se transmitió el dominio."
            )
        result["history_id"] = save_analysis("domain", result["indicator"], result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/analyze/email", dependencies=[Depends(require_auth)])
async def analyze_email(request: IndicatorRequest):
    try:
        result = classify_email(request.indicator)
        result["history_id"] = save_analysis("email", result["indicator"], result)
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


@app.get("/api/incidents", dependencies=[Depends(require_auth)])
async def incidents(limit: int = 100):
    return {"items": list_incidents(limit)}


@app.post("/api/incidents", dependencies=[Depends(require_auth)])
async def add_incident(request: IncidentCreate):
    incident_id = create_incident(
        request.title, request.description, request.severity, request.source, request.indicator
    )
    return {"id": incident_id, "status": "open"}


@app.patch("/api/incidents/{incident_id}", dependencies=[Depends(require_auth)])
async def change_incident(incident_id: int, request: IncidentUpdate):
    if not update_incident_status(incident_id, request.status):
        raise HTTPException(status_code=404, detail="Incidente no encontrado.")
    return {"id": incident_id, "status": request.status}


@app.get("/", include_in_schema=False, dependencies=[Depends(require_auth)])
async def dashboard():
    index = STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Dashboard no disponible.")
    return FileResponse(index)


def run() -> None:
    import uvicorn
    uvicorn.run(
        "kyros.web:app", host=os.getenv("KYROS_HOST", "127.0.0.1"),
        port=int(os.getenv("KYROS_PORT", "8000")), reload=False,
    )
