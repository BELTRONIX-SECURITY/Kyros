"""FastAPI application for the Kyros SOC web interface."""
from __future__ import annotations

import asyncio
import csv
import io
import os
import secrets
from pathlib import Path
from typing import Literal

import httpx
import dns.resolver
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from kyros.database import (
    add_security_event, add_threat_indicator, correlate_security_events, create_incident,
    dashboard_summary, list_analyses, list_incidents, list_security_events, list_threat_indicators,
    save_analysis, update_incident_status,
)
from kyros.soc import MAX_FILE_SIZE, analyze_file, classify_domain, classify_email, classify_ip, scan_yara

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



def lookup_domain_dns(domain: str) -> dict:
    """Query DNS records only after explicit user opt-in."""
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 2.5
    records: dict[str, list[str]] = {}
    queries = (("A", domain), ("AAAA", domain), ("MX", domain),
               ("TXT", domain), ("DMARC", f"_dmarc.{domain}"))
    for record_type, query_name in queries:
        query_type = "TXT" if record_type == "DMARC" else record_type
        try:
            answer = resolver.resolve(query_name, query_type)
            values = [str(item) for item in answer][:20]
            if values:
                records[record_type] = values
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
                dns.exception.Timeout):
            continue
    return {"status": "ok" if records else "no_records", "records": records}


async def lookup_ip_external(ip: str) -> list[dict]:
    """Query fixed provider endpoints; never accept a caller-supplied URL."""
    timeout = httpx.Timeout(5.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return list(await asyncio.gather(_fetch_ipapi(client, ip), _fetch_freeipapi(client, ip)))


is_production = os.getenv("KYROS_ENV", "development").lower() == "production"
app = FastAPI(
    title="Kyros SOC API", version="0.6.0",
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


class ThreatIndicatorCreate(BaseModel):
    indicator_type: Literal["ip", "domain", "email", "sha256"]
    indicator: str = Field(min_length=3, max_length=253)
    confidence: int = Field(ge=0, le=100)
    source: str = Field(min_length=2, max_length=100)
    description: str = Field(default="", max_length=1000)


class SecurityEventCreate(BaseModel):
    source: str = Field(min_length=2, max_length=100)
    event_type: str = Field(min_length=2, max_length=100)
    indicator: str = Field(min_length=3, max_length=253)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    details: str = Field(default="", max_length=2000)


class IncidentUpdate(BaseModel):
    status: Literal["open", "acknowledged", "closed"]


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Kyros SOC", "version": "0.6.0"}


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
            result["external_lookup"] = True
            result["dns"] = await asyncio.to_thread(lookup_domain_dns, result["indicator"])
            result["external_lookup_note"] = (
                "Se consultó el DNS configurado para A, AAAA, MX, TXT y DMARC. "
                "La consulta revela el dominio al resolvedor DNS; no constituye una evaluación de reputación."
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
        result["yara"] = scan_yara(data)
        result["history_id"] = save_analysis("file", result["hashes"]["sha256"], result)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/history", dependencies=[Depends(require_auth)])
async def history(limit: int = 50):
    return {"items": list_analyses(limit)}


@app.get("/api/threat-intel/indicators", dependencies=[Depends(require_auth)])
async def threat_indicators(limit: int = 100):
    return {"items": list_threat_indicators(limit)}


@app.post("/api/threat-intel/indicators", dependencies=[Depends(require_auth)])
async def add_threat_intel(request: ThreatIndicatorCreate):
    value = request.indicator.strip()
    try:
        if request.indicator_type == "ip":
            value = classify_ip(value)["indicator"]
        elif request.indicator_type == "domain":
            value = classify_domain(value)["indicator"]
        elif request.indicator_type == "email":
            value = classify_email(value)["indicator"]
        elif request.indicator_type == "sha256":
            import re
            if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                raise ValueError("El SHA-256 debe contener exactamente 64 caracteres hexadecimales.")
            value = value.lower()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    item_id = add_threat_indicator(request.indicator_type, value, request.confidence, request.source, request.description)
    return {"id": item_id, "indicator": value, "stored_locally": True}



@app.post("/api/threat-intel/import", dependencies=[Depends(require_auth)])
async def import_threat_intel_csv(file: UploadFile = File(...)):
    raw = await file.read(1024 * 1024 + 1)
    await file.close()
    if len(raw) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="El CSV supera el límite de 1 MB.")
    try:
        text = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail="El CSV debe estar codificado en UTF-8.") from exc
    required = {"indicator_type", "indicator"}
    if not reader.fieldnames or not required.issubset(set(reader.fieldnames)):
        raise HTTPException(status_code=422, detail="El CSV requiere columnas indicator_type e indicator.")
    imported = 0
    errors = []
    for row_number, row in enumerate(reader, start=2):
        if row_number > 5001:
            errors.append("Se alcanzó el máximo de 5000 filas.")
            break
        kind = (row.get("indicator_type") or "").strip().lower()
        value = (row.get("indicator") or "").strip()
        try:
            if kind == "ip":
                value = classify_ip(value)["indicator"]
            elif kind == "domain":
                value = classify_domain(value)["indicator"]
            elif kind == "email":
                value = classify_email(value)["indicator"]
            elif kind == "sha256":
                import re
                if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
                    raise ValueError("SHA-256 no válido.")
                value = value.lower()
            else:
                raise ValueError("Tipo no admitido.")
            confidence = int((row.get("confidence") or "50").strip())
            if not 0 <= confidence <= 100:
                raise ValueError("Confianza fuera del rango 0-100.")
            add_threat_indicator(
                kind, value, confidence,
                (row.get("source") or "csv-import").strip()[:100],
                (row.get("description") or "").strip()[:1000],
            )
            imported += 1
        except (ValueError, TypeError) as exc:
            errors.append(f"Fila {row_number}: {str(exc)[:180]}")
    return {"imported": imported, "errors": errors[:100],
            "stored_locally": True, "external_submission": False}


@app.post("/api/events", dependencies=[Depends(require_auth)])
async def ingest_security_event(request: SecurityEventCreate):
    event_id = add_security_event(request.source, request.event_type, request.indicator.strip(), request.severity, request.details)
    return {"id": event_id, "status": "recorded_locally"}


@app.get("/api/events", dependencies=[Depends(require_auth)])
async def security_events(limit: int = 100):
    return {"items": list_security_events(limit)}


@app.get("/api/correlation", dependencies=[Depends(require_auth)])
async def event_correlation(limit: int = 100):
    return {"items": correlate_security_events(limit),
            "note": "Las coincidencias IOC son pistas para investigación, no confirmaciones de incidente."}


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
