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

from kyros.ai import MAX_AI_CONTEXT, ai_configuration, analyze_soc_context
from kyros.external_intel import build_assessment, lookup_available_sources, lookup_indicator, provider_status

from kyros.database import (
    add_incident_evidence, add_incident_timeline, add_security_event, add_threat_indicator,
    correlate_security_events, create_incident, dashboard_summary, get_incident_case,
    list_analyses, list_incidents, list_security_events, list_threat_indicators,
    save_analysis, update_incident_status,
)
from kyros.soc import (MAX_FILE_SIZE, analyze_file, classify_domain, classify_email, classify_ip,
                      extract_ioc_candidates, scan_yara)

STATIC_DIR = Path(__file__).parent / "static"
security = HTTPBasic(auto_error=False)


def require_auth(
    request: Request, credentials: HTTPBasicCredentials | None = Depends(security)
) -> str:
    """Require configured HTTP Basic credentials and reject cross-origin form posts."""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.headers.get("x-kyros-request") != "1":
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


class AIAnalysisRequest(BaseModel):
    context: str = Field(min_length=1, max_length=MAX_AI_CONTEXT)
    external_consent: bool = False


class IndicatorRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=253)
    external_lookup: bool = False


class ExternalIntelRequest(BaseModel):
    provider: Literal["auto", "virustotal", "abuseipdb", "otx"]
    indicator_type: Literal["ip", "domain", "sha256"]
    indicator: str = Field(min_length=3, max_length=253)
    external_consent: bool = False


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

class IncidentTimelineCreate(BaseModel):
    category: Literal["alert", "observation", "containment", "eradication", "recovery", "communication", "other"] = "observation"
    description: str = Field(min_length=3, max_length=2000)
    source: str = Field(default="manual", max_length=100)
    event_time: str = Field(default="", max_length=40)


class IncidentEvidenceCreate(BaseModel):
    evidence_type: Literal["log", "screenshot_reference", "file_hash", "event_id", "ticket", "other"] = "other"
    reference: str = Field(min_length=1, max_length=500)
    sha256: str = Field(default="", max_length=64)
    source: str = Field(default="manual", max_length=100)
    notes: str = Field(default="", max_length=2000)


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "Kyros SOC", "version": "0.6.0"}


@app.get("/api/ai/status", dependencies=[Depends(require_auth)])
async def ai_status():
    return ai_configuration()


@app.post("/api/ai/analyze", dependencies=[Depends(require_auth)])
async def ai_analyze(request: AIAnalysisRequest):
    if not request.external_consent:
        raise HTTPException(
            status_code=400,
            detail="Debes confirmar que autorizas enviar este texto al proveedor IA configurado.",
        )
    if not ai_configuration()["enabled"]:
        raise HTTPException(status_code=503, detail="El copiloto IA no está configurado.")
    try:
        return await analyze_soc_context(request.context)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="El proveedor IA no está disponible o rechazó la solicitud.") from exc


@app.get("/api/threat-intel/providers", dependencies=[Depends(require_auth)])
async def threat_intel_providers():
    return {"providers": provider_status(), "note": "Solo se consulta un indicador por solicitud; no se suben archivos."}


@app.post("/api/threat-intel/enrich", dependencies=[Depends(require_auth)])
async def enrich_threat_indicator(request: ExternalIntelRequest):
    if not request.external_consent:
        raise HTTPException(status_code=400, detail="Debes autorizar expresamente el envío del indicador al proveedor.")
    indicator = request.indicator.strip()
    if request.indicator_type == "ip":
        try:
            ip_result = classify_ip(indicator)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if ip_result.get("scope") != "public":
            raise HTTPException(status_code=422, detail="Solo se permite enriquecer IP públicas.")
    if request.indicator_type == "domain":
        try:
            classify_domain(indicator)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    try:
        if request.provider == "auto":
            result = await lookup_available_sources(request.indicator_type, indicator)
            return {"result": result, "assessment": result, "external_submission": True,
                    "submitted": {"type": request.indicator_type, "indicator": indicator},
                    "file_uploaded": False,
                    "note": "Se consultaron únicamente proveedores configurados y aplicables. Solo se transmitió el indicador autorizado."}
        result = await lookup_indicator(request.provider, request.indicator_type, indicator)
        assessment = build_assessment(result, request.indicator_type)
        return {"result": result, "assessment": assessment, "external_submission": True,
                "submitted": {"type": request.indicator_type, "indicator": indicator},
                "file_uploaded": False,
                "note": "Se envió únicamente el indicador autorizado; no se transmitieron archivos ni contexto."}
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            raise HTTPException(status_code=404, detail="El proveedor no tiene un resultado para este indicador.") from exc
        raise HTTPException(status_code=502, detail="El proveedor rechazó la consulta o no está disponible.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="No se pudo completar la consulta externa.") from exc


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



@app.post("/api/threat-intel/analyze-file", dependencies=[Depends(require_auth)])
async def analyze_threat_intel_file(file: UploadFile = File(...)):
    """Receive any file for local hash triage and extract review-only IOCs from supported text formats."""
    data = await file.read(MAX_FILE_SIZE + 1)
    await file.close()
    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail="El tamaño máximo permitido es 10 MB.")
    try:
        analysis = analyze_file(data, file.filename)
        analysis.pop("filename", None)
        analysis["yara"] = scan_yara(data)
        candidates = extract_ioc_candidates(data, file.filename)
        history_id = save_analysis("threat_file", analysis["hashes"]["sha256"], analysis)
        return {
            "analysis": analysis,
            "ioc_extraction": candidates,
            "history_id": history_id,
            "stored_locally": True,
            "external_submission": False,
            "execution_performed": False,
            "auto_imported": False,
            "note": "Los indicadores extraídos son candidatos no verificados. Deben revisarse y guardarse manualmente.",
        }
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



def _read_ioc_rows(filename: str, raw: bytes) -> tuple[list[dict], str]:
    """Read CSV or XLSX locally; reject legacy XLS and oversized workbook expansion."""
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".csv":
        try:
            reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=422, detail="El CSV debe estar codificado en UTF-8.") from exc
        if not reader.fieldnames or not {"indicator_type", "indicator"}.issubset(
            {name.strip().lower() for name in reader.fieldnames if name}
        ):
            raise HTTPException(status_code=422, detail="El CSV requiere columnas indicator_type e indicator.")
        return list(reader), "csv"
    if suffix != ".xlsx":
        raise HTTPException(status_code=415, detail="Formato no admitido. Utiliza .csv o .xlsx; .xls no está soportado.")
    try:
        import zipfile
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            if sum(item.file_size for item in archive.infolist()) > 20 * 1024 * 1024:
                raise HTTPException(status_code=413, detail="El contenido descomprimido del Excel supera 20 MB.")
        from openpyxl import load_workbook
        workbook = load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
        sheet = workbook.active
        iterator = sheet.iter_rows(values_only=True)
        headers = next(iterator, None)
        if not headers:
            raise HTTPException(status_code=422, detail="El Excel está vacío.")
        names = [str(value).strip().lower() if value is not None else "" for value in headers]
        if not {"indicator_type", "indicator"}.issubset(set(names)):
            raise HTTPException(status_code=422, detail="El Excel requiere columnas indicator_type e indicator.")
        rows = []
        for values in iterator:
            if len(rows) >= 5000:
                break
            rows.append({names[i]: (str(value).strip() if value is not None else "")
                         for i, value in enumerate(values[:len(names)]) if i < len(names) and names[i]})
        workbook.close()
        return rows, "xlsx"
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=422, detail="No se pudo leer el Excel. Comprueba que sea un .xlsx válido.") from exc


@app.post("/api/threat-intel/import", dependencies=[Depends(require_auth)])
async def import_threat_intel_file(file: UploadFile = File(...)):
    raw = await file.read(2 * 1024 * 1024 + 1)
    await file.close()
    if len(raw) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="El archivo supera el límite de 2 MB.")
    rows, file_type = _read_ioc_rows(file.filename or "", raw)
    imported = 0
    errors = []
    for row_number, row in enumerate(rows, start=2):
        kind = str(row.get("indicator_type") or "").strip().lower()
        value = str(row.get("indicator") or "").strip()
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
            confidence = int(str(row.get("confidence") or "50").strip())
            if not 0 <= confidence <= 100:
                raise ValueError("Confianza fuera del rango 0-100.")
            add_threat_indicator(
                kind, value, confidence,
                str(row.get("source") or f"{file_type}-import").strip()[:100],
                str(row.get("description") or "").strip()[:1000],
            )
            imported += 1
        except (ValueError, TypeError) as exc:
            errors.append(f"Fila {row_number}: {str(exc)[:180]}")
    return {"file_type": file_type, "processed": len(rows), "imported": imported,
            "rejected": len(errors), "errors": errors[:100],
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


@app.get("/api/incidents/{incident_id}/case", dependencies=[Depends(require_auth)])
async def incident_case(incident_id: int):
    case = get_incident_case(incident_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado.")
    return case


@app.post("/api/incidents/{incident_id}/timeline", dependencies=[Depends(require_auth)])
async def add_incident_timeline_entry(incident_id: int, request: IncidentTimelineCreate):
    entry_id = add_incident_timeline(
        incident_id, request.category, request.description, request.source, request.event_time
    )
    if entry_id is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado.")
    return {"id": entry_id, "incident_id": incident_id, "stored_locally": True}


@app.post("/api/incidents/{incident_id}/evidence", dependencies=[Depends(require_auth)])
async def add_incident_evidence_item(incident_id: int, request: IncidentEvidenceCreate):
    digest = request.sha256.strip().lower()
    if digest:
        import re
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise HTTPException(status_code=422, detail="El SHA-256 debe contener 64 caracteres hexadecimales.")
    evidence_id = add_incident_evidence(
        incident_id, request.evidence_type, request.reference, digest, request.source, request.notes
    )
    if evidence_id is None:
        raise HTTPException(status_code=404, detail="Incidente no encontrado.")
    return {"id": evidence_id, "incident_id": incident_id, "stored_locally": True,
            "evidence_bytes_stored": False}


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
