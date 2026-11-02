"""Explicit, indicator-only lookups to optional threat-intelligence providers."""
from __future__ import annotations

import os
import re

import httpx

HASH_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def provider_status() -> dict:
    return {
        "virustotal": bool(os.getenv("KYROS_VT_API_KEY", "").strip()),
        "abuseipdb": bool(os.getenv("KYROS_ABUSEIPDB_API_KEY", "").strip()),
        "otx": bool(os.getenv("KYROS_OTX_API_KEY", "").strip()),
    }


async def lookup_indicator(provider: str, indicator_type: str, indicator: str) -> dict:
    """Query one indicator only. Never upload a file or send surrounding context."""
    keys = {
        "virustotal": os.getenv("KYROS_VT_API_KEY", "").strip(),
        "abuseipdb": os.getenv("KYROS_ABUSEIPDB_API_KEY", "").strip(),
        "otx": os.getenv("KYROS_OTX_API_KEY", "").strip(),
    }
    key = keys.get(provider, "")
    if not key:
        raise RuntimeError(f"Proveedor {provider} no configurado.")
    if provider == "virustotal" and (indicator_type != "sha256" or not HASH_RE.fullmatch(indicator)):
        raise ValueError("VirusTotal está habilitado inicialmente solo para consultas SHA-256.")
    if provider == "abuseipdb" and indicator_type != "ip":
        raise ValueError("AbuseIPDB solo admite indicadores IP.")
    if provider == "otx" and indicator_type not in {"ip", "domain", "sha256"}:
        raise ValueError("OTX admite IP, dominio y SHA-256.")

    timeout = httpx.Timeout(12.0, connect=4.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        if provider == "virustotal":
            response = await client.get(
                f"https://www.virustotal.com/api/v3/files/{indicator.lower()}",
                headers={"x-apikey": key},
            )
            response.raise_for_status()
            attrs = response.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {"provider": provider, "indicator": indicator.lower(),
                    "reputation": attrs.get("reputation"),
                    "last_analysis_stats": {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")},
                    "meaning": "Resultados agregados de análisis; no constituyen por sí solos confirmación de malware."}
        if provider == "abuseipdb":
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": "90"},
                headers={"Key": key, "Accept": "application/json"},
            )
            response.raise_for_status()
            attrs = response.json().get("data", {})
            return {"provider": provider, "indicator": indicator,
                    "abuse_confidence_score": attrs.get("abuseConfidenceScore"),
                    "total_reports": attrs.get("totalReports"),
                    "last_reported_at": attrs.get("lastReportedAt"),
                    "country_code": attrs.get("countryCode"),
                    "meaning": "Puntuación comunitaria de reportes; puede contener falsos positivos."}
        section = "IPv4" if indicator_type == "ip" and "." in indicator else (
            "IPv6" if indicator_type == "ip" else ("domain" if indicator_type == "domain" else " file")
        )
        section = section.strip()
        response = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/{section}/{indicator}/general",
            headers={"X-OTX-API-KEY": key},
        )
        response.raise_for_status()
        attrs = response.json()
        pulse_info = attrs.get("pulse_info", {})
        return {"provider": provider, "indicator": indicator,
                "pulse_count": pulse_info.get("count", 0),
                "reputation": attrs.get("reputation"),
                "validation": attrs.get("validation", []),
                "meaning": "La presencia en pulses requiere revisar contexto, fechas y fuentes."}
