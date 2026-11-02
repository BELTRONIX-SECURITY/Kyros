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


def build_assessment(result: dict, indicator_type: str) -> dict:
    """Create a conservative, evidence-led conclusion from one provider response."""
    provider = result.get("provider", "unknown")
    findings = []
    recommendations = []
    risk = "unknown"
    stats = result.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if provider == "virustotal":
        if malicious > 0:
            risk = "high" if malicious >= 5 else "medium"
            findings.append(f"{malicious} motor(es) clasificaron el hash como malicioso.")
            recommendations.append("Mantener el archivo aislado y escalar para análisis local y contextual.")
        elif suspicious > 0:
            risk = "medium"
            findings.append(f"{suspicious} motor(es) lo clasificaron como sospechoso; no equivale a malware confirmado.")
            recommendations.append("Revisar las detecciones individuales, antigüedad y reputación de los motores.")
        else:
            risk = "unknown"
            findings.append("La consulta no muestra detecciones maliciosas ni sospechosas.")
            recommendations.append("No declarar el archivo seguro; completar inspección local y revisar contexto de origen.")
        detected = (result.get("detected_type") or "").lower()
        names = result.get("names", [])
        extensions = {str(name).rsplit(".", 1)[-1].lower() for name in names if "." in str(name)}
        expected = {"xlsx": "xlsx", "xlsm": "xlsm", "docx": "docx", "docm": "docm",
                    "pptx": "pptx", "pptm": "pptm", "exe": "pe"}
        if detected and extensions:
            mismatches = [ext for ext in extensions if expected.get(ext, ext) not in detected]
            if mismatches:
                findings.append("Se encontraron nombres alternativos cuya extensión no coincide con el tipo detectado: " + ", ".join(sorted(mismatches)[:8]) + ".")
                recommendations.append("Verificar extensión, nombre de origen y tipo real; los nombres alternativos no prueban por sí solos suplantación.")
        conclusion = ("VirusTotal reporta detecciones; requiere investigación y contención según el contexto."
                      if malicious else
                      "No se observaron detecciones en los motores consultados. El veredicto permanece no concluyente: ausencia de detección no demuestra seguridad.")
    elif provider == "abuseipdb":
        score = int(result.get("abuse_confidence_score") or 0)
        reports = int(result.get("total_reports") or 0)
        risk = "high" if score >= 80 else "medium" if score >= 30 else "unknown"
        findings.append(f"AbuseIPDB informa una confianza de abuso de {score}/100 y {reports} reportes.")
        recommendations.append("Correlacionar los reportes con telemetría, fecha, ASN y función legítima de la IP antes de bloquear.")
        conclusion = "La reputación comunitaria es orientativa y no confirma actividad maliciosa en el entorno."
    elif provider == "otx":
        count = int(result.get("pulse_count") or 0)
        risk = "medium" if count else "unknown"
        findings.append(f"OTX devuelve {count} pulse(s) asociados al indicador.")
        recommendations.append("Revisar pulses, fechas, fuentes y contexto antes de elevar la severidad.")
        conclusion = "La presencia o ausencia en OTX no constituye por sí sola una confirmación de amenaza."
    else:
        conclusion = "No hay información suficiente para emitir una conclusión."
    verdict = ("detections_reported" if provider == "virustotal" and malicious else
               "no_detections_not_conclusive" if provider == "virustotal" else "reputation_context_only")
    if provider == "virustotal" and malicious:
        confidence = "medium" if malicious < 5 else "high"
        severity = "high" if malicious >= 5 else "medium"
        status = "probable_threat"
    elif provider == "virustotal" and suspicious:
        confidence, severity, status = "low", "medium", "needs_validation"
    else:
        confidence, severity, status = "low", "undetermined", "inconclusive"
    return {
        "analysis_level": "L2_indicator_triage",
        "risk": risk,
        "severity": severity if provider == "virustotal" else risk,
        "confidence": confidence if provider == "virustotal" else "low",
        "case_status": status if provider == "virustotal" else "context_only",
        "verdict": verdict,
        "scope": "Consulta de un único indicador; no equivale a investigación completa del endpoint o incidente.",
        "facts": findings,
        "findings": findings,
        "hypotheses": [
            "Una ausencia de detecciones puede deberse a que el indicador no es conocido, no está analizado o no es detectado por los motores."
        ] if provider == "virustotal" and not malicious and not suspicious else [],
        "mitre_attack": {
            "mapping": "not_justified",
            "note": "Una consulta de reputación de hash por sí sola no demuestra una táctica o técnica ATT&CK."
        },
        "recommendations": recommendations,
        "priority_actions": [
            {"priority": "P1", "action": item, "validation": "Registrar resultado y evidencia de la comprobación."}
            for item in recommendations
        ],
        "conclusion": conclusion,
        "missing_evidence": [
            "Telemetría del endpoint y proceso que originó o abrió el archivo.",
            "Contexto de usuario, equipo, fecha, origen y actividad asociada.",
            "Resultados locales de antivirus/YARA y revisión de contenido."
        ],
        "limitations": [
            "La consulta cubre únicamente el indicador autorizado; no se envió el archivo.",
            "La reputación externa puede estar incompleta o desactualizada.",
            "No se consultaron relaciones ni comportamiento salvo que se indique expresamente.",
            "La conclusión debe correlacionarse con telemetría y contexto del entorno."
        ],
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
            return {
                "provider": provider, "indicator": indicator.lower(),
                "reputation": attrs.get("reputation"),
                "last_analysis_stats": {k: stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout")},
                "detected_type": attrs.get("type_description") or attrs.get("type_tag") or "",
                "magic": attrs.get("magic", ""),
                "size": attrs.get("size"),
                "names": [str(x)[:180] for x in (attrs.get("names") or [])[:20]],
                "meaningful_name": attrs.get("meaningful_name", ""),
                "first_submission_date": attrs.get("first_submission_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "meaning": "Resultados agregados de análisis; no constituyen por sí solos confirmación de malware.",
            }
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

async def lookup_available_sources(indicator_type: str, indicator: str) -> dict:
    """Query only configured providers applicable to this IOC type; never upload samples."""
    available = provider_status()
    selected = []
    if indicator_type == "sha256":
        selected = ["virustotal", "otx"]
    elif indicator_type == "ip":
        selected = ["abuseipdb", "otx"]
    elif indicator_type == "domain":
        selected = ["otx"]
    results, errors = [], []
    for provider in selected:
        if not available.get(provider):
            continue
        try:
            data = await lookup_indicator(provider, indicator_type, indicator)
            results.append({"provider": provider, "data": data,
                            "assessment": build_assessment(data, indicator_type)})
        except httpx.HTTPStatusError as exc:
            errors.append({"provider": provider, "error": f"HTTP {exc.response.status_code}"})
        except (httpx.HTTPError, RuntimeError, ValueError):
            errors.append({"provider": provider, "error": "Consulta no disponible o rechazada"})
    if not results and not errors:
        raise RuntimeError("No hay proveedores aplicables configurados para este tipo de indicador.")
    malicious = sum(int(x["data"].get("last_analysis_stats", {}).get("malicious", 0) or 0)
                    for x in results if x["provider"] == "virustotal")
    suspicious = sum(int(x["data"].get("last_analysis_stats", {}).get("suspicious", 0) or 0)
                     for x in results if x["provider"] == "virustotal")
    return {
        "analysis_level": "L2_multi_source_indicator_triage",
        "indicator_type": indicator_type,
        "indicator": indicator,
        "sources_queried": [x["provider"] for x in results],
        "sources_not_available": [p for p in selected if not available.get(p)],
        "source_errors": errors,
        "source_results": results,
        "risk": "high" if malicious >= 5 else "medium" if malicious or suspicious else "unknown",
        "conclusion": (
            "Se observaron detecciones maliciosas en VirusTotal; validar con telemetría y análisis local."
            if malicious else
            "No se obtuvieron detecciones maliciosas en las fuentes consultadas. Resultado no concluyente; ausencia de detección no demuestra seguridad."
        ),
        "limitations": [
            "Solo se consultaron fuentes configuradas y aplicables al tipo de indicador.",
            "Se compartió únicamente el indicador autorizado; nunca el archivo ni su contenido.",
            "Las fuentes de reputación no confirman por sí solas actividad en el entorno.",
            "No se consultaron automáticamente relaciones ni sandbox; requieren módulos y permisos específicos."
        ],
        "recommendations": [
            "Correlacionar el indicador con eventos del SIEM/EDR, usuario, host y marca temporal.",
            "Validar resultados discrepantes y antigüedad de cada fuente.",
            "Completar análisis local del archivo con antivirus/YARA y revisión estática."
        ]
    }

