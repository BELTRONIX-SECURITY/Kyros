"""Local SIEM log ingestion, normalization and conservative correlation."""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_SIEM_UPLOAD = 12 * 1024 * 1024
MAX_SIEM_ROWS = 20000
MAX_EXPANDED = 80 * 1024 * 1024

ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "event_time", "date", "fecha", "hora"),
    "hostname": ("hostname", "host", "computer", "computername", "device", "equipo"),
    "event_id": ("event_id", "eventid", "id_evento", "id de evento", "event code"),
    "user": ("user", "username", "account", "account_name", "usuario", "subject_user_name"),
    "source_ip": ("source_ip", "src_ip", "src", "ip_origen", "ip origen", "client_ip"),
    "destination": ("destination", "dest_ip", "dst", "destination_ip", "destino", "url", "resource"),
    "log_source": ("log_source", "source", "channel", "provider", "logname", "fuente", "source_name"),
    "description": ("event_description", "description", "message", "details", "event", "descripcion", "mensaje"),
    "process": ("process_commandline", "commandline", "process", "process_name", "image", "comando", "command"),
    "severity": ("severity", "level", "risk", "severidad", "priority"),
    "destination_port": ("destination_port", "dest_port", "dst_port", "port", "puerto"),
    "bytes_sent": ("bytes_sent", "sent_bytes", "upload_bytes", "bytes_out", "bytes"),
}
SUSPICIOUS = {
    "rdp": re.compile(r"\b(rdp|remote desktop|terminal services)\b", re.I),
    "powershell": re.compile(r"powershell|encodedcommand|pwsh", re.I),
    "discovery": re.compile(r"net\.exe\s+view|whoami|query user|nltest|ipconfig|arp\s+-a", re.I),
    "archive": re.compile(r"7z\.exe|winrar|makecab|compress-archive|\bzip\b", re.I),
    "exfil": re.compile(r"upload|https?\s+post|/upload/|large outbound|bytes_sent", re.I),
    "persistence": re.compile(r"schtasks|scheduled task|event.?id.?4698|7045|create service|new-service", re.I),
    "web_exec": re.compile(r"\.aspx?.{0,100}(cmd=|whoami)|w3wp.{0,80}cmd\.exe|iis apppool", re.I),
    "backup_impact": re.compile(r"vssadmin.{0,80}delete shadows|wbadmin.{0,80}delete", re.I),
    "auth_fail": re.compile(r"logon failure|failed logon|authentication failed|event.?id.?4625", re.I),
    "auth_success": re.compile(r"logon success|successful logon|event.?id.?4624", re.I),
    "privilege": re.compile(r"special privileges|event.?id.?4672|admin group", re.I),
    "share": re.compile(r"\\\\[^\\]+\\|network share|event.?id.?5140", re.I),
}

def _key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")

def _parse_time(value: Any) -> str:
    if isinstance(value, datetime):
        dt = value
    elif value is None or str(value).strip() == "":
        return ""
    else:
        raw = str(value).strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(raw)
        except ValueError:
            for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(raw, fmt)
                    break
                except ValueError:
                    continue
            else:
                return raw[:80]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()

def _normalise_row(raw: dict[str, Any], row_number: int) -> dict[str, Any]:
    normalized = {_key(k): v for k, v in raw.items() if k is not None}
    out: dict[str, Any] = {"row_number": row_number}
    for target, aliases in ALIASES.items():
        value = ""
        for alias in aliases:
            if _key(alias) in normalized and normalized[_key(alias)] not in (None, ""):
                value = normalized[_key(alias)]
                break
        if target == "timestamp":
            value = _parse_time(value)
        elif value is not None:
            value = str(value).strip()[:2000]
        out[target] = value
    out["event_id"] = str(out["event_id"])
    out["raw"] = {str(k)[:100]: str(v)[:1000] for k, v in raw.items() if k is not None}
    out["search"] = " ".join(str(out.get(k, "")) for k in (
        "event_id", "log_source", "description", "process", "severity"
    ))
    return out

def _read_rows(filename: str, data: bytes) -> tuple[list[dict], str]:
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".csv":
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise ValueError("El CSV debe estar codificado en UTF-8.") from exc
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("El CSV no contiene encabezados.")
        rows = list(reader)
        if len(rows) > MAX_SIEM_ROWS:
            raise ValueError(f"El archivo supera el máximo de {MAX_SIEM_ROWS} eventos.")
        return rows, "csv"
    if suffix != ".xlsx":
        raise ValueError("Formato no admitido. Utiliza Excel .xlsx o CSV UTF-8; .xls no está soportado.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if sum(x.file_size for x in archive.infolist()) > MAX_EXPANDED:
                raise ValueError("El Excel supera el límite de expansión permitido.")
        from openpyxl import load_workbook
        wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        ws = wb.active
        iterator = ws.iter_rows(values_only=True)
        headers = next(iterator, None)
        if not headers:
            raise ValueError("La hoja Excel está vacía.")
        names = [str(x).strip() if x is not None else "" for x in headers]
        rows = []
        for values in iterator:
            if len(rows) >= MAX_SIEM_ROWS:
                raise ValueError(f"El archivo supera el máximo de {MAX_SIEM_ROWS} eventos.")
            if not any(x is not None for x in values):
                continue
            rows.append({names[i]: values[i] for i in range(min(len(names), len(values))) if names[i]})
        wb.close()
        return rows, "xlsx"
    except zipfile.BadZipFile as exc:
        raise ValueError("El archivo Excel no es válido.") from exc

def _event_flags(event: dict) -> list[str]:
    haystack = " ".join(str(event.get(k, "")) for k in ("event_id", "description", "process", "log_source", "search"))
    flags = [name for name, pattern in SUSPICIOUS.items() if pattern.search(haystack)]
    eid = str(event.get("event_id", "")).strip()
    if eid == "4625" and "auth_fail" not in flags: flags.append("auth_fail")
    if eid == "4624" and "auth_success" not in flags: flags.append("auth_success")
    if eid == "4672" and "privilege" not in flags: flags.append("privilege")
    if eid == "4698" and "persistence" not in flags: flags.append("persistence")
    if eid == "7045" and "persistence" not in flags: flags.append("persistence")
    return flags

def analyze_siem_rows(rows: list[dict], source_format: str = "xlsx") -> dict:
    events = [_normalise_row(row, i + 2) for i, row in enumerate(rows)]
    for event in events:
        event["signals"] = _event_flags(event)
    counts = Counter(flag for event in events for flag in event["signals"])
    hosts = Counter(e["hostname"] for e in events if e["hostname"])
    sources = Counter(e["log_source"] for e in events if e["log_source"])
    failed = [e for e in events if "auth_fail" in e["signals"]]
    successful = [e for e in events if "auth_success" in e["signals"]]
    high = [e for e in events if str(e["severity"]).lower() in {"high", "critical", "error"}]
    incidents = []

    def add_incident(title: str, severity: str, confidence: str, description: str,
                     selected: list[dict], techniques: list[str], limitations: list[str]) -> None:
        if not selected: return
        incidents.append({
            "id": f"SIEM-{len(incidents)+1:03d}", "title": title, "severity": severity,
            "confidence": confidence, "status": "hypothesis_pending_validation",
            "description": description,
            "event_rows": [e["row_number"] for e in selected[:100]],
            "event_count": len(selected),
            "hosts": sorted({e["hostname"] for e in selected if e["hostname"]}),
            "users": sorted({e["user"] for e in selected if e["user"]}),
            "source_ips": sorted({e["source_ip"] for e in selected if e["source_ip"]}),
            "timeline": [{"time": e["timestamp"], "host": e["hostname"], "event_id": e["event_id"],
                          "description": e["description"][:240], "row": e["row_number"]}
                         for e in selected[:30]],
            "mitre_candidates": techniques,
            "limitations": limitations,
            "recommendations": [
                "Validar la actividad con el propietario del activo y la ventana de mantenimiento.",
                "Correlacionar los eventos con EDR, autenticación y telemetría de red.",
                "Preservar los registros originales y documentar la validación del analista."
            ],
        })

    # Suspicious chains are grouped by host and time-independent event patterns;
    # event references are retained so analysts can validate the sequence.
    by_host: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        if event["hostname"]: by_host[event["hostname"]].append(event)
    for host, items in by_host.items():
        patterns = set(flag for e in items for flag in e["signals"])
        if {"rdp", "auth_success", "privilege"} <= patterns or (
            "rdp" in patterns and "auth_success" in patterns and "powershell" in patterns
        ):
            selected = [e for e in items if set(e["signals"]) & {"rdp","auth_success","auth_fail","privilege","powershell","discovery","share"}]
            add_incident("Acceso remoto sospechoso y reconocimiento", "critical", "medium",
                "Secuencia compatible con acceso remoto seguido de actividad de reconocimiento. Validar autorización y sesión.",
                selected, ["T1021.001", "T1059.001", "T1087", "T1135"],
                ["La coincidencia de patrones no demuestra compromiso de cuenta."])
        if "persistence" in patterns:
            selected = [e for e in items if "persistence" in e["signals"]]
            add_incident("Posible mecanismo de persistencia", "high", "medium",
                "Se observan eventos compatibles con creación de tarea programada o instalación de servicio.",
                selected, ["T1053.005", "T1543.003"],
                ["Se requiere validar nombre, ruta, firma y autorización administrativa."])
        if "web_exec" in patterns:
            selected = [e for e in items if "web_exec" in e["signals"] or "powershell" in e["signals"]]
            add_incident("Posible ejecución de comandos desde servidor web", "high", "medium",
                "La telemetría contiene patrones de petición web y ejecución de comandos asociados a IIS.",
                selected, ["T1190", "T1059.003"],
                ["Se necesita correlación HTTP y árbol de procesos para demostrar causalidad."])
        if "backup_impact" in patterns:
            selected = [e for e in items if "backup_impact" in e["signals"]]
            add_incident("Actividad que puede afectar a copias de seguridad", "high", "medium",
                "Se detecta una orden asociada a eliminación de copias de sombra.",
                selected, ["T1490"],
                ["Puede corresponder a mantenimiento autorizado; validar cambio y cuenta."])
        if "archive" in patterns and "exfil" in patterns:
            selected = [e for e in items if set(e["signals"]) & {"archive","exfil"}]
            add_incident("Compresión seguida de transferencia saliente", "high", "medium",
                "Se observa compresión y actividad de transferencia en el mismo host; posible salida de datos pendiente de confirmar.",
                selected, ["T1560", "T1041"],
                ["Los logs no demuestran qué contenido se transfirió ni su recepción."])
    # Generic failed-auth burst: report only when repeated on a host.
    if len(failed) >= 5:
        add_incident("Múltiples fallos de autenticación", "medium", "low",
            f"Se registraron {len(failed)} eventos compatibles con fallos de autenticación.",
            failed, ["T1110"], ["No se ha demostrado que los fallos precedieran a un acceso exitoso."])

    # Relate cases only when they share a concrete host, account or source IP.
    for index, incident in enumerate(incidents):
        related = []
        for other_index, other in enumerate(incidents):
            if index == other_index:
                continue
            shared_hosts = set(incident["hosts"]) & set(other["hosts"])
            shared_users = set(incident["users"]) & set(other["users"])
            shared_ips = set(incident["source_ips"]) & set(other["source_ips"])
            if shared_hosts or shared_users or shared_ips:
                related.append({
                    "incident_id": other["id"],
                    "shared_hosts": sorted(shared_hosts),
                    "shared_users": sorted(shared_users),
                    "shared_source_ips": sorted(shared_ips),
                })
        incident["related_incidents"] = related

    severities = Counter(e["severity"].lower() for e in events if e["severity"])
    return {
        "analysis_type": "siem_log_correlation", "source_format": source_format,
        "total_events": len(events), "normalized_events": len(events),
        "time_range": {"first": min((e["timestamp"] for e in events if e["timestamp"]), default=""),
                       "last": max((e["timestamp"] for e in events if e["timestamp"]), default="")},
        "hosts": [{"name": k, "events": v} for k, v in hosts.most_common(20)],
        "log_sources": [{"name": k, "events": v} for k, v in sources.most_common(20)],
        "severity_counts": dict(severities), "signal_counts": dict(counts),
        "authentication": {"failures": len(failed), "successes": len(successful)},
        "incidents": incidents,
        "incident_count": len(incidents),
        "high_priority_count": sum(i["severity"] in {"critical", "high"} for i in incidents),
        "events": [{k: e[k] for k in ("row_number","timestamp","hostname","event_id","user","source_ip",
                     "destination","log_source","description","process","severity","signals")}
                   for e in events[:MAX_SIEM_ROWS]],
        "data_quality": {
            "missing_timestamp": sum(not e["timestamp"] for e in events),
            "missing_hostname": sum(not e["hostname"] for e in events),
            "missing_description": sum(not e["description"] and not e["process"] for e in events),
            "note": "La detección se basa en patrones heurísticos y campos disponibles; no sustituye validación EDR/SIEM."
        },
        "limitations": [
            "Los incidentes son hipótesis de investigación; no se confirman automáticamente.",
            "Las correlaciones se agrupan principalmente por hostname y señales; la causalidad requiere más telemetría.",
            "MITRE ATT&CK se presenta como técnica candidata, no como atribución confirmada.",
            "No se realizan consultas externas ni se transmiten los logs durante este análisis."
        ],
        "privacy": {"processed_locally": True, "external_submission": False, "file_stored": False}
    }

def analyze_siem_file(filename: str, data: bytes) -> dict:
    if len(data) > MAX_SIEM_UPLOAD:
        raise ValueError("El archivo supera el límite de 12 MB.")
    rows, fmt = _read_rows(filename, data)
    if not rows:
        raise ValueError("El archivo no contiene eventos.")
    return analyze_siem_rows(rows, fmt)

def build_soc_l2_report(result: dict) -> str:
    lines = [
        "INFORME SOC L2 — KYROS",
        f"Eventos analizados: {result['total_events']}",
        f"Incidentes candidatos: {result['incident_count']}",
        f"Incidentes de prioridad alta/crítica: {result['high_priority_count']}",
        f"Periodo UTC: {result['time_range']['first']} — {result['time_range']['last']}",
        "",
        "RESUMEN EJECUTIVO",
        "El análisis local identificó patrones que requieren validación. Ninguna hipótesis equivale por sí sola a una intrusión confirmada.",
        "",
        "INCIDENTES Y EVIDENCIAS",
    ]
    for item in result["incidents"]:
        lines += [
            f"{item['id']} | {item['severity'].upper()} | Confianza {item['confidence']}",
            item["title"], item["description"],
            f"Hosts: {', '.join(item['hosts']) or 'No identificados'}",
            f"Usuarios: {', '.join(item['users']) or 'No identificados'}",
            f"Filas de evidencia: {', '.join(map(str, item['event_rows']))}",
            f"MITRE candidatos: {', '.join(item['mitre_candidates']) or 'No justificado'}",
            "Recomendaciones: " + " ".join(item["recommendations"]),
            "",
        ]
    lines += [
        "LIMITACIONES",
        *[f"- {x}" for x in result["limitations"]],
        "",
        "CONCLUSIÓN SOC L2",
        "Escalar los incidentes de mayor prioridad para validación. Preservar la evidencia original y documentar los resultados de cada comprobación.",
    ]
    return "\n".join(lines)
