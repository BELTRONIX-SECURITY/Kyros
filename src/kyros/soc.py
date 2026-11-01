"""Safe, local-first IOC and file triage helpers for Kyros SOC."""
from __future__ import annotations
import hashlib
import ipaddress
import re
from pathlib import PurePath
from typing import Any

MAX_FILE_SIZE = 10 * 1024 * 1024
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[A-Za-z]{2,63}$")


def classify_ip(value: str) -> dict[str, Any]:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("La dirección IP no tiene un formato válido.") from exc
    if address.is_global:
        scope, note = "public", "IP pública; esto no determina actividad maliciosa."
    elif address.is_loopback:
        scope, note = "loopback", "Dirección de bucle local."
    elif address.is_link_local:
        scope, note = "link-local", "Dirección de enlace local."
    elif address.is_private:
        scope, note = "private", "IP privada; normalmente pertenece a una red interna."
    else:
        scope, note = "special", "Dirección reservada o de uso especial."
    return {
        "indicator": str(address), "type": f"IPv{address.version}", "scope": scope,
        "is_global": address.is_global, "risk": "unknown", "assessment": note,
        "external_lookup": False,
        "external_lookup_note": "No se consultaron fuentes externas.",
    }


def classify_domain(value: str) -> dict[str, Any]:
    raw = value.strip().rstrip(".")
    if not raw or len(raw) > 253 or "://" in raw or "/" in raw or "@" in raw:
        raise ValueError("Introduce únicamente un nombre de dominio, sin URL ni ruta.")
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("El dominio contiene caracteres no válidos.") from exc
    if not DOMAIN_RE.fullmatch(domain):
        raise ValueError("El nombre de dominio no tiene un formato válido.")
    return {
        "indicator": domain, "type": "domain", "risk": "unknown",
        "assessment": "Formato válido. No se ha consultado DNS ni fuentes externas; reputación y actividad sin determinar.",
        "external_lookup": False,
    }


def _file_type(data: bytes) -> str:
    signatures = [
        (b"\\x7fELF", "ELF executable"),
        (b"MZ", "Windows PE/DOS executable (signature only)"),
        (b"PK\\x03\\x04", "ZIP archive"), (b"%PDF-", "PDF document"),
        (b"\\x1f\\x8b", "GZIP archive"), (b"\\x89PNG\\r\\n\\x1a\\n", "PNG image"),
        (b"\\xff\\xd8\\xff", "JPEG image"), (b"SQLite format 3\\x00", "SQLite database"),
    ]
    for signature, label in signatures:
        if data.startswith(signature):
            return label
    return "Unknown / unclassified"


def analyze_file(data: bytes, filename: str | None = None) -> dict[str, Any]:
    if not data:
        raise ValueError("El archivo está vacío.")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("El tamaño máximo permitido es 10 MB.")
    return {
        "filename": PurePath(filename or "uploaded-file").name[:128],
        "size_bytes": len(data), "extension": PurePath(filename or "").suffix.lower()[:16],
        "file_type": _file_type(data),
        "hashes": {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        },
        "risk": "unknown",
        "assessment": "Triaje estático inicial. No se ejecutó el archivo, no se usaron firmas YARA/antivirus y no se envió a terceros.",
        "execution_performed": False, "external_submission": False,
    }
