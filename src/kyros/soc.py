"""Safe, local-first IOC and file triage helpers for Kyros SOC."""
from __future__ import annotations
import hashlib
import ipaddress
import re
from pathlib import PurePath
from typing import Any

MAX_FILE_SIZE = 10 * 1024 * 1024
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")


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


def _ooxml_analysis(data: bytes) -> dict[str, Any] | None:
    """Identify and inspect Office Open XML containers without extracting or executing them."""
    import io
    import zipfile
    import xml.etree.ElementTree as ET

    if not data.startswith(b"\x50\x4b\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > 2000 or sum(item.file_size for item in entries) > 40 * 1024 * 1024:
                return {"file_type": "ZIP archive (contenido no inspeccionado: límites excedidos)",
                        "structure": {"valid_ooxml": False, "inspection": "resource_limit"}}
            names = {item.filename for item in entries}
            if "[Content_Types].xml" not in names:
                return None
            families = (
                ("xl/workbook.xml", "Microsoft Excel"),
                ("word/document.xml", "Microsoft Word"),
                ("ppt/presentation.xml", "Microsoft PowerPoint"),
            )
            match = next(((path, label) for path, label in families if path in names), None)
            if not match:
                return None
            main_part, family = match
            macro_paths = {"xl/vbaProject.bin", "word/vbaProject.bin", "ppt/vbaProject.bin"}
            has_macros = bool(names.intersection(macro_paths))
            extlinks = [name for name in names if name.startswith(("xl/externalLinks/", "word/externalLinks/", "ppt/externalLinks/"))]
            formulas = 0
            sheet_count = 0
            try:
                root = ET.fromstring(archive.read(main_part)[:2 * 1024 * 1024])
                if family == "Microsoft Excel":
                    sheet_count = sum(1 for node in root.iter() if node.tag.endswith("}sheet"))
                    for name in names:
                        if name.startswith("xl/worksheets/") and name.endswith(".xml"):
                            info = archive.getinfo(name)
                            if info.file_size <= 4 * 1024 * 1024:
                                xml_data = archive.read(name)
                                formulas += xml_data.count(b"<f") + xml_data.count(b":f")
            except (ET.ParseError, KeyError, OSError, zipfile.BadZipFile):
                return {"file_type": "Office Open XML (estructura no válida)",
                        "structure": {"valid_ooxml": False, "inspection": "invalid_xml"}}
            extension = "XLSM" if family == "Microsoft Excel" and has_macros else {
                "Microsoft Excel": "XLSX", "Microsoft Word": "DOCX",
                "Microsoft PowerPoint": "PPTX"
            }[family]
            return {
                "file_type": f"{family} ({extension})",
                "structure": {
                    "valid_ooxml": True, "family": family, "main_part": main_part,
                    "entry_count": len(entries),
                    "sheet_count": sheet_count if family == "Microsoft Excel" else None,
                    "formulas_present": formulas > 0,
                    "formula_count_approx": formulas if family == "Microsoft Excel" else None,
                    "macro_project_present": has_macros, "external_link_parts": len(extlinks),
                    "inspection": "static_only",
                    "note": "Macros, fórmulas o enlaces externos son datos estructurales; no demuestran actividad maliciosa."
                }
            }
    except (zipfile.BadZipFile, OSError, ValueError):
        return {"file_type": "ZIP archive (contenedor no válido)",
                "structure": {"valid_ooxml": False, "inspection": "invalid_container"}}


def _file_type(data: bytes, filename: str | None = None) -> tuple[str, dict[str, Any] | None]:
    ooxml = _ooxml_analysis(data)
    if ooxml:
        return ooxml["file_type"], ooxml.get("structure")
    signatures = [
        (b"\x7fELF", "ELF executable"),
        (b"MZ", "Windows PE/DOS executable (signature only)"),
        (b"PK\x03\x04", "ZIP archive"), (b"%PDF-", "PDF document"),
        (b"\x1f\x8b", "GZIP archive"), (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"), (b"SQLite format 3\x00", "SQLite database"),
    ]
    detected = next((label for signature, label in signatures if data.startswith(signature)), "Unknown / unclassified")
    return detected, None


def analyze_file(data: bytes, filename: str | None = None) -> dict[str, Any]:
    if not data:
        raise ValueError("El archivo está vacío.")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("El tamaño máximo permitido es 10 MB.")
    return {
        "filename": PurePath(filename or "uploaded-file").name[:128],
        "size_bytes": len(data), "extension": PurePath(filename or "").suffix.lower()[:16],
        "file_type": _file_type(data, filename)[0],
        "structure": _file_type(data, filename)[1],
        "hashes": {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        },
        "risk": "unknown",
        "assessment": "Triaje estático inicial. No se ejecutó el archivo, no se usaron firmas YARA/antivirus y no se envió a terceros.",
        "execution_performed": False, "external_submission": False,
    }


def classify_email(value: str) -> dict[str, Any]:
    """Validate an email address locally without querying or disclosing it externally."""
    raw = value.strip()
    if len(raw) > 254 or raw.count("@") != 1:
        raise ValueError("Introduce una dirección de correo válida.")
    local, domain = raw.rsplit("@", 1)
    if (
        not local or len(local) > 64 or not domain or
        local.startswith(".") or local.endswith(".") or ".." in local or
        any(ch.isspace() for ch in raw) or
        not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)
    ):
        raise ValueError("La dirección de correo no tiene un formato válido.")
    try:
        normalized_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("El dominio del correo no es válido.") from exc
    if not DOMAIN_RE.fullmatch(normalized_domain):
        raise ValueError("El dominio del correo no tiene un formato válido.")
    normalized = f"{local}@{normalized_domain}"
    return {
        "indicator": normalized,
        "type": "email",
        "domain": normalized_domain,
        "risk": "unknown",
        "assessment": (
            "Formato válido. No se ha comprobado la existencia del buzón, DNS, "
            "brechas ni reputación; no se ha transmitido la dirección."
        ),
        "external_lookup": False,
        "external_submission": False,
    }



def scan_yara(data: bytes) -> dict[str, Any]:
    """Run optional local YARA rules against bytes; never executes or uploads the sample."""
    import os

    rules_path = os.getenv("KYROS_YARA_RULES", "").strip()
    if not rules_path:
        return {"status": "not_configured", "matches": [],
                "note": "Configura KYROS_YARA_RULES con una ruta local de reglas YARA."}
    try:
        import yara
    except ImportError:
        return {"status": "unavailable", "matches": [],
                "note": "YARA no está instalado. Instala el extra opcional kyros[yara]."}
    try:
        rules = yara.compile(filepath=rules_path)
        matches = rules.match(data=data, timeout=5)
        return {
            "status": "completed",
            "matches": [
                {"rule": match.rule, "namespace": match.namespace,
                 "tags": list(match.tags)}
                for match in matches[:50]
            ],
            "note": "Coincidencias YARA requieren análisis contextual; no son veredictos automáticos.",
        }
    except (OSError, yara.Error, TimeoutError) as exc:
        return {"status": "error", "matches": [],
                "note": f"No se pudo completar YARA: {type(exc).__name__}."}
