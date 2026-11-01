"""Carga de API keys desde YAML y variables de entorno."""

import os
from pathlib import Path

import yaml

DEFAULT_PATH = Path.home() / ".kyros.yaml"
KNOWN_KEYS = ("hunter", "emailrep", "hibp")


def load_config(path: str | None = None) -> dict[str, str]:
    """Devuelve {servicio: api_key}. Las variables de entorno tienen prioridad."""
    keys: dict[str, str] = {}
    candidate = Path(path) if path else DEFAULT_PATH

    if candidate.exists():
        data = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
        for name, value in (data.get("keys") or {}).items():
            if value:
                keys[str(name)] = str(value)
    elif path:
        raise FileNotFoundError(f"No existe el archivo de configuración: {path}")

    for name in KNOWN_KEYS:
        env_value = os.getenv(f"KYROS_{name.upper()}_KEY")
        if env_value:
            keys[name] = env_value
    return keys
