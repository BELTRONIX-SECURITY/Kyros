"""Validación sintáctica de direcciones de correo."""

import re

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@" + _LABEL + r"(?:\." + _LABEL + r")+$"
)


def split_email(email: str) -> tuple[str, str]:
    """Devuelve (parte_local, dominio_en_minúsculas) o lanza ValueError."""
    email = email.strip()
    if len(email) > 254 or not EMAIL_RE.match(email):
        raise ValueError(f"Correo no válido: {email!r}")
    local, domain = email.rsplit("@", 1)
    if len(local) > 64:
        raise ValueError("La parte local supera los 64 caracteres")
    return local, domain.lower()
