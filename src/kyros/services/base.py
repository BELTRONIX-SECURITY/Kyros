"""Contrato común de todos los servicios."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class Context:
    email: str
    local: str
    domain: str
    client: httpx.AsyncClient | None
    keys: dict[str, str]
    timeout: float = 15.0


class Service(ABC):
    """Cada fuente de datos hereda de aquí e implementa `run`."""

    name: str = "servicio"
    key_name: str | None = None  # si se define, el servicio se omite sin esa API key

    @abstractmethod
    async def run(self, ctx: Context) -> dict[str, Any]:
        """Devuelve un diccionario serializable a JSON. Lanza excepción si falla."""
