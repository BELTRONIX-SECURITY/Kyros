"""Modelos de datos del resultado."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class ServiceResult:
    name: str
    status: str  # "ok" | "error" | "skipped"
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class Report:
    email: str
    domain: str
    results: list[ServiceResult]
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
