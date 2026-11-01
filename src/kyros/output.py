"""Salida por terminal (rich) y a archivo JSON."""

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from kyros.models import Report

_STATUS_STYLE = {"ok": "green", "error": "red", "skipped": "yellow"}


def _fmt(value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        lines = []
        for key, val in value.items():
            if isinstance(val, (dict, list)) and val:
                lines.append(f"{pad}{key}:")
                lines.append(_fmt(val, indent + 1))
            else:
                lines.append(f"{pad}{key}: {val if val not in (None, [], {}) else '-'}")
        return "\n".join(lines)
    if isinstance(value, list):
        return "\n".join(
            _fmt(item, indent) if isinstance(item, dict) else f"{pad}- {item}" for item in value
        )
    return f"{pad}{value}"


def render(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    table = Table(title=f"Resultados para {report.email}", show_lines=True)
    table.add_column("Servicio", style="bold")
    table.add_column("Estado")
    table.add_column("Detalle", overflow="fold")

    for result in report.results:
        style = _STATUS_STYLE.get(result.status, "white")
        detail = result.error if result.status != "ok" else _fmt(result.data)
        table.add_row(result.name, f"[{style}]{result.status}[/{style}]", detail or "-")
    console.print(table)


def write_json(report: Report, path: str) -> None:
    Path(path).write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8"
    )
