"""Local SQLite history for Kyros SOC. File contents are never persisted."""
from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def database_path() -> Path:
    configured = os.getenv("KYROS_DB_PATH")
    if configured:
        path = Path(configured).expanduser()
    else:
        path = Path.home() / ".kyros" / "kyros_soc.sqlite3"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path

def initialize() -> None:
    with sqlite3.connect(database_path()) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)
        connection.commit()

def save_analysis(analysis_type: str, indicator: str, result: dict[str, Any]) -> int:
    initialize()
    created_at = datetime.now(timezone.utc).isoformat()
    safe_result = dict(result)
    if analysis_type == "file":
        safe_result.pop("filename", None)
    with sqlite3.connect(database_path()) as connection:
        cursor = connection.execute(
            "INSERT INTO analyses (created_at, analysis_type, indicator, result_json) VALUES (?, ?, ?, ?)",
            (created_at, analysis_type, indicator[:253], json.dumps(safe_result, ensure_ascii=False)),
        )
        connection.commit()
        return int(cursor.lastrowid)

def list_analyses(limit: int = 50) -> list[dict[str, Any]]:
    initialize()
    bounded_limit = max(1, min(limit, 200))
    with sqlite3.connect(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT id, created_at, analysis_type, indicator, result_json FROM analyses ORDER BY id DESC LIMIT ?",
            (bounded_limit,),
        ).fetchall()
    return [{"id": row["id"], "created_at": row["created_at"],
             "analysis_type": row["analysis_type"], "indicator": row["indicator"],
             "result": json.loads(row["result_json"])} for row in rows]
