"""Local SQLite persistence for Kyros SOC. Uploaded file bytes are never stored."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def database_path() -> Path:
    configured = os.getenv("KYROS_DB_PATH")
    path = Path(configured).expanduser() if configured else Path.home() / ".kyros" / "kyros_soc.sqlite3"
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
        connection.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL,
                indicator TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS threat_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                indicator_type TEXT NOT NULL, indicator TEXT NOT NULL UNIQUE,
                confidence INTEGER NOT NULL, source TEXT NOT NULL, description TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
                source TEXT NOT NULL, event_type TEXT NOT NULL, indicator TEXT NOT NULL,
                severity TEXT NOT NULL, details TEXT NOT NULL
            )
        """)
        connection.commit()


def add_threat_indicator(indicator_type: str, indicator: str, confidence: int,
                         source: str, description: str) -> int:
    initialize()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path()) as connection:
        connection.execute(
            """INSERT INTO threat_indicators
            (created_at, indicator_type, indicator, confidence, source, description)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(indicator) DO UPDATE SET confidence=excluded.confidence,
            source=excluded.source, description=excluded.description""",
            (now, indicator_type, indicator, confidence, source[:100], description[:1000]),
        )
        row = connection.execute("SELECT id FROM threat_indicators WHERE indicator = ?", (indicator,)).fetchone()
        connection.commit()
        return int(row[0])


def list_threat_indicators(limit: int = 100) -> list[dict[str, Any]]:
    initialize()
    with sqlite3.connect(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM threat_indicators ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
    return [dict(row) for row in rows]


def find_threat_indicator(indicator: str) -> dict[str, Any] | None:
    initialize()
    with sqlite3.connect(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute("SELECT * FROM threat_indicators WHERE indicator = ?", (indicator,)).fetchone()
    return dict(row) if row else None


def add_security_event(source: str, event_type: str, indicator: str,
                       severity: str, details: str) -> int:
    initialize()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path()) as connection:
        cursor = connection.execute(
            """INSERT INTO security_events
            (created_at, source, event_type, indicator, severity, details)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (now, source[:100], event_type[:100], indicator[:253], severity, details[:2000]),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_security_events(limit: int = 100) -> list[dict[str, Any]]:
    initialize()
    with sqlite3.connect(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
    return [dict(row) for row in rows]


def correlate_security_events(limit: int = 100) -> list[dict[str, Any]]:
    results = []
    for event in list_security_events(limit):
        match = find_threat_indicator(event["indicator"])
        results.append({
            "event": event, "threat_match": match,
            "assessment": "Coincidencia con IOC local; requiere validación contextual." if match
            else "Sin coincidencia en el catálogo IOC local.",
            "incident_confirmed": False,
        })
    return results


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
    return [
        {"id": row["id"], "created_at": row["created_at"],
         "analysis_type": row["analysis_type"], "indicator": row["indicator"],
         "result": json.loads(row["result_json"])}
        for row in rows
    ]


def create_incident(title: str, description: str, severity: str, source: str, indicator: str) -> int:
    initialize()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path()) as connection:
        cursor = connection.execute(
            """INSERT INTO incidents
            (created_at, updated_at, title, description, severity, status, source, indicator)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?)""",
            (now, now, title[:160], description[:2000], severity, source[:60], indicator[:253]),
        )
        connection.commit()
        return int(cursor.lastrowid)


def list_incidents(limit: int = 100) -> list[dict[str, Any]]:
    initialize()
    bounded_limit = max(1, min(limit, 200))
    with sqlite3.connect(database_path()) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (bounded_limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def update_incident_status(incident_id: int, status: str) -> bool:
    initialize()
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(database_path()) as connection:
        cursor = connection.execute(
            "UPDATE incidents SET status = ?, updated_at = ? WHERE id = ?",
            (status, now, incident_id),
        )
        connection.commit()
        return cursor.rowcount == 1


def dashboard_summary() -> dict[str, Any]:
    initialize()
    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with sqlite3.connect(database_path()) as connection:
        total = connection.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        last_24h = connection.execute(
            "SELECT COUNT(*) FROM analyses WHERE created_at >= ?", (since,)
        ).fetchone()[0]
        by_type = dict(connection.execute(
            "SELECT analysis_type, COUNT(*) FROM analyses GROUP BY analysis_type"
        ).fetchall())
        open_incidents = connection.execute(
            "SELECT COUNT(*) FROM incidents WHERE status != 'closed'"
        ).fetchone()[0]
        severity = dict(connection.execute(
            "SELECT severity, COUNT(*) FROM incidents WHERE status != 'closed' GROUP BY severity"
        ).fetchall())
    return {
        "total_analyses": total,
        "analyses_last_24h": last_24h,
        "analyses_by_type": by_type,
        "open_incidents": open_incidents,
        "incidents_by_severity": severity,
        "risk_assessment": "not_determined_without_correlated_telemetry",
    }
