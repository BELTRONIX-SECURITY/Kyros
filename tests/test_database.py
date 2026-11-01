from kyros.database import list_analyses, save_analysis


def test_local_history_roundtrip(tmp_path, monkeypatch):
    db_path = tmp_path / "kyros.sqlite3"
    monkeypatch.setenv("KYROS_DB_PATH", str(db_path))
    record_id = save_analysis("ip", "203.0.113.5", {"risk": "unknown"})
    rows = list_analyses()
    assert rows[0]["id"] == record_id
    assert rows[0]["analysis_type"] == "ip"
    assert rows[0]["result"]["risk"] == "unknown"


def test_file_history_does_not_retain_filename_or_file_content(tmp_path, monkeypatch):
    db_path = tmp_path / "kyros.sqlite3"
    monkeypatch.setenv("KYROS_DB_PATH", str(db_path))
    save_analysis(
        "file",
        "a" * 64,
        {
            "filename": "confidential-report.xlsx",
            "hashes": {"sha256": "a" * 64},
            "assessment": "Static triage",
        },
    )
    row = list_analyses()[0]
    assert "filename" not in row["result"]
    assert row["indicator"] == "a" * 64
    assert "confidential-report.xlsx" not in str(row)


def test_incident_lifecycle_and_dashboard_summary(tmp_path, monkeypatch):
    from kyros.database import create_incident, dashboard_summary, list_incidents, update_incident_status

    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    incident_id = create_incident("Suspicious login review", "Review sign-in telemetry", "high", "siem", "203.0.113.8")
    items = list_incidents()
    assert items[0]["id"] == incident_id
    assert items[0]["status"] == "open"
    summary = dashboard_summary()
    assert summary["open_incidents"] == 1
    assert summary["incidents_by_severity"]["high"] == 1
    assert update_incident_status(incident_id, "acknowledged") is True
    assert list_incidents()[0]["status"] == "acknowledged"
    assert update_incident_status(9999, "closed") is False
    assert update_incident_status(incident_id, "closed") is True
    assert dashboard_summary()["open_incidents"] == 0
