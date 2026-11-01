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
