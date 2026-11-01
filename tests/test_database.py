from kyros.database import list_analyses, save_analysis

def test_local_history_roundtrip(tmp_path, monkeypatch):
    db_path = tmp_path / "kyros.sqlite3"
    monkeypatch.setenv("KYROS_DB_PATH", str(db_path))
    record_id = save_analysis("ip", "203.0.113.5", {"risk": "unknown"})
    rows = list_analyses()
    assert rows[0]["id"] == record_id
    assert rows[0]["analysis_type"] == "ip"
    assert rows[0]["result"]["risk"] == "unknown"
