from kyros import database


def test_incident_case_stores_timeline_and_evidence_metadata(tmp_path, monkeypatch):
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    incident_id = database.create_incident(
        "Actividad sospechosa", "Alerta de demostración", "medium", "manual", "8.8.8.8"
    )

    timeline_id = database.add_incident_timeline(
        incident_id, "observation", "Se revisó la alerta de prueba.", "analyst",
        "2026-11-02T10:30:00Z",
    )
    evidence_id = database.add_incident_evidence(
        incident_id, "file_hash", "Repositorio controlado de evidencias",
        "a" * 64, "analyst", "Hash de muestra ficticia",
    )

    case = database.get_incident_case(incident_id)
    assert timeline_id is not None
    assert evidence_id is not None
    assert case is not None
    assert case["incident"]["id"] == incident_id
    assert len(case["timeline"]) == 1
    assert case["timeline"][0]["description"] == "Se revisó la alerta de prueba."
    assert len(case["evidence"]) == 1
    assert case["evidence"][0]["sha256"] == "a" * 64


def test_incident_case_returns_none_for_unknown_incident(tmp_path, monkeypatch):
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    assert database.get_incident_case(999) is None
    assert database.add_incident_timeline(999, "observation", "Detalle", "manual") is None
    assert database.add_incident_evidence(999, "other", "ref", "", "manual", "") is None
