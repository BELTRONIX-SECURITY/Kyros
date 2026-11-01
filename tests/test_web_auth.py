from fastapi.testclient import TestClient

from kyros.web import app

client = TestClient(app)


def set_credentials(monkeypatch):
    monkeypatch.setenv("KYROS_AUTH_USERNAME", "soc-admin")
    monkeypatch.setenv("KYROS_AUTH_PASSWORD", "a-strong-test-password-123")


def test_dashboard_requires_auth(monkeypatch):
    set_credentials(monkeypatch)
    response = client.get("/")
    assert response.status_code == 401


def test_dashboard_accepts_configured_credentials(monkeypatch):
    set_credentials(monkeypatch)
    response = client.get("/", auth=("soc-admin", "a-strong-test-password-123"))
    assert response.status_code == 200
    assert "KYROS" in response.text
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_api_requires_auth(monkeypatch):
    set_credentials(monkeypatch)
    response = client.post(
        "/api/analyze/ip",
        json={"indicator": "8.8.8.8"},
        headers={"X-Kyros-Request": "1"},
    )
    assert response.status_code == 401


def test_api_accepts_configured_credentials(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    response = client.post(
        "/api/analyze/ip",
        json={"indicator": "8.8.8.8"},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 200
    assert response.json()["scope"] == "public"
    assert response.json()["external_lookup"] is False


def test_external_ip_lookup_requires_explicit_opt_in(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    calls = []

    async def fake_lookup(ip):
        calls.append(ip)
        return [{"provider": "test-provider", "status": "ok", "data": {"country": "US"}}]

    monkeypatch.setattr("kyros.web.lookup_ip_external", fake_lookup)
    response = client.post(
        "/api/analyze/ip",
        json={"indicator": "8.8.8.8", "external_lookup": True},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 200
    assert calls == ["8.8.8.8"]
    assert response.json()["external_lookup"] is True
    assert response.json()["external_sources"][0]["provider"] == "test-provider"


def test_external_lookup_skips_non_public_ip(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))

    async def unexpected_lookup(ip):
        raise AssertionError("Non-public IP must not be sent to external providers")

    monkeypatch.setattr("kyros.web.lookup_ip_external", unexpected_lookup)
    response = client.post(
        "/api/analyze/ip",
        json={"indicator": "192.168.1.10", "external_lookup": True},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 200
    assert response.json()["external_lookup"] is False
    assert "omitida" in response.json()["external_lookup_note"]


def test_api_rejects_post_without_csrf_header(monkeypatch):
    set_credentials(monkeypatch)
    response = client.post(
        "/api/analyze/ip",
        json={"indicator": "8.8.8.8"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 403


def test_file_upload_is_analyzed_without_execution_or_external_submission(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    response = client.post(
        "/api/analyze/file",
        files={"file": ("sample.txt", b"safe test content", "text/plain")},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 200
    result = response.json()
    assert result["execution_performed"] is False
    assert result["external_submission"] is False
    assert len(result["hashes"]["sha256"]) == 64


def test_file_upload_rejects_files_over_10mb(monkeypatch):
    set_credentials(monkeypatch)
    response = client.post(
        "/api/analyze/file",
        files={"file": ("large.bin", b"x" * (10 * 1024 * 1024 + 1), "application/octet-stream")},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 413


def test_health_probe_is_public():
    response = client.get("/api/health")
    assert response.status_code == 200


def test_missing_auth_configuration_fails_closed(monkeypatch):
    monkeypatch.delenv("KYROS_AUTH_USERNAME", raising=False)
    monkeypatch.delenv("KYROS_AUTH_PASSWORD", raising=False)
    response = client.get("/", auth=("soc-admin", "a-strong-test-password-123"))
    assert response.status_code == 503


def test_weak_password_configuration_fails_closed(monkeypatch):
    monkeypatch.setenv("KYROS_AUTH_USERNAME", "soc-admin")
    monkeypatch.setenv("KYROS_AUTH_PASSWORD", "too-short")
    response = client.get("/", auth=("soc-admin", "too-short"))
    assert response.status_code == 503


def test_dashboard_summary_and_incident_api(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    auth = ("soc-admin", "a-strong-test-password-123")
    headers = {"X-Kyros-Request": "1"}
    summary = client.get("/api/dashboard/summary", auth=auth)
    assert summary.status_code == 200
    assert summary.json()["total_analyses"] == 0

    created = client.post(
        "/api/incidents",
        json={"title": "Suspicious login review", "severity": "high", "source": "siem"},
        headers=headers,
        auth=auth,
    )
    assert created.status_code == 200
    incident_id = created.json()["id"]
    assert created.json()["status"] == "open"

    listing = client.get("/api/incidents", auth=auth)
    assert listing.status_code == 200
    assert listing.json()["items"][0]["id"] == incident_id

    updated = client.patch(
        f"/api/incidents/{incident_id}",
        json={"status": "acknowledged"},
        headers=headers,
        auth=auth,
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "acknowledged"


def test_incident_rejects_invalid_severity(monkeypatch):
    set_credentials(monkeypatch)
    response = client.post(
        "/api/incidents",
        json={"title": "Invalid severity", "severity": "extreme"},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 422


def test_email_api_is_local_and_persisted(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    response = client.post(
        "/api/analyze/email",
        json={"indicator": "analyst@example.com"},
        headers={"X-Kyros-Request": "1"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 200
    assert response.json()["external_submission"] is False
    assert response.json()["risk"] == "unknown"


def test_domain_dns_requires_explicit_opt_in(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    calls = []

    def fake_dns(domain):
        calls.append(domain)
        return {"status": "ok", "records": {"A": ["192.0.2.10"]}}

    monkeypatch.setattr("kyros.web.lookup_domain_dns", fake_dns)
    auth = ("soc-admin", "a-strong-test-password-123")
    headers = {"X-Kyros-Request": "1"}
    local = client.post(
        "/api/analyze/domain",
        json={"indicator": "example.com"},
        headers=headers,
        auth=auth,
    )
    assert local.status_code == 200
    assert calls == []
    external = client.post(
        "/api/analyze/domain",
        json={"indicator": "example.com", "external_lookup": True},
        headers=headers,
        auth=auth,
    )
    assert external.status_code == 200
    assert calls == ["example.com"]
    assert external.json()["dns"]["records"]["A"] == ["192.0.2.10"]


def test_local_threat_intel_and_event_correlation(monkeypatch, tmp_path):
    set_credentials(monkeypatch)
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    auth = ("soc-admin", "a-strong-test-password-123")
    headers = {"X-Kyros-Request": "1"}
    ioc = client.post(
        "/api/threat-intel/indicators",
        json={"indicator_type": "ip", "indicator": "203.0.113.7",
              "confidence": 70, "source": "internal-test", "description": "Test IOC"},
        headers=headers, auth=auth,
    )
    assert ioc.status_code == 200
    event = client.post(
        "/api/events",
        json={"source": "test-sensor", "event_type": "connection",
              "indicator": "203.0.113.7", "severity": "medium"},
        headers=headers, auth=auth,
    )
    assert event.status_code == 200
    correlated = client.get("/api/correlation", auth=auth)
    assert correlated.status_code == 200
    assert correlated.json()["items"][0]["threat_match"]["indicator"] == "203.0.113.7"
    assert correlated.json()["items"][0]["incident_confirmed"] is False
