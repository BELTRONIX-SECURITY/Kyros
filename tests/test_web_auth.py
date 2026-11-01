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
