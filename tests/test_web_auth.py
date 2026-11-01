from fastapi.testclient import TestClient

from kyros.web import app

client = TestClient(app)


def test_dashboard_requires_auth(monkeypatch):
    monkeypatch.setenv("KYROS_AUTH_USERNAME", "soc-admin")
    monkeypatch.setenv("KYROS_AUTH_PASSWORD", "a-strong-test-password-123")
    response = client.get("/")
    assert response.status_code == 401


def test_dashboard_accepts_configured_credentials(monkeypatch):
    monkeypatch.setenv("KYROS_AUTH_USERNAME", "soc-admin")
    monkeypatch.setenv("KYROS_AUTH_PASSWORD", "a-strong-test-password-123")
    response = client.get("/", auth=("soc-admin", "a-strong-test-password-123"))
    assert response.status_code == 200
    assert "KYROS" in response.text
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_api_requires_auth(monkeypatch):
    monkeypatch.setenv("KYROS_AUTH_USERNAME", "soc-admin")
    monkeypatch.setenv("KYROS_AUTH_PASSWORD", "a-strong-test-password-123")
    response = client.post("/api/analyze/ip", json={"indicator": "8.8.8.8"})
    assert response.status_code == 401


def test_api_accepts_configured_credentials(monkeypatch, tmp_path):
    monkeypatch.setenv("KYROS_AUTH_USERNAME", "soc-admin")
    monkeypatch.setenv("KYROS_AUTH_PASSWORD", "a-strong-test-password-123")
    monkeypatch.setenv("KYROS_DB_PATH", str(tmp_path / "kyros.sqlite3"))
    response = client.post(
        "/api/analyze/ip",
        json={"indicator": "8.8.8.8"},
        auth=("soc-admin", "a-strong-test-password-123"),
    )
    assert response.status_code == 200
    assert response.json()["scope"] == "public"


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
