import asyncio

from kyros.external_intel import lookup_indicator, provider_status
import pytest


def test_provider_status_is_disabled_without_keys(monkeypatch):
    for key in ("KYROS_VT_API_KEY", "KYROS_ABUSEIPDB_API_KEY", "KYROS_OTX_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert provider_status() == {"virustotal": False, "abuseipdb": False, "otx": False}


def test_virustotal_rejects_non_sha256_before_network(monkeypatch):
    monkeypatch.setenv("KYROS_VT_API_KEY", "test-key")
    with pytest.raises(ValueError, match="SHA-256"):
        asyncio.run(lookup_indicator("virustotal", "ip", "8.8.8.8"))


def test_abuseipdb_rejects_domain_before_network(monkeypatch):
    monkeypatch.setenv("KYROS_ABUSEIPDB_API_KEY", "test-key")
    with pytest.raises(ValueError, match="IP"):
        asyncio.run(lookup_indicator("abuseipdb", "domain", "example.com"))


def test_unconfigured_provider_is_rejected(monkeypatch):
    monkeypatch.delenv("KYROS_OTX_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="no configurado"):
        asyncio.run(lookup_indicator("otx", "domain", "example.com"))


from kyros.external_intel import build_assessment


def test_virustotal_no_detections_is_not_called_safe():
    report = build_assessment({
        "provider": "virustotal",
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 60},
        "detected_type": "Office Open XML Spreadsheet document",
        "names": ["kwoxrk.exe"],
    }, "sha256")
    assert report["risk"] == "unknown"
    assert report["verdict"] == "no_detections_not_conclusive"
    assert "no demuestra seguridad" in report["conclusion"]
    assert any("extensión no coincide" in item for item in report["findings"])


def test_virustotal_malicious_detections_raise_risk():
    report = build_assessment({
        "provider": "virustotal",
        "last_analysis_stats": {"malicious": 7, "suspicious": 0},
        "detected_type": "Windows executable",
        "names": ["sample.exe"],
    }, "sha256")
    assert report["risk"] == "high"
    assert report["verdict"] == "detections_reported"
