from kyros.external_intel import lookup_indicator, provider_status
import pytest


def test_provider_status_is_disabled_without_keys(monkeypatch):
    for key in ("KYROS_VT_API_KEY", "KYROS_ABUSEIPDB_API_KEY", "KYROS_OTX_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert provider_status() == {"virustotal": False, "abuseipdb": False, "otx": False}


@pytest.mark.asyncio
async def test_virustotal_rejects_non_sha256_before_network(monkeypatch):
    monkeypatch.setenv("KYROS_VT_API_KEY", "test-key")
    with pytest.raises(ValueError, match="SHA-256"):
        await lookup_indicator("virustotal", "ip", "8.8.8.8")


@pytest.mark.asyncio
async def test_abuseipdb_rejects_domain_before_network(monkeypatch):
    monkeypatch.setenv("KYROS_ABUSEIPDB_API_KEY", "test-key")
    with pytest.raises(ValueError, match="IP"):
        await lookup_indicator("abuseipdb", "domain", "example.com")


@pytest.mark.asyncio
async def test_unconfigured_provider_is_rejected(monkeypatch):
    monkeypatch.delenv("KYROS_OTX_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="no configurado"):
        await lookup_indicator("otx", "domain", "example.com")
