import asyncio

import pytest

from kyros.ai import MAX_AI_CONTEXT, ai_configuration, analyze_soc_context


def test_ai_disabled_without_configuration(monkeypatch):
    monkeypatch.delenv("KYROS_AI_BASE_URL", raising=False)
    monkeypatch.delenv("KYROS_AI_MODEL", raising=False)
    assert ai_configuration()["enabled"] is False


def test_ai_accepts_local_ollama_compatible_endpoint(monkeypatch):
    monkeypatch.setenv("KYROS_AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("KYROS_AI_MODEL", "qwen2.5:7b")
    assert ai_configuration()["enabled"] is True
    assert ai_configuration()["provider"] == "openai_compatible"


def test_ai_rejects_remote_plain_http(monkeypatch):
    monkeypatch.setenv("KYROS_AI_BASE_URL", "http://ai.example.com/v1")
    monkeypatch.setenv("KYROS_AI_MODEL", "model")
    assert ai_configuration()["enabled"] is False
    assert ai_configuration()["provider"] == "https_required"


def test_ai_requires_configured_provider(monkeypatch):
    monkeypatch.delenv("KYROS_AI_BASE_URL", raising=False)
    monkeypatch.delenv("KYROS_AI_MODEL", raising=False)
    with pytest.raises(RuntimeError):
        asyncio.run(analyze_soc_context("SOC alert sample"))


def test_ai_context_length_is_bounded(monkeypatch):
    monkeypatch.setenv("KYROS_AI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("KYROS_AI_MODEL", "local-model")
    with pytest.raises(ValueError):
        asyncio.run(analyze_soc_context("A" * (MAX_AI_CONTEXT + 1)))
