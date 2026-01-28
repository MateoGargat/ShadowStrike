"""Tests for analyzers.llm_providers module."""

from unittest.mock import MagicMock, patch

import pytest

from analyzers.llm_providers import LLMProvider
from core.models import AIAnalysis, AppConfig


@pytest.fixture
def groq_config():
    return AppConfig(groq_api_key="test_groq_key")


@pytest.fixture
def multi_config():
    return AppConfig(
        groq_api_key="test_groq_key",
        openai_api_key="test_openai_key",
        anthropic_api_key="test_anthropic_key",
    )


@pytest.fixture
def empty_config():
    return AppConfig(groq_api_key="")


class TestGetAvailableProviders:
    def test_groq_only(self, groq_config):
        provider = LLMProvider(groq_config)
        available = provider.get_available_providers()
        assert available == ["groq"]

    def test_all_providers(self, multi_config):
        provider = LLMProvider(multi_config)
        available = provider.get_available_providers()
        assert "groq" in available
        assert "openai" in available
        assert "anthropic" in available
        assert len(available) == 3

    def test_no_providers(self, empty_config):
        provider = LLMProvider(empty_config)
        available = provider.get_available_providers()
        assert available == []

    def test_partial_providers(self):
        config = AppConfig(groq_api_key="k1", openai_api_key="k2")
        provider = LLMProvider(config)
        available = provider.get_available_providers()
        assert "groq" in available
        assert "openai" in available
        assert "anthropic" not in available


class TestCallProvider:
    def test_unsupported_provider(self, groq_config):
        provider = LLMProvider(groq_config)
        with pytest.raises(ValueError, match="Unsupported"):
            provider.call(
                provider="unsupported",
                model="test",
                system_prompt="test",
                user_prompt="test",
                response_model=AIAnalysis,
            )

    def test_groq_call(self, groq_config):
        provider = LLMProvider(groq_config)
        mock_analysis = AIAnalysis(
            risk_score=50, executive_summary="Test", attack_surface_size="S",
            findings=[], exposed_services_summary="S", recommendations=[],
        )

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_analysis

        with patch.object(provider, "_get_client", return_value=mock_client):
            result = provider.call(
                provider="groq",
                model="llama-3.3-70b-versatile",
                system_prompt="You are a test.",
                user_prompt="Analyze this.",
                response_model=AIAnalysis,
            )
            assert isinstance(result, AIAnalysis)
            assert result.risk_score == 50

    def test_anthropic_call_uses_messages(self, multi_config):
        provider = LLMProvider(multi_config)
        mock_analysis = AIAnalysis(
            risk_score=30, executive_summary="Test", attack_surface_size="S",
            findings=[], exposed_services_summary="S", recommendations=[],
        )

        mock_client = MagicMock()
        mock_client.messages.create.return_value = mock_analysis

        with patch.object(provider, "_get_client", return_value=mock_client):
            result = provider.call(
                provider="anthropic",
                model="claude-3-5-haiku",
                system_prompt="You are a test.",
                user_prompt="Analyze this.",
                response_model=AIAnalysis,
            )
            assert isinstance(result, AIAnalysis)
            # Verify that messages.create was called (not chat.completions.create)
            mock_client.messages.create.assert_called_once()


class TestLazyInit:
    def test_groq_no_key_raises(self):
        config = AppConfig(groq_api_key="")
        provider = LLMProvider(config)
        with pytest.raises(ValueError, match="Groq API key"):
            provider._init_groq_client()

    def test_openai_no_key_raises(self):
        config = AppConfig(groq_api_key="test")
        provider = LLMProvider(config)
        with pytest.raises(ValueError, match="OpenAI API key"):
            provider._init_openai_client()

    def test_anthropic_no_key_raises(self):
        config = AppConfig(groq_api_key="test")
        provider = LLMProvider(config)
        with pytest.raises(ValueError, match="Anthropic API key"):
            provider._init_anthropic_client()

    def test_client_caching(self, groq_config):
        provider = LLMProvider(groq_config)
        mock_client = MagicMock()
        provider._clients["groq"] = mock_client
        # Should return the cached client
        result = provider._get_client("groq")
        assert result is mock_client
