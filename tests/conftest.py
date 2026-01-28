"""Shared test fixtures."""

import pytest
from core.models import AppConfig


@pytest.fixture
def app_config():
    """Default test configuration with no real API keys."""
    return AppConfig(
        groq_api_key="test_key",
        http_timeout=10,
        dns_timeout=5,
        cache_enabled=False,
    )
