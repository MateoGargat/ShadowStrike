"""Tests for collectors.virustotal module."""

import pytest
import httpx
import respx

from collectors.virustotal import VirusTotalCollector, VT_API_URL
from core.models import AppConfig


@pytest.fixture
def config_with_key():
    return AppConfig(groq_api_key="test", virustotal_api_key="test_vt_key")


@pytest.fixture
def config_no_key():
    return AppConfig(groq_api_key="test")


@pytest.fixture
def collector(config_with_key):
    return VirusTotalCollector(config=config_with_key)


@pytest.fixture
def collector_no_key(config_no_key):
    return VirusTotalCollector(config=config_no_key)


class TestVirusTotalCollector:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self, collector):
        respx.get(f"{VT_API_URL}/domains/example.com/subdomains").mock(
            return_value=httpx.Response(200, json={
                "data": [
                    {"id": "www.example.com", "type": "domain"},
                    {"id": "api.example.com", "type": "domain"},
                    {"id": "mail.example.com", "type": "domain"},
                ]
            })
        )
        result = await collector.collect("example.com")
        assert result.success is True
        assert len(result.subdomains) == 3

    @pytest.mark.asyncio
    async def test_no_key(self, collector_no_key):
        result = await collector_no_key.collect("example.com")
        assert result.success is False
        assert "No VirusTotal API key" in result.error

    @respx.mock
    @pytest.mark.asyncio
    async def test_rate_limited(self, collector):
        respx.get(f"{VT_API_URL}/domains/example.com/subdomains").mock(
            return_value=httpx.Response(429, json={"error": {"code": "QuotaExceededError"}})
        )
        result = await collector.collect("example.com")
        assert result.success is False
