"""Tests for collectors.crtsh module."""

import pytest
import httpx
import respx

from collectors.crtsh import CrtshCollector, CRT_SH_URL
from core.models import AppConfig


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test")


@pytest.fixture
def collector(config):
    return CrtshCollector(config=config)


class TestCrtshCollector:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self, collector):
        respx.get(CRT_SH_URL).mock(
            return_value=httpx.Response(200, json=[
                {"name_value": "www.example.com"},
                {"name_value": "api.example.com"},
                {"name_value": "mail.example.com"},
            ])
        )
        result = await collector.collect("example.com")
        assert result.success is True
        assert len(result.subdomains) == 3
        names = {s.name for s in result.subdomains}
        assert "www.example.com" in names
        assert "api.example.com" in names

    @respx.mock
    @pytest.mark.asyncio
    async def test_wildcard_filtering(self, collector):
        respx.get(CRT_SH_URL).mock(
            return_value=httpx.Response(200, json=[
                {"name_value": "*.example.com"},
                {"name_value": "www.example.com"},
            ])
        )
        result = await collector.collect("example.com")
        assert result.success is True
        assert len(result.subdomains) == 1
        assert result.subdomains[0].name == "www.example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_multiline_name_value(self, collector):
        respx.get(CRT_SH_URL).mock(
            return_value=httpx.Response(200, json=[
                {"name_value": "a.example.com\nb.example.com\n*.example.com"},
            ])
        )
        result = await collector.collect("example.com")
        assert result.success is True
        assert len(result.subdomains) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(self, collector):
        respx.get(CRT_SH_URL).mock(side_effect=httpx.TimeoutException("timeout"))
        result = await collector.collect("example.com")
        assert result.success is False
        assert "timeout" in result.error.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_response(self, collector):
        respx.get(CRT_SH_URL).mock(
            return_value=httpx.Response(200, json=[])
        )
        result = await collector.collect("example.com")
        assert result.success is True
        assert len(result.subdomains) == 0

    @respx.mock
    @pytest.mark.asyncio
    async def test_http_error(self, collector):
        respx.get(CRT_SH_URL).mock(
            return_value=httpx.Response(503)
        )
        result = await collector.collect("example.com")
        assert result.success is False
