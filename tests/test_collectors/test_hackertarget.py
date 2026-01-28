"""Tests for collectors.hackertarget module."""

import pytest
import httpx
import respx

from collectors.hackertarget import HackerTargetCollector, HACKERTARGET_HOSTSEARCH, HACKERTARGET_ASLOOKUP
from core.models import AppConfig


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test")


@pytest.fixture
def collector(config):
    return HackerTargetCollector(config=config)


class TestHackerTargetCollector:
    @respx.mock
    @pytest.mark.asyncio
    async def test_hostsearch(self, collector):
        response_text = "www.example.com,93.184.216.34\nmail.example.com,93.184.216.35"
        respx.get(HACKERTARGET_HOSTSEARCH).mock(
            return_value=httpx.Response(200, text=response_text)
        )
        result = await collector.collect("example.com")
        assert result.success is True
        assert len(result.subdomains) == 2
        assert len(result.ips) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_error_response(self, collector):
        respx.get(HACKERTARGET_HOSTSEARCH).mock(
            return_value=httpx.Response(200, text="error check your search parameter")
        )
        result = await collector.collect("example.com")
        assert result.success is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_api_limit(self, collector):
        respx.get(HACKERTARGET_HOSTSEARCH).mock(
            return_value=httpx.Response(200, text="error API count exceeded")
        )
        result = await collector.collect("example.com")
        assert result.success is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_aslookup(self, collector):
        respx.get(HACKERTARGET_ASLOOKUP).mock(
            return_value=httpx.Response(200, text='"93.184.216.34","15133","EDGECAST"')
        )
        asn = await collector.asn_lookup("93.184.216.34")
        assert asn is not None
        assert asn.asn == "15133"
        assert "EDGECAST" in asn.name
