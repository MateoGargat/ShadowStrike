"""Tests for collectors.shodan_collector module."""

import pytest
import httpx
import respx

from collectors.shodan_collector import ShodanCollector, INTERNETDB_URL, SHODAN_API_URL
from core.models import AppConfig


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test")


@pytest.fixture
def config_with_key():
    return AppConfig(groq_api_key="test", shodan_api_key="test_shodan_key")


@pytest.fixture
def collector(config):
    return ShodanCollector(config=config)


@pytest.fixture
def collector_with_key(config_with_key):
    return ShodanCollector(config=config_with_key)


class TestShodanCollector:
    @respx.mock
    @pytest.mark.asyncio
    async def test_internetdb(self, collector):
        respx.get(f"{INTERNETDB_URL}/8.8.8.8").mock(
            return_value=httpx.Response(200, json={
                "ip": "8.8.8.8",
                "ports": [53, 443],
                "cpes": ["cpe:/a:google:dns"],
                "hostnames": ["dns.google"],
                "vulns": [],
            })
        )
        result = await collector.collect("8.8.8.8")
        assert result.success is True
        assert len(result.ports) == 2
        assert len(result.ips) == 1
        assert result.ips[0].hostnames == ["dns.google"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_not_found(self, collector):
        respx.get(f"{INTERNETDB_URL}/10.0.0.1").mock(
            return_value=httpx.Response(404, json={"detail": "No information available"})
        )
        result = await collector.collect("10.0.0.1")
        assert result.success is True
        assert result.raw_data.get("found") is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_full_api(self, collector_with_key):
        respx.get(f"{INTERNETDB_URL}/8.8.8.8").mock(
            return_value=httpx.Response(200, json={
                "ip": "8.8.8.8",
                "ports": [53],
                "cpes": [],
                "hostnames": ["dns.google"],
                "vulns": [],
            })
        )
        respx.get(f"{SHODAN_API_URL}/shodan/host/8.8.8.8").mock(
            return_value=httpx.Response(200, json={
                "ip_str": "8.8.8.8",
                "hostnames": ["dns.google"],
                "data": [
                    {
                        "port": 53,
                        "transport": "udp",
                        "product": "Google DNS",
                        "version": "1.0",
                        "data": "DNS server",
                    },
                    {
                        "port": 443,
                        "transport": "tcp",
                        "product": "nginx",
                        "data": "HTTP/1.1 200 OK",
                    },
                ],
            })
        )
        result = await collector_with_key.collect("8.8.8.8")
        assert result.success is True
        assert len(result.ports) == 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_fallback_to_internetdb(self, collector_with_key):
        """If full API fails, InternetDB result should still be returned."""
        respx.get(f"{INTERNETDB_URL}/8.8.8.8").mock(
            return_value=httpx.Response(200, json={
                "ip": "8.8.8.8",
                "ports": [53],
                "cpes": [],
                "hostnames": [],
                "vulns": [],
            })
        )
        respx.get(f"{SHODAN_API_URL}/shodan/host/8.8.8.8").mock(
            return_value=httpx.Response(401, json={"error": "Access denied"})
        )
        result = await collector_with_key.collect("8.8.8.8")
        # Should fallback to InternetDB result
        assert result.success is True
        assert len(result.ports) == 1
