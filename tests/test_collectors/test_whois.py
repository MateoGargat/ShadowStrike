"""Tests for collectors.whois_collector module."""

from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest

from collectors.whois_collector import WhoisCollector
from core.models import AppConfig


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test")


@pytest.fixture
def collector(config):
    return WhoisCollector(config=config)


class TestWhoisCollector:
    @pytest.mark.asyncio
    async def test_success(self, collector):
        mock_data = {
            "domain_name": ["EXAMPLE.COM", "example.com"],
            "registrar": "Test Registrar, Inc.",
            "creation_date": datetime(2020, 1, 1),
            "expiration_date": datetime(2025, 1, 1),
            "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
            "org": "Example Organization",
            "country": "US",
            "emails": ["admin@example.com"],
            "dnssec": "unsigned",
            "status": ["clientTransferProhibited"],
        }
        mock_whois = MagicMock()
        mock_whois.get = mock_data.get
        mock_whois.__getitem__ = mock_data.__getitem__

        with patch("collectors.whois_collector.whois.whois", return_value=mock_whois):
            result = await collector.collect("example.com")
            assert result.success is True
            assert result.whois is not None
            assert result.whois.registrar == "Test Registrar, Inc."
            assert result.whois.organization == "Example Organization"

    @pytest.mark.asyncio
    async def test_not_found(self, collector):
        mock_whois = MagicMock()
        mock_whois.get = MagicMock(return_value=None)

        with patch("collectors.whois_collector.whois.whois", return_value=mock_whois):
            result = await collector.collect("nonexistent.example")
            assert result.success is False

    @pytest.mark.asyncio
    async def test_partial_data(self, collector):
        mock_data = {
            "domain_name": "example.com",
            "registrar": "Some Registrar",
        }
        mock_whois = MagicMock()
        mock_whois.get = lambda k, d=None: mock_data.get(k, d)

        with patch("collectors.whois_collector.whois.whois", return_value=mock_whois):
            result = await collector.collect("example.com")
            assert result.success is True
            assert result.whois.registrar == "Some Registrar"
            assert result.whois.organization is None

    @pytest.mark.asyncio
    async def test_exception(self, collector):
        with patch("collectors.whois_collector.whois.whois", side_effect=Exception("Network error")):
            result = await collector.collect("example.com")
            assert result.success is False
            assert "Network error" in result.error
