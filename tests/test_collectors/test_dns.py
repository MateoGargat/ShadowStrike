"""Tests for collectors.dns_resolver module."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from collectors.dns_resolver import DNSCollector
from core.models import AppConfig, SubdomainRecord


@pytest.fixture
def config():
    return AppConfig(groq_api_key="test", dns_timeout=5)


@pytest.fixture
def collector(config):
    return DNSCollector(config=config)


def _mock_rdata(text: str):
    rd = MagicMock()
    rd.to_text.return_value = text
    return rd


def _mock_answer(*texts):
    records = [_mock_rdata(t) for t in texts]
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(records)
    answer.__getitem__ = lambda self, i: records[i]
    return answer


class TestDNSCollector:
    @pytest.mark.asyncio
    async def test_a_record(self, collector):
        with patch.object(collector._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            async def resolve_side_effect(domain, rtype):
                if rtype == "A":
                    return _mock_answer("1.2.3.4")
                raise Exception("NoAnswer")

            mock_resolve.side_effect = resolve_side_effect
            result = await collector.collect("example.com")
            assert result.success is True
            assert result.dns is not None
            assert "1.2.3.4" in result.dns.a

    @pytest.mark.asyncio
    async def test_all_types(self, collector):
        with patch.object(collector._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            async def resolve_side_effect(domain, rtype):
                records = {
                    "A": _mock_answer("1.2.3.4"),
                    "AAAA": _mock_answer("2001:db8::1"),
                    "MX": _mock_answer("10 mail.example.com."),
                    "NS": _mock_answer("ns1.example.com."),
                    "TXT": _mock_answer('"v=spf1 include:_spf.google.com ~all"'),
                    "CNAME": _mock_answer("other.example.com."),
                    "SOA": _mock_answer("ns1.example.com. admin.example.com. 2024 3600 900 604800 86400"),
                }
                if rtype in records:
                    return records[rtype]
                raise Exception("NoAnswer")

            mock_resolve.side_effect = resolve_side_effect
            result = await collector.collect("example.com")
            assert result.success is True
            assert len(result.dns.a) == 1
            assert len(result.dns.mx) == 1
            assert result.dns.soa is not None

    @pytest.mark.asyncio
    async def test_nxdomain(self, collector):
        import dns.resolver
        with patch.object(collector._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NXDOMAIN("not found")
            result = await collector.collect("nonexistent.example.com")
            assert result.success is True
            assert len(result.dns.a) == 0

    @pytest.mark.asyncio
    async def test_timeout(self, collector):
        import dns.exception
        with patch.object(collector._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = dns.exception.Timeout("timeout")
            result = await collector.collect("slow.example.com")
            assert result.success is True  # gracefully handled
            assert len(result.dns.a) == 0

    @pytest.mark.asyncio
    async def test_batch_resolve(self, collector):
        subdomains = [
            SubdomainRecord(name="www.example.com", source="test"),
            SubdomainRecord(name="api.example.com", source="test"),
        ]
        with patch.object(collector._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.return_value = _mock_answer("1.2.3.4")
            dns_records, ips = await collector.resolve_subdomains(subdomains)
            assert len(dns_records) == 2
            assert len(ips) >= 2

    @pytest.mark.asyncio
    async def test_no_answer(self, collector):
        import dns.resolver
        with patch.object(collector._resolver, "resolve", new_callable=AsyncMock) as mock_resolve:
            mock_resolve.side_effect = dns.resolver.NoAnswer("no answer")
            result = await collector.collect("empty.example.com")
            assert result.success is True
            assert len(result.dns.a) == 0
