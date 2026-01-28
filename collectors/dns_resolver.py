"""DNS resolution collector using dnspython."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import dns.asyncresolver
import dns.exception
import dns.resolver

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import (
    AppConfig,
    CollectorResult,
    DNSRecords,
    IPRecord,
    SubdomainRecord,
)

logger = logging.getLogger(__name__)


class DNSCollector(BaseCollector):
    """Collect DNS records for a domain and its subdomains."""

    SOURCE_NAME = "dns"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)
        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.timeout = config.dns_timeout
        self._resolver.lifetime = config.dns_timeout

    async def collect(self, target: str) -> CollectorResult:
        """Resolve DNS records for the target domain."""
        dns_records = await self._resolve_domain(target)
        ips: list[IPRecord] = []

        # Collect IPs from A records
        for addr in dns_records.a:
            ips.append(IPRecord(address=addr, version=4, hostnames=[target]))
        for addr in dns_records.aaaa:
            ips.append(IPRecord(address=addr, version=6, hostnames=[target]))

        raw_data = {
            "domain": target,
            "a": dns_records.a,
            "aaaa": dns_records.aaaa,
            "mx": dns_records.mx,
            "ns": dns_records.ns,
            "txt": dns_records.txt,
            "cname": dns_records.cname,
            "soa": dns_records.soa,
        }

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            dns=dns_records,
            ips=ips,
            raw_data=raw_data,
        )

    async def resolve_subdomains(
        self, subdomains: list[SubdomainRecord]
    ) -> tuple[list[DNSRecords], list[IPRecord]]:
        """Batch-resolve A/AAAA records for discovered subdomains.

        Args:
            subdomains: List of subdomain records to resolve.

        Returns:
            Tuple of (dns_records_list, ip_records_list).
        """
        all_dns: list[DNSRecords] = []
        all_ips: list[IPRecord] = []

        # Process in batches of 10
        batch_size = 10
        for i in range(0, len(subdomains), batch_size):
            batch = subdomains[i : i + batch_size]
            tasks = [self._resolve_subdomain(sub.name) for sub in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for sub, result in zip(batch, results):
                if isinstance(result, Exception):
                    logger.debug("DNS resolve failed for %s: %s", sub.name, result)
                    continue
                dns_rec, ips = result
                all_dns.append(dns_rec)
                all_ips.extend(ips)

        return all_dns, all_ips

    async def _resolve_subdomain(
        self, name: str
    ) -> tuple[DNSRecords, list[IPRecord]]:
        """Resolve A and AAAA records for a single subdomain."""
        dns_rec = DNSRecords(domain=name)
        ips: list[IPRecord] = []

        # A records
        try:
            answers = await self._resolver.resolve(name, "A")
            dns_rec.a = [rdata.to_text() for rdata in answers]
            for addr in dns_rec.a:
                ips.append(IPRecord(address=addr, version=4, hostnames=[name]))
        except (dns.exception.DNSException, Exception):
            pass

        # AAAA records
        try:
            answers = await self._resolver.resolve(name, "AAAA")
            dns_rec.aaaa = [rdata.to_text() for rdata in answers]
            for addr in dns_rec.aaaa:
                ips.append(IPRecord(address=addr, version=6, hostnames=[name]))
        except (dns.exception.DNSException, Exception):
            pass

        return dns_rec, ips

    async def _resolve_domain(self, domain: str) -> DNSRecords:
        """Resolve all DNS record types for a domain."""
        records = DNSRecords(domain=domain)

        # Resolve each type independently
        record_types = {
            "A": "a",
            "AAAA": "aaaa",
            "MX": "mx",
            "NS": "ns",
            "TXT": "txt",
            "CNAME": "cname",
            "SOA": "soa",
        }

        for rtype, attr in record_types.items():
            try:
                answers = await self._resolver.resolve(domain, rtype)
                if rtype == "SOA":
                    records.soa = answers[0].to_text()
                else:
                    values = [rdata.to_text() for rdata in answers]
                    setattr(records, attr, values)
            except dns.resolver.NoAnswer:
                logger.debug("No %s records for %s", rtype, domain)
            except dns.resolver.NXDOMAIN:
                logger.warning("Domain %s does not exist (NXDOMAIN)", domain)
                break
            except dns.exception.Timeout:
                logger.warning("DNS timeout resolving %s %s", rtype, domain)
            except Exception as exc:
                logger.debug("DNS %s error for %s: %s", rtype, domain, exc)

        return records

    def _parse_cached(self, data: dict) -> dict:
        """Restore DNS records from cached data."""
        dns_rec = DNSRecords(
            domain=data.get("domain", ""),
            a=data.get("a", []),
            aaaa=data.get("aaaa", []),
            mx=data.get("mx", []),
            ns=data.get("ns", []),
            txt=data.get("txt", []),
            cname=data.get("cname", []),
            soa=data.get("soa"),
        )
        ips = []
        for addr in dns_rec.a:
            ips.append(IPRecord(address=addr, version=4))
        for addr in dns_rec.aaaa:
            ips.append(IPRecord(address=addr, version=6))
        return {"dns": dns_rec, "ips": ips}
