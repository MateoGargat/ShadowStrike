"""HackerTarget API collector for subdomains and ASN data."""

from __future__ import annotations

import logging
from typing import Optional

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import (
    AppConfig,
    ASNInfo,
    CollectorResult,
    IPRecord,
    SubdomainRecord,
)

logger = logging.getLogger(__name__)

HACKERTARGET_HOSTSEARCH = "https://api.hackertarget.com/hostsearch/"
HACKERTARGET_ASLOOKUP = "https://api.hackertarget.com/aslookup/"


class HackerTargetCollector(BaseCollector):
    """Collect subdomains and ASN info from HackerTarget free API."""

    SOURCE_NAME = "hackertarget"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)
        self._rate_delay = 2.0  # conservative: 100 req/day limit

    async def collect(self, target: str) -> CollectorResult:
        """Query HackerTarget hostsearch for subdomains + IPs."""
        subdomains: list[SubdomainRecord] = []
        ips: list[IPRecord] = []
        seen_subs: set[str] = set()
        seen_ips: set[str] = set()

        # Hostsearch
        try:
            response = await self._http_get(
                HACKERTARGET_HOSTSEARCH, params={"q": target}
            )
            text = response.text.strip()

            if text.startswith("error"):
                return CollectorResult(
                    source=self.SOURCE_NAME,
                    success=False,
                    error=f"HackerTarget error: {text}",
                )

            if text and text != "No records found":
                for line in text.split("\n"):
                    parts = line.strip().split(",")
                    if len(parts) >= 2:
                        hostname = parts[0].strip().lower()
                        ip_addr = parts[1].strip()

                        if hostname and hostname not in seen_subs:
                            seen_subs.add(hostname)
                            subdomains.append(
                                SubdomainRecord(name=hostname, source=self.SOURCE_NAME)
                            )

                        if ip_addr and ip_addr not in seen_ips:
                            seen_ips.add(ip_addr)
                            ips.append(
                                IPRecord(
                                    address=ip_addr,
                                    version=4 if "." in ip_addr else 6,
                                    hostnames=[hostname] if hostname else [],
                                )
                            )

        except Exception as exc:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"Hostsearch failed: {exc}",
            )

        logger.info(
            "[hackertarget] Found %d subdomains, %d IPs for %s",
            len(subdomains), len(ips), target,
        )

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            subdomains=subdomains,
            ips=ips,
            raw_data={
                "subdomains": [s.name for s in subdomains],
                "ips": [ip.address for ip in ips],
            },
        )

    async def asn_lookup(self, ip: str) -> Optional[ASNInfo]:
        """Look up ASN information for an IP address."""
        try:
            response = await self._http_get(
                HACKERTARGET_ASLOOKUP, params={"q": ip}
            )
            text = response.text.strip()

            if text.startswith("error") or not text:
                return None

            # Format: "ip","asn","as_name"
            # or CSV lines
            parts = text.replace('"', "").split(",")
            if len(parts) >= 3:
                return ASNInfo(
                    asn=parts[1].strip().replace("AS", ""),
                    name=parts[2].strip(),
                )
        except Exception as exc:
            logger.debug("ASN lookup failed for %s: %s", ip, exc)

        return None

    def _parse_cached(self, data: dict) -> dict:
        """Restore from cached data."""
        subdomains = [
            SubdomainRecord(name=s, source=self.SOURCE_NAME)
            for s in data.get("subdomains", [])
        ]
        ips = [
            IPRecord(address=ip, version=4 if "." in ip else 6)
            for ip in data.get("ips", [])
        ]
        return {"subdomains": subdomains, "ips": ips}
