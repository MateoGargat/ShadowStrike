"""VirusTotal API v3 collector for subdomain enumeration."""

from __future__ import annotations

import logging
from typing import Optional

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import AppConfig, CollectorResult, SubdomainRecord

logger = logging.getLogger(__name__)

VT_API_URL = "https://www.virustotal.com/api/v3"


class VirusTotalCollector(BaseCollector):
    """Collect subdomains from VirusTotal API v3."""

    SOURCE_NAME = "virustotal"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)
        self._api_key = config.virustotal_api_key
        self._rate_delay = 15.0  # 4 req/min = 1 per 15s

    async def collect(self, target: str) -> CollectorResult:
        """Query VirusTotal for subdomains of the target domain."""
        if not self._api_key:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error="No VirusTotal API key configured",
            )

        headers = {"x-apikey": self._api_key}

        try:
            data = await self._http_get_json(
                f"{VT_API_URL}/domains/{target}/subdomains",
                headers=headers,
                params={"limit": 40},
            )
        except Exception as exc:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"VirusTotal API error: {exc}",
            )

        subdomains: list[SubdomainRecord] = []
        seen: set[str] = set()

        for item in data.get("data", []):
            name = item.get("id", "").strip().lower()
            if name and name not in seen:
                seen.add(name)
                subdomains.append(
                    SubdomainRecord(name=name, source=self.SOURCE_NAME)
                )

        logger.info(
            "[virustotal] Found %d subdomains for %s", len(subdomains), target
        )

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            subdomains=subdomains,
            raw_data={"subdomains": [s.name for s in subdomains]},
        )

    def _parse_cached(self, data: dict) -> dict:
        """Restore subdomains from cached data."""
        subdomains = [
            SubdomainRecord(name=s, source=self.SOURCE_NAME)
            for s in data.get("subdomains", [])
        ]
        return {"subdomains": subdomains}
