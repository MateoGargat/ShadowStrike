"""Certificate Transparency collector via crt.sh."""

from __future__ import annotations

import logging
from typing import Optional

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import AppConfig, CollectorResult, SubdomainRecord

logger = logging.getLogger(__name__)

CRT_SH_URL = "https://crt.sh/"


class CrtshCollector(BaseCollector):
    """Collect subdomains from Certificate Transparency logs via crt.sh."""

    SOURCE_NAME = "crtsh"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)
        self._rate_delay = 1.0  # crt.sh is rate-sensitive

    async def collect(self, target: str) -> CollectorResult:
        """Query crt.sh for subdomains of the target domain."""
        params = {"q": f"%.{target}", "output": "json"}
        try:
            response = await self._http_get(CRT_SH_URL, params=params, timeout=30)
            data = response.json()
        except Exception as exc:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=str(exc),
            )

        if not isinstance(data, list):
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=True,
                subdomains=[],
                raw_data={"entries": []},
            )

        # Extract and deduplicate subdomains
        seen: set[str] = set()
        subdomains: list[SubdomainRecord] = []

        for entry in data:
            name_value = entry.get("name_value", "")
            # crt.sh can return multiline entries
            for name in name_value.split("\n"):
                name = name.strip().lower().rstrip(".")
                # Skip wildcards and empty
                if not name or name.startswith("*"):
                    continue
                if name in seen:
                    continue
                seen.add(name)
                subdomains.append(
                    SubdomainRecord(name=name, source=self.SOURCE_NAME)
                )

        logger.info("[crtsh] Found %d unique subdomains for %s", len(subdomains), target)
        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            subdomains=subdomains,
            raw_data={"entries": [e.get("name_value", "") for e in data[:200]]},
        )

    def _parse_cached(self, data: dict) -> dict:
        """Restore subdomains from cached data."""
        entries = data.get("entries", [])
        seen: set[str] = set()
        subdomains: list[SubdomainRecord] = []
        for entry in entries:
            for name in entry.split("\n"):
                name = name.strip().lower().rstrip(".")
                if not name or name.startswith("*") or name in seen:
                    continue
                seen.add(name)
                subdomains.append(SubdomainRecord(name=name, source=self.SOURCE_NAME))
        return {"subdomains": subdomains}
