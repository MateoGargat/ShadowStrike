"""Shodan collector: InternetDB (free) + full API (with key)."""

from __future__ import annotations

import logging
from typing import Optional

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import (
    AppConfig,
    CollectorResult,
    IPRecord,
    PortRecord,
    TechnologyRecord,
)

logger = logging.getLogger(__name__)

INTERNETDB_URL = "https://internetdb.shodan.io"
SHODAN_API_URL = "https://api.shodan.io"


class ShodanCollector(BaseCollector):
    """Collect port, service, and vulnerability data from Shodan."""

    SOURCE_NAME = "shodan"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)
        self._api_key = config.shodan_api_key

    async def collect(self, target: str) -> CollectorResult:
        """Query Shodan for the target IP.

        Uses InternetDB (free, no key) first, then full API if key available.
        """
        # Try InternetDB first (no key required)
        result = await self._query_internetdb(target)

        # If we have an API key, enrich with full API
        if self._api_key and result.success:
            full_result = await self._query_full_api(target)
            if full_result.success:
                return full_result

        return result

    async def _query_internetdb(self, ip: str) -> CollectorResult:
        """Query Shodan InternetDB (free, no API key)."""
        try:
            data = await self._http_get_json(f"{INTERNETDB_URL}/{ip}")
        except Exception as exc:
            error_str = str(exc)
            if "404" in error_str:
                return CollectorResult(
                    source=self.SOURCE_NAME,
                    success=True,
                    raw_data={"source": "internetdb", "found": False},
                )
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"InternetDB error: {exc}",
            )

        ports: list[PortRecord] = []
        technologies: list[TechnologyRecord] = []
        hostnames: list[str] = data.get("hostnames", [])

        # Ports
        for port_num in data.get("ports", []):
            ports.append(
                PortRecord(
                    port=port_num,
                    protocol="tcp",
                    ip_address=ip,
                )
            )

        # CPEs → Technologies
        for cpe in data.get("cpes", []):
            parts = cpe.split(":")
            name = parts[3] if len(parts) > 3 else cpe
            version = parts[4] if len(parts) > 4 else None
            technologies.append(
                TechnologyRecord(
                    name=name,
                    version=version,
                    cpe=cpe,
                    ip_address=ip,
                )
            )

        ip_record = IPRecord(
            address=ip,
            version=4 if "." in ip else 6,
            hostnames=hostnames,
        )

        logger.info(
            "[shodan/internetdb] %s: %d ports, %d techs",
            ip, len(ports), len(technologies),
        )

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            ips=[ip_record],
            ports=ports,
            technologies=technologies,
            raw_data={
                "source": "internetdb",
                "found": True,
                "ports": data.get("ports", []),
                "cpes": data.get("cpes", []),
                "hostnames": hostnames,
                "vulns": data.get("vulns", []),
            },
        )

    async def _query_full_api(self, ip: str) -> CollectorResult:
        """Query Shodan full API (requires API key)."""
        if not self._api_key:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error="No Shodan API key configured",
            )

        try:
            data = await self._http_get_json(
                f"{SHODAN_API_URL}/shodan/host/{ip}",
                params={"key": self._api_key},
            )
        except Exception as exc:
            logger.warning("[shodan/api] Full API failed for %s: %s", ip, exc)
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"Shodan API error: {exc}",
            )

        ports: list[PortRecord] = []
        technologies: list[TechnologyRecord] = []

        for service in data.get("data", []):
            port_num = service.get("port", 0)
            ports.append(
                PortRecord(
                    port=port_num,
                    protocol=service.get("transport", "tcp"),
                    service=service.get("product"),
                    banner=service.get("data", "")[:500],
                    product=service.get("product"),
                    version=service.get("version"),
                    ip_address=ip,
                )
            )

            if service.get("product"):
                technologies.append(
                    TechnologyRecord(
                        name=service["product"],
                        version=service.get("version"),
                        ip_address=ip,
                        port=port_num,
                        category="service",
                    )
                )

        ip_record = IPRecord(
            address=ip,
            version=4 if "." in ip else 6,
            hostnames=data.get("hostnames", []),
        )

        logger.info(
            "[shodan/api] %s: %d ports, %d techs",
            ip, len(ports), len(technologies),
        )

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            ips=[ip_record],
            ports=ports,
            technologies=technologies,
            raw_data={"source": "api", "data": data},
        )

    def _parse_cached(self, data: dict) -> dict:
        """Restore from cached data."""
        ports = []
        technologies = []
        ip = data.get("hostnames", [""])[0] if data.get("hostnames") else ""

        for port_num in data.get("ports", []):
            ports.append(PortRecord(port=port_num, protocol="tcp", ip_address=ip))

        for cpe in data.get("cpes", []):
            parts = cpe.split(":")
            name = parts[3] if len(parts) > 3 else cpe
            technologies.append(TechnologyRecord(name=name, cpe=cpe, ip_address=ip))

        return {"ports": ports, "technologies": technologies}
