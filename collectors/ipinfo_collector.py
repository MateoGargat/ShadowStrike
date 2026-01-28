"""ipinfo.io collector for IP geolocation and ASN data."""

from __future__ import annotations

import logging
from typing import Optional

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import (
    AppConfig,
    ASNInfo,
    CollectorResult,
    GeoLocation,
    IPRecord,
)

logger = logging.getLogger(__name__)

IPINFO_URL = "https://ipinfo.io"


class IPInfoCollector(BaseCollector):
    """Collect geolocation and ASN data from ipinfo.io."""

    SOURCE_NAME = "ipinfo"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)
        self._token = config.ipinfo_token

    async def collect(self, target: str) -> CollectorResult:
        """Query ipinfo.io for IP details."""
        params = {}
        if self._token:
            params["token"] = self._token

        try:
            data = await self._http_get_json(
                f"{IPINFO_URL}/{target}/json", params=params
            )
        except Exception as exc:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"ipinfo.io error: {exc}",
            )

        # Parse geolocation
        loc = data.get("loc", "")
        lat, lon = None, None
        if loc and "," in loc:
            parts = loc.split(",")
            try:
                lat = float(parts[0])
                lon = float(parts[1])
            except (ValueError, IndexError):
                pass

        geo = GeoLocation(
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country"),
            country_code=data.get("country"),
            latitude=lat,
            longitude=lon,
            timezone=data.get("timezone"),
        )

        # Parse ASN
        asn_info = None
        org = data.get("org", "")
        if org:
            parts = org.split(" ", 1)
            asn_num = parts[0].replace("AS", "") if parts else ""
            asn_name = parts[1] if len(parts) > 1 else ""
            asn_info = ASNInfo(
                asn=asn_num,
                name=asn_name,
                domain=data.get("hostname"),
            )

        ip_record = IPRecord(
            address=target,
            version=4 if "." in target else 6,
            hostnames=[data["hostname"]] if data.get("hostname") else [],
            geolocation=geo,
            asn_info=asn_info,
        )

        logger.info("[ipinfo] %s -> %s, %s", target, geo.city, geo.country)

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            ips=[ip_record],
            raw_data=data,
        )

    def _parse_cached(self, data: dict) -> dict:
        """Restore IP record from cached data."""
        ip = data.get("ip", "")
        geo = GeoLocation(
            city=data.get("city"),
            region=data.get("region"),
            country=data.get("country"),
        )
        ip_record = IPRecord(
            address=ip,
            version=4 if "." in ip else 6,
            geolocation=geo,
        )
        return {"ips": [ip_record]}
