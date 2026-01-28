"""WHOIS data collector."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Optional

import whois

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from core.models import AppConfig, CollectorResult, WhoisRecord

logger = logging.getLogger(__name__)


class WhoisCollector(BaseCollector):
    """Collect WHOIS registration data for a domain."""

    SOURCE_NAME = "whois"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        super().__init__(config, cache)

    async def collect(self, target: str) -> CollectorResult:
        """Query WHOIS for the target domain."""
        try:
            # python-whois is synchronous, run in executor
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, target)
        except Exception as exc:
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"WHOIS lookup failed: {exc}",
            )

        if not w or not w.get("domain_name"):
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error="No WHOIS data found",
            )

        record = WhoisRecord(
            domain=target,
            registrar=_first_or_none(w.get("registrar")),
            creation_date=_parse_date(w.get("creation_date")),
            expiration_date=_parse_date(w.get("expiration_date")),
            updated_date=_parse_date(w.get("updated_date")),
            nameservers=_to_list(w.get("name_servers")),
            organization=_first_or_none(w.get("org")),
            country=_first_or_none(w.get("country")),
            emails=_to_list(w.get("emails")),
            dnssec=_first_or_none(w.get("dnssec")),
            status=_to_list(w.get("status")),
        )

        raw_data = {}
        for key in ("domain_name", "registrar", "creation_date", "expiration_date",
                     "updated_date", "name_servers", "org", "country", "emails",
                     "dnssec", "status"):
            val = w.get(key)
            if val is not None:
                raw_data[key] = _serialize(val)

        return CollectorResult(
            source=self.SOURCE_NAME,
            success=True,
            whois=record,
            raw_data=raw_data,
        )

    def _parse_cached(self, data: dict) -> dict:
        """Restore WHOIS record from cached data."""
        try:
            record = WhoisRecord(
                domain=data.get("domain_name", [""])[0] if isinstance(data.get("domain_name"), list) else data.get("domain_name", ""),
                registrar=_first_or_none(data.get("registrar")),
                creation_date=_parse_date(data.get("creation_date")),
                expiration_date=_parse_date(data.get("expiration_date")),
                nameservers=_to_list(data.get("name_servers")),
                organization=_first_or_none(data.get("org")),
                country=_first_or_none(data.get("country")),
                emails=_to_list(data.get("emails")),
            )
            return {"whois": record}
        except Exception:
            return {}


def _first_or_none(value: Any) -> Optional[str]:
    """Extract first element if list, or return as string."""
    if value is None:
        return None
    if isinstance(value, list):
        return str(value[0]) if value else None
    return str(value)


def _to_list(value: Any) -> list[str]:
    """Normalize value to list of strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value.lower()]
    if isinstance(value, list):
        return [str(v).lower() for v in value if v]
    return [str(value)]


def _parse_date(value: Any) -> Optional[datetime]:
    """Parse date from whois response (can be list or single)."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return None
    return None


def _serialize(value: Any) -> Any:
    """Make a value JSON-serializable."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize(v) for v in value]
    return str(value) if value is not None else None
