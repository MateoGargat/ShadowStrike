"""Abstract base collector with HTTP client, retries, rate limiting, and caching."""

from __future__ import annotations

import abc
import asyncio
import logging
from typing import Optional

import httpx

from cache.cache_manager import CacheManager
from core.models import AppConfig, CollectorResult

logger = logging.getLogger(__name__)


class BaseCollector(abc.ABC):
    """Abstract base for all OSINT data collectors."""

    SOURCE_NAME: str = "unknown"

    def __init__(self, config: AppConfig, cache: Optional[CacheManager] = None):
        self.config = config
        self.cache = cache
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        self._rate_delay: float = 0.0  # seconds between requests

    @abc.abstractmethod
    async def collect(self, target: str) -> CollectorResult:
        """Collect OSINT data for the given target.

        Args:
            target: Domain, IP, or other target string.

        Returns:
            CollectorResult with collected data.
        """

    async def safe_collect(self, target: str) -> CollectorResult:
        """Collect data without ever raising an exception.

        Wraps collect() with error handling, caching, and rate limiting.
        """
        # Check cache first
        if self.cache:
            cached = self.cache.get(self.SOURCE_NAME, target)
            if cached is not None:
                logger.info("[%s] Cache hit for %s", self.SOURCE_NAME, target)
                return CollectorResult(
                    source=self.SOURCE_NAME,
                    success=True,
                    raw_data=cached,
                    **self._parse_cached(cached),
                )

        try:
            async with self._semaphore:
                if self._rate_delay > 0:
                    await asyncio.sleep(self._rate_delay)
                result = await self.collect(target)

            # Store in cache
            if self.cache and result.success and result.raw_data:
                self.cache.set(self.SOURCE_NAME, target, result.raw_data)

            return result

        except Exception as exc:
            logger.error("[%s] Error collecting %s: %s", self.SOURCE_NAME, target, exc)
            return CollectorResult(
                source=self.SOURCE_NAME,
                success=False,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _parse_cached(self, data: dict) -> dict:
        """Parse cached raw_data back into CollectorResult fields.

        Override in subclasses to restore structured data from cache.
        Returns a dict of fields to pass to CollectorResult.
        """
        return {}

    async def _http_get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> httpx.Response:
        """Perform an async HTTP GET request.

        Args:
            url: URL to fetch.
            params: Query parameters.
            headers: HTTP headers.
            timeout: Request timeout in seconds (defaults to config).

        Returns:
            httpx.Response object.

        Raises:
            httpx.HTTPStatusError: On 4xx/5xx responses.
            httpx.TimeoutException: On timeout.
        """
        _timeout = timeout or self.config.http_timeout
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_timeout),
            follow_redirects=True,
        ) as client:
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response

    async def _http_get_json(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> dict:
        """Perform an async HTTP GET and return JSON."""
        response = await self._http_get(url, params=params, headers=headers, timeout=timeout)
        return response.json()
