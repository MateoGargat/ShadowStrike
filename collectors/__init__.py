"""Collector registry and factory for Shadow-OSINT."""

from __future__ import annotations

from typing import Optional

from cache.cache_manager import CacheManager
from collectors.base import BaseCollector
from collectors.crtsh import CrtshCollector
from collectors.dns_resolver import DNSCollector
from collectors.hackertarget import HackerTargetCollector
from collectors.ipinfo_collector import IPInfoCollector
from collectors.shodan_collector import ShodanCollector
from collectors.virustotal import VirusTotalCollector
from collectors.whois_collector import WhoisCollector
from core.models import AppConfig

# Registry mapping source name to collector class
COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "crtsh": CrtshCollector,
    "dns": DNSCollector,
    "whois": WhoisCollector,
    "hackertarget": HackerTargetCollector,
    "shodan": ShodanCollector,
    "virustotal": VirusTotalCollector,
    "ipinfo": IPInfoCollector,
}

# Priority 0 = always run (free, no key)
# Priority 1 = run if key available or has free tier
# Priority 2 = only run if key provided
COLLECTOR_PRIORITY: dict[str, int] = {
    "crtsh": 0,
    "dns": 0,
    "whois": 0,
    "hackertarget": 0,
    "shodan": 1,
    "virustotal": 2,
    "ipinfo": 2,
}

# Which collectors need API keys
COLLECTOR_REQUIRES_KEY: dict[str, Optional[str]] = {
    "crtsh": None,
    "dns": None,
    "whois": None,
    "hackertarget": None,
    "shodan": "shodan_api_key",         # Works without key via InternetDB
    "virustotal": "virustotal_api_key",  # Requires key
    "ipinfo": "ipinfo_token",            # Requires key for full data
}


def get_collector(
    name: str, config: AppConfig, cache: Optional[CacheManager] = None
) -> BaseCollector:
    """Instantiate a collector by name.

    Args:
        name: Collector source name.
        config: Application configuration.
        cache: Optional cache manager.

    Returns:
        Configured collector instance.

    Raises:
        KeyError: If collector name is not registered.
    """
    cls = COLLECTOR_REGISTRY[name]
    return cls(config=config, cache=cache)


def get_available_collectors(
    config: AppConfig,
    cache: Optional[CacheManager] = None,
    include_optional: bool = True,
) -> list[BaseCollector]:
    """Get all collectors that can run with the current configuration.

    Args:
        config: Application configuration.
        cache: Optional cache manager.
        include_optional: Whether to include collectors that need API keys.

    Returns:
        List of configured collector instances.
    """
    collectors: list[BaseCollector] = []

    for name, priority in sorted(COLLECTOR_PRIORITY.items(), key=lambda x: x[1]):
        key_field = COLLECTOR_REQUIRES_KEY.get(name)

        if priority == 0:
            # Always available (free, no key)
            collectors.append(get_collector(name, config, cache))
        elif priority == 1:
            # Has free tier, always include
            if include_optional:
                collectors.append(get_collector(name, config, cache))
        elif priority == 2:
            # Only include if key is configured
            if include_optional and key_field:
                key_value = getattr(config, key_field, None)
                if key_value:
                    collectors.append(get_collector(name, config, cache))

    return collectors


def get_domain_collectors(
    config: AppConfig, cache: Optional[CacheManager] = None
) -> list[BaseCollector]:
    """Get collectors suitable for domain targets."""
    names = ["crtsh", "dns", "whois", "hackertarget"]
    if config.virustotal_api_key:
        names.append("virustotal")
    return [get_collector(n, config, cache) for n in names]


def get_ip_collectors(
    config: AppConfig, cache: Optional[CacheManager] = None
) -> list[BaseCollector]:
    """Get collectors suitable for IP targets."""
    names = ["shodan"]
    if config.ipinfo_token:
        names.append("ipinfo")
    return [get_collector(n, config, cache) for n in names]
