"""Active scanner registry, factory, and execution constants."""

from __future__ import annotations

from typing import Optional, Type

from core.models import ActiveScanConfig
from scanners.base import BaseActiveScanner
from scanners.nmap_scanner import NmapScanner
from scanners.gobuster_scanner import GobusterScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.whatweb_scanner import WhatWebScanner
from scanners.wafw00f_scanner import Wafw00fScanner
from scanners.ssl_scanner import SSLScanner
from scanners.dnsrecon_scanner import DNSReconScanner
from scanners.ffuf_scanner import FfufScanner
from scanners.wpscan_scanner import WPScanScanner

# Registry mapping scanner name to class
SCANNER_REGISTRY: dict[str, Type[BaseActiveScanner]] = {
    "nmap": NmapScanner,
    "gobuster": GobusterScanner,
    "nikto": NiktoScanner,
    "nuclei": NucleiScanner,
    "whatweb": WhatWebScanner,
    "wafw00f": Wafw00fScanner,
    "sslscan": SSLScanner,
    "dnsrecon": DNSReconScanner,
    "ffuf": FfufScanner,
    "wpscan": WPScanScanner,
}

# Phase 1: Run first, no dependencies
PHASE_1_SCANNERS = ["nmap", "dnsrecon", "wafw00f"]

# Phase 2: Depend on Phase 1 results
PHASE_2_SCANNERS = ["whatweb", "sslscan", "gobuster", "nikto", "nuclei", "wpscan"]

# Mutual exclusions: only one of each group should run unless explicitly selected
EXCLUSIVE_GROUPS = [
    {"gobuster", "ffuf"},       # Directory brute-force
]

ALL_SCANNER_NAMES = list(SCANNER_REGISTRY.keys())


def get_scanner(
    name: str,
    config: ActiveScanConfig,
    output_callback=None,
) -> BaseActiveScanner:
    """Instantiate a scanner by name.

    Args:
        name: Scanner name (key in SCANNER_REGISTRY).
        config: Active scan configuration.
        output_callback: Optional callback for streaming output.

    Returns:
        Configured scanner instance.

    Raises:
        KeyError: If scanner name is not registered.
    """
    cls = SCANNER_REGISTRY[name]
    return cls(config=config, output_callback=output_callback)


def get_selected_scanners(
    config: ActiveScanConfig,
    output_callback=None,
) -> list[BaseActiveScanner]:
    """Get all selected (or default) scanners.

    Applies mutual exclusion rules unless explicitly overridden.
    """
    selected = config.selected_scanners
    if not selected:
        # Default: all scanners except ffuf (gobuster preferred)
        selected = [n for n in ALL_SCANNER_NAMES if n != "ffuf"]
    else:
        # Apply mutual exclusions
        selected = _apply_exclusions(selected)

    scanners = []
    for name in selected:
        if name in SCANNER_REGISTRY:
            scanners.append(get_scanner(name, config, output_callback))
    return scanners


def _apply_exclusions(selected: list[str]) -> list[str]:
    """Apply mutual exclusion rules — keep the first in each group."""
    result = list(selected)
    for group in EXCLUSIVE_GROUPS:
        found = [s for s in result if s in group]
        if len(found) > 1:
            # Keep only the first one found
            for s in found[1:]:
                result.remove(s)
    return result
