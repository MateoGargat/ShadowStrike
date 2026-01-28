"""Scan intensity profiles for active scanners."""

from __future__ import annotations

from core.models import ScanIntensity


SCAN_PROFILES: dict[ScanIntensity, dict] = {
    ScanIntensity.QUICK: {
        "nmap_ports": "--top-ports 100",
        "nmap_flags": ["-sV", "-T4", "--open"],
        "nmap_timeout": 300,
        "gobuster_wordlist": "common.txt",
        "nuclei_severity": "high,critical",
        "whatweb_aggression": "1",
        "dnsrecon_types": "std,axfr",
        "default_timeout": 300,
    },
    ScanIntensity.STANDARD: {
        "nmap_ports": "--top-ports 1000",
        "nmap_flags": ["-sV", "-sC", "-O", "-T3", "--open"],
        "nmap_timeout": 600,
        "gobuster_wordlist": "medium.txt",
        "nuclei_severity": "low,medium,high,critical",
        "whatweb_aggression": "3",
        "dnsrecon_types": "std,brt,axfr",
        "default_timeout": 600,
    },
    ScanIntensity.AGGRESSIVE: {
        "nmap_ports": "-p-",
        "nmap_flags": ["-sV", "-sC", "-O", "-A", "-T3", "--script=vuln", "--open"],
        "nmap_timeout": 3600,
        "gobuster_wordlist": "big.txt",
        "nuclei_severity": "info,low,medium,high,critical",
        "whatweb_aggression": "4",
        "dnsrecon_types": "std,brt,axfr,srv,rvl",
        "default_timeout": 1200,
    },
}


def get_profile(intensity: ScanIntensity) -> dict:
    """Return the scan profile for the given intensity."""
    return SCAN_PROFILES[intensity]
