"""Parse nikto JSON output into structured records."""

from __future__ import annotations

import json
import logging
from typing import Any

from core.models import VulnerabilityRecord, VulnSeverity

logger = logging.getLogger(__name__)


def parse_nikto_json(json_output: str) -> list[VulnerabilityRecord]:
    """Parse nikto JSON output.

    Args:
        json_output: Raw JSON string from nikto -Format json.

    Returns:
        List of VulnerabilityRecord entries.
    """
    records: list[VulnerabilityRecord] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError:
        # nikto may output multiple JSON objects or wrapped format
        try:
            # Try parsing as array
            for line in json_output.strip().splitlines():
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        records.extend(_extract_vulns(data))
                    except json.JSONDecodeError:
                        continue
            return records
        except Exception as exc:
            logger.error("Failed to parse nikto JSON: %s", exc)
            return records

    records.extend(_extract_vulns(data))
    return records


def _extract_vulns(data: Any) -> list[VulnerabilityRecord]:
    """Extract vulnerability records from parsed nikto data."""
    records: list[VulnerabilityRecord] = []

    if isinstance(data, dict):
        host = data.get("host", "")
        port = data.get("port")
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        elif not isinstance(port, int):
            port = None

        vulnerabilities = data.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            vulnerabilities = []

        for vuln in vulnerabilities:
            if not isinstance(vuln, dict):
                continue

            osvdb_id = vuln.get("OSVDB", vuln.get("id", ""))
            method = vuln.get("method", "")
            url = vuln.get("url", vuln.get("uri", ""))
            msg = vuln.get("msg", vuln.get("message", ""))

            references = []
            if osvdb_id and str(osvdb_id) != "0":
                references.append(f"OSVDB-{osvdb_id}")

            affected_url = None
            if url and host:
                scheme = "https" if port == 443 else "http"
                port_str = "" if port in (80, 443, None) else f":{port}"
                affected_url = f"{scheme}://{host}{port_str}{url}"

            records.append(VulnerabilityRecord(
                vuln_id=f"NIKTO-{osvdb_id}" if osvdb_id else None,
                title=msg[:200] if msg else f"Nikto finding ({method} {url})",
                severity=VulnSeverity.MEDIUM,
                affected_host=host or None,
                affected_port=port,
                affected_url=affected_url,
                scanner="nikto",
                references=references,
                description=msg,
            ))

    elif isinstance(data, list):
        for item in data:
            records.extend(_extract_vulns(item))

    return records
