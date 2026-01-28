"""Parse wafw00f JSON output into structured records."""

from __future__ import annotations

import json
import logging

from core.models import WAFRecord

logger = logging.getLogger(__name__)


def parse_wafw00f_json(json_output: str) -> list[WAFRecord]:
    """Parse wafw00f JSON output.

    Args:
        json_output: Raw JSON string from wafw00f -o - -f json.

    Returns:
        List of WAFRecord entries.
    """
    records: list[WAFRecord] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse wafw00f JSON: %s", exc)
        return records

    if isinstance(data, list):
        for entry in data:
            if not isinstance(entry, dict):
                continue
            records.append(_parse_entry(entry))
    elif isinstance(data, dict):
        records.append(_parse_entry(data))

    return records


def _parse_entry(entry: dict) -> WAFRecord:
    """Parse a single wafw00f result entry."""
    url = entry.get("url", "")
    detected = entry.get("detected", False)
    firewall = entry.get("firewall", entry.get("waf", ""))
    manufacturer = entry.get("manufacturer", entry.get("vendor", ""))

    # Extract host from URL
    host = url
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split(":")[0]

    return WAFRecord(
        host=host,
        detected=bool(detected) if detected else bool(firewall),
        waf_name=firewall if firewall else None,
        waf_vendor=manufacturer if manufacturer else None,
    )
