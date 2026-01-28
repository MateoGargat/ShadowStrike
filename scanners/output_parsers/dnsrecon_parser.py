"""Parse dnsrecon JSON output into structured records."""

from __future__ import annotations

import json
import logging

from core.models import ActiveDNSRecord

logger = logging.getLogger(__name__)


def parse_dnsrecon_json(json_output: str) -> list[ActiveDNSRecord]:
    """Parse dnsrecon JSON output.

    Args:
        json_output: Raw JSON string from dnsrecon -j -.

    Returns:
        List of ActiveDNSRecord entries.
    """
    records: list[ActiveDNSRecord] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse dnsrecon JSON: %s", exc)
        return records

    if not isinstance(data, list):
        data = [data]

    for entry in data:
        if not isinstance(entry, dict):
            continue

        record_type = entry.get("type", "")
        name = entry.get("name", entry.get("domain", ""))
        address = entry.get("address", entry.get("target", entry.get("data", "")))

        if not name or not record_type:
            continue

        # Skip metadata entries
        if record_type in ("info", "error", "*"):
            continue

        source_method = entry.get("method", "")

        records.append(ActiveDNSRecord(
            host=name,
            record_type=record_type.upper(),
            value=str(address),
            source_method=source_method,
        ))

    return records
