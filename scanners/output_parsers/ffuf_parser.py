"""Parse ffuf JSON output into structured records."""

from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from core.models import WebDirectoryRecord

logger = logging.getLogger(__name__)


def parse_ffuf_json(json_output: str) -> list[WebDirectoryRecord]:
    """Parse ffuf JSON output.

    Args:
        json_output: Raw JSON string from ffuf -of json.

    Returns:
        List of WebDirectoryRecord entries.
    """
    records: list[WebDirectoryRecord] = []

    try:
        data = json.loads(json_output)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse ffuf JSON: %s", exc)
        return records

    if not isinstance(data, dict):
        return records

    results = data.get("results", [])
    if not isinstance(results, list):
        return records

    for entry in results:
        if not isinstance(entry, dict):
            continue

        url = entry.get("url", "")
        status = entry.get("status", 0)
        length = entry.get("length", entry.get("content-length"))

        if not url or not status:
            continue

        parsed = urlparse(url)

        records.append(WebDirectoryRecord(
            url=url,
            status_code=int(status),
            content_length=int(length) if length else None,
            host=parsed.hostname,
            port=parsed.port,
            scanner="ffuf",
        ))

    return records
