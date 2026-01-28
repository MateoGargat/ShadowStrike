"""Parse gobuster text output into structured records."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from core.models import WebDirectoryRecord

logger = logging.getLogger(__name__)


def parse_gobuster_output(text_output: str, base_url: str = "") -> list[WebDirectoryRecord]:
    """Parse gobuster directory brute-force output.

    Args:
        text_output: Raw text output from gobuster.
        base_url: The base URL that was scanned.

    Returns:
        List of WebDirectoryRecord entries.
    """
    records: list[WebDirectoryRecord] = []
    parsed_base = urlparse(base_url) if base_url else None
    host = parsed_base.hostname if parsed_base else None
    port = parsed_base.port if parsed_base else None

    for line in text_output.splitlines():
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("Gobuster"):
            continue

        # gobuster output format: /path (Status: 200) [Size: 1234]
        match = re.match(
            r"^(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)])?",
            line,
        )
        if match:
            path = match.group(1)
            status_code = int(match.group(2))
            size = int(match.group(3)) if match.group(3) else None

            url = f"{base_url.rstrip('/')}{path}" if base_url else path

            records.append(WebDirectoryRecord(
                url=url,
                status_code=status_code,
                content_length=size,
                host=host,
                port=port,
                scanner="gobuster",
            ))
            continue

        # Alternative format: http://target/path  [Status: 200, Size: 1234, ...]
        match2 = re.match(
            r"^(https?://\S+)\s+\[Status:\s*(\d+)(?:,\s*Size:\s*(\d+))?",
            line,
        )
        if match2:
            url = match2.group(1)
            status_code = int(match2.group(2))
            size = int(match2.group(3)) if match2.group(3) else None
            parsed = urlparse(url)

            records.append(WebDirectoryRecord(
                url=url,
                status_code=status_code,
                content_length=size,
                host=parsed.hostname or host,
                port=parsed.port or port,
                scanner="gobuster",
            ))

    return records
