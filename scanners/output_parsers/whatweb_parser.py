"""Parse whatweb JSON output into structured records."""

from __future__ import annotations

import json
import logging
from typing import Any

from core.models import TechnologyRecord

logger = logging.getLogger(__name__)


def parse_whatweb_json(json_output: str) -> list[TechnologyRecord]:
    """Parse whatweb JSON log output.

    Args:
        json_output: Raw JSON string from whatweb --log-json=-.

    Returns:
        List of TechnologyRecord entries.
    """
    records: list[TechnologyRecord] = []

    # whatweb outputs one JSON object per line
    for line in json_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(entry, dict):
            continue

        target = entry.get("target", "")
        plugins = entry.get("plugins", {})
        if not isinstance(plugins, dict):
            continue

        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue

            # Skip generic/meta plugins
            if plugin_name in ("Title", "HTTPServer", "IP", "Country", "UncommonHeaders"):
                continue

            version_list = plugin_data.get("version", [])
            version = None
            if isinstance(version_list, list) and version_list:
                version = str(version_list[0])
            elif isinstance(version_list, str):
                version = version_list

            string_list = plugin_data.get("string", [])
            category = None
            if isinstance(string_list, list) and string_list:
                category = str(string_list[0])

            records.append(TechnologyRecord(
                name=plugin_name,
                version=version,
                category=category or "web",
            ))

    return records
