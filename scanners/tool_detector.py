"""Detection of installed security tools on the system."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Optional

from core.models import ToolInfo

logger = logging.getLogger(__name__)

# Tool binary names and version flags
TOOL_DEFINITIONS: dict[str, dict] = {
    "nmap": {"binary": "nmap", "version_flag": "--version", "version_pattern": r"Nmap version ([\d.]+)"},
    "gobuster": {"binary": "gobuster", "version_flag": "version", "version_pattern": r"([\d.]+)"},
    "nikto": {"binary": "nikto", "version_flag": "-Version", "version_pattern": r"([\d.]+)"},
    "nuclei": {"binary": "nuclei", "version_flag": "-version", "version_pattern": r"([\d.]+)"},
    "whatweb": {"binary": "whatweb", "version_flag": "--version", "version_pattern": r"WhatWeb version ([\d.]+)"},
    "wafw00f": {"binary": "wafw00f", "version_flag": "--version", "version_pattern": r"([\d.]+)"},
    "sslscan": {"binary": "sslscan", "version_flag": "--version", "version_pattern": r"([\d.]+)"},
    "dnsrecon": {"binary": "dnsrecon", "version_flag": "--version", "version_pattern": r"([\d.]+)"},
    "ffuf": {"binary": "ffuf", "version_flag": "-V", "version_pattern": r"([\d.]+)"},
    "wpscan": {"binary": "wpscan", "version_flag": "--version", "version_pattern": r"([\d.]+)"},
}


def detect_tool(name: str, custom_path: Optional[str] = None) -> ToolInfo:
    """Detect if a tool is installed and get its version.

    Args:
        name: Tool name (key in TOOL_DEFINITIONS).
        custom_path: Optional custom path to the binary.

    Returns:
        ToolInfo with installation status.
    """
    definition = TOOL_DEFINITIONS.get(name)
    if not definition:
        return ToolInfo(name=name, installed=False)

    binary = custom_path or definition["binary"]
    path = shutil.which(binary)

    if not path:
        return ToolInfo(name=name, installed=False)

    version = _get_version(path, definition["version_flag"], definition["version_pattern"])
    return ToolInfo(name=name, installed=True, path=path, version=version)


def detect_all_tools(custom_paths: Optional[dict[str, str]] = None) -> list[ToolInfo]:
    """Detect all known tools.

    Args:
        custom_paths: Optional dict mapping tool name to custom binary path.

    Returns:
        List of ToolInfo for all known tools.
    """
    custom_paths = custom_paths or {}
    tools = []
    for name in TOOL_DEFINITIONS:
        custom = custom_paths.get(name)
        tools.append(detect_tool(name, custom))
    return tools


def _get_version(binary_path: str, version_flag: str, pattern: str) -> Optional[str]:
    """Extract version string from tool output."""
    try:
        result = subprocess.run(
            [binary_path, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        match = re.search(pattern, output)
        if match:
            return match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        logger.debug("Could not get version for %s: %s", binary_path, exc)
    return None
