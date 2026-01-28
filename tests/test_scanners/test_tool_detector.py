"""Tests for tool_detector module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import subprocess

import pytest

from scanners.tool_detector import detect_tool, detect_all_tools


def test_detect_tool_installed():
    """Should detect installed tool with version."""
    mock_result = MagicMock()
    mock_result.stdout = "Nmap version 7.94 ( https://nmap.org )"
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", return_value=mock_result):
            info = detect_tool("nmap")

    assert info.installed
    assert info.path == "/usr/bin/nmap"
    assert info.version == "7.94"
    assert info.name == "nmap"


def test_detect_tool_not_installed():
    """Should report tool not found."""
    with patch("shutil.which", return_value=None):
        info = detect_tool("nmap")

    assert not info.installed
    assert info.path is None
    assert info.version is None


def test_detect_tool_unknown_name():
    """Should handle unknown tool names gracefully."""
    info = detect_tool("nonexistent_tool")
    assert not info.installed


def test_detect_tool_custom_path():
    """Should use custom path for detection."""
    mock_result = MagicMock()
    mock_result.stdout = "Nmap version 7.80"
    mock_result.stderr = ""

    with patch("shutil.which", return_value="/custom/nmap") as mock_which:
        with patch("subprocess.run", return_value=mock_result):
            info = detect_tool("nmap", custom_path="/custom/nmap")

    mock_which.assert_called_once_with("/custom/nmap")
    assert info.installed


def test_detect_tool_version_timeout():
    """Should handle version extraction timeout."""
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 10)):
            info = detect_tool("nmap")

    assert info.installed
    assert info.version is None


def test_detect_all_tools():
    """Should detect multiple tools."""
    def mock_which(binary):
        if binary in ("nmap", "nuclei"):
            return f"/usr/bin/{binary}"
        return None

    mock_result = MagicMock()
    mock_result.stdout = "version 1.0"
    mock_result.stderr = ""

    with patch("shutil.which", side_effect=mock_which):
        with patch("subprocess.run", return_value=mock_result):
            tools = detect_all_tools()

    installed = [t for t in tools if t.installed]
    assert len(installed) == 2
    names = {t.name for t in installed}
    assert "nmap" in names
    assert "nuclei" in names
