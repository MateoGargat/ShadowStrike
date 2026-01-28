"""Tests for BaseActiveScanner."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from core.models import ActiveScanConfig, ActiveScannerResult, ScanIntensity
from scanners.base import BaseActiveScanner


class DummyScanner(BaseActiveScanner):
    TOOL_NAME = "dummy"
    BINARY_NAME = "dummy-tool"

    def build_command(self, target: str, context: dict) -> list[str]:
        return [self.get_binary_path(), "--scan", target]

    def parse_output(self, stdout: str, stderr: str, return_code: int) -> ActiveScannerResult:
        return ActiveScannerResult(
            scanner_name=self.TOOL_NAME,
            success=return_code == 0,
            error=stderr if return_code != 0 else None,
        )


@pytest.fixture
def config():
    return ActiveScanConfig(
        enabled=True,
        intensity=ScanIntensity.STANDARD,
        scanner_timeout=30,
    )


@pytest.fixture
def scanner(config):
    return DummyScanner(config)


def test_tool_not_found(config):
    """Scanner should return error when tool is not installed."""
    s = DummyScanner(config)
    with patch("shutil.which", return_value=None):
        result = asyncio.get_event_loop().run_until_complete(s.scan("target"))
    assert not result.success
    assert "not found" in result.error


def test_successful_scan(config):
    """Scanner should return success on clean execution."""
    s = DummyScanner(config)

    mock_process = AsyncMock()
    mock_process.communicate = AsyncMock(return_value=(b"output data", b""))
    mock_process.returncode = 0
    mock_process.kill = MagicMock()
    mock_process.wait = AsyncMock()

    with patch("shutil.which", return_value="/usr/bin/dummy-tool"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            result = asyncio.get_event_loop().run_until_complete(s.scan("target"))

    assert result.success
    assert result.scanner_name == "dummy"
    assert result.duration_seconds >= 0


def test_timeout_handling(config):
    """Scanner should handle timeout gracefully."""
    config.scanner_timeout = 1
    s = DummyScanner(config)

    mock_process = AsyncMock()
    mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    mock_process.kill = MagicMock()
    mock_process.wait = AsyncMock()
    mock_process.returncode = -9

    with patch("shutil.which", return_value="/usr/bin/dummy-tool"):
        with patch("asyncio.create_subprocess_exec", return_value=mock_process):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                result = asyncio.get_event_loop().run_until_complete(s.scan("target"))

    assert not result.success
    assert "Timed out" in result.error


def test_build_command(scanner):
    """build_command should return proper command list."""
    with patch("shutil.which", return_value="/usr/bin/dummy-tool"):
        cmd = scanner.build_command("example.com", {})
    assert cmd == ["/usr/bin/dummy-tool", "--scan", "example.com"]


def test_get_timeout_from_config(config):
    """Timeout should come from config when set."""
    config.scanner_timeout = 120
    s = DummyScanner(config)
    assert s.get_timeout() == 120
