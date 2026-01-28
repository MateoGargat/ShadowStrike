"""Tests for nuclei scanner and parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.models import ActiveScanConfig, ScanIntensity, VulnSeverity
from scanners.output_parsers.nuclei_parser import parse_nuclei_jsonl
from scanners.nuclei_scanner import NucleiScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_nuclei_jsonl():
    """Should parse nuclei JSONL output correctly."""
    jsonl = (FIXTURES_DIR / "nuclei_sample.jsonl").read_text()
    records = parse_nuclei_jsonl(jsonl)

    assert len(records) == 3

    # First: Critical CVE
    crit = records[0]
    assert crit.severity == VulnSeverity.CRITICAL
    assert crit.title == "Apache Log4j RCE"
    assert crit.cvss == 10.0
    assert "CVE-2021-44228" in crit.references
    assert crit.affected_url == "http://example.com/api/login"

    # Second: Info
    info = records[1]
    assert info.severity == VulnSeverity.INFO
    assert "X-Frame-Options" in info.title

    # Third: High
    high = records[2]
    assert high.severity == VulnSeverity.HIGH
    assert high.cvss == 8.5


def test_parse_nuclei_jsonl_empty():
    """Should handle empty input."""
    records = parse_nuclei_jsonl("")
    assert records == []


def test_parse_nuclei_jsonl_invalid():
    """Should skip invalid JSON lines."""
    records = parse_nuclei_jsonl("not json\n{invalid}\n")
    assert records == []


def test_nuclei_scanner_build_command():
    """Should build correct nuclei command."""
    config = ActiveScanConfig(
        enabled=True,
        intensity=ScanIntensity.STANDARD,
    )
    scanner = NucleiScanner(config)

    import shutil
    original = shutil.which
    try:
        shutil.which = lambda x: "/usr/bin/nuclei"
        cmd = scanner.build_command("http://example.com", {})
    finally:
        shutil.which = original

    assert cmd[0] == "/usr/bin/nuclei"
    assert "-target" in cmd
    assert "-jsonl" in cmd
    assert "-severity" in cmd


def test_nuclei_scanner_parse_empty():
    """Should handle empty output as success with no vulns."""
    config = ActiveScanConfig(enabled=True, intensity=ScanIntensity.QUICK)
    scanner = NucleiScanner(config)

    result = scanner.parse_output("", "", 0)
    assert result.success
    assert result.vulnerabilities == []


def test_nuclei_scanner_parse_valid():
    """Should parse valid JSONL output."""
    config = ActiveScanConfig(enabled=True, intensity=ScanIntensity.QUICK)
    scanner = NucleiScanner(config)

    jsonl = (FIXTURES_DIR / "nuclei_sample.jsonl").read_text()
    result = scanner.parse_output(jsonl, "", 0)

    assert result.success
    assert len(result.vulnerabilities) == 3
