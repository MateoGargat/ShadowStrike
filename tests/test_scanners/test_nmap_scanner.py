"""Tests for nmap scanner and parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.models import ActiveScanConfig, ScanIntensity
from scanners.output_parsers.nmap_parser import parse_nmap_xml
from scanners.nmap_scanner import NmapScanner

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_parse_nmap_xml_basic():
    """Should parse nmap XML with ports, OS, and vulns."""
    xml_content = (FIXTURES_DIR / "nmap_basic.xml").read_text()
    result = parse_nmap_xml(xml_content)

    # Ports
    assert len(result["ports"]) == 3  # 22, 80, 9929 (443 is closed)
    port_numbers = {p.port for p in result["ports"]}
    assert 22 in port_numbers
    assert 80 in port_numbers
    assert 9929 in port_numbers
    assert 443 not in port_numbers

    # Check port details
    ssh_port = next(p for p in result["ports"] if p.port == 22)
    assert ssh_port.service == "ssh"
    assert ssh_port.product == "OpenSSH"
    assert ssh_port.version == "6.6.1p1"
    assert ssh_port.ip_address == "45.33.32.156"

    # Technologies
    assert len(result["technologies"]) >= 2
    tech_names = {t.name for t in result["technologies"]}
    assert "OpenSSH" in tech_names
    assert "Apache httpd" in tech_names

    # OS Detection
    assert len(result["os_detections"]) >= 1
    os_rec = result["os_detections"][0]
    assert os_rec.os_family == "Linux"
    assert os_rec.os_accuracy == 95

    # Vulnerabilities (from NSE script)
    assert len(result["vulnerabilities"]) >= 1
    vuln = result["vulnerabilities"][0]
    assert "CVE-2020-15778" in vuln.vuln_id or "CVE-2020-15778" in str(vuln.references)


def test_parse_nmap_xml_empty():
    """Should handle empty/invalid XML."""
    result = parse_nmap_xml("")
    assert result["ports"] == []
    assert result["technologies"] == []


def test_parse_nmap_xml_malformed():
    """Should handle malformed XML gracefully."""
    result = parse_nmap_xml("<invalid>xml<broken")
    assert result["ports"] == []


def test_nmap_scanner_build_command():
    """Should build correct nmap command."""
    config = ActiveScanConfig(
        enabled=True,
        intensity=ScanIntensity.STANDARD,
    )
    scanner = NmapScanner(config)

    # Mock the binary path
    import shutil
    original = shutil.which

    try:
        shutil.which = lambda x: "/usr/bin/nmap"
        cmd = scanner.build_command("scanme.nmap.org", {})
    finally:
        shutil.which = original

    assert cmd[0] == "/usr/bin/nmap"
    assert "scanme.nmap.org" in cmd
    assert "-oX" in cmd
    assert "-" in cmd


def test_nmap_scanner_parse_output_no_xml():
    """Should handle non-XML output."""
    config = ActiveScanConfig(enabled=True, intensity=ScanIntensity.QUICK)
    scanner = NmapScanner(config)

    result = scanner.parse_output("Not XML output", "error", 1)
    assert not result.success


def test_nmap_scanner_parse_output_valid():
    """Should parse valid nmap XML output."""
    config = ActiveScanConfig(enabled=True, intensity=ScanIntensity.QUICK)
    scanner = NmapScanner(config)

    xml_content = (FIXTURES_DIR / "nmap_basic.xml").read_text()
    result = scanner.parse_output(xml_content, "", 0)

    assert result.success
    assert len(result.ports) == 3
    assert len(result.technologies) >= 2
    assert len(result.os_detections) >= 1
