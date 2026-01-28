"""Parse nmap XML output into structured records."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import Optional

from core.models import (
    OSDetectionRecord,
    PortRecord,
    TechnologyRecord,
    VulnerabilityRecord,
    VulnSeverity,
)

logger = logging.getLogger(__name__)


def parse_nmap_xml(xml_output: str) -> dict:
    """Parse nmap XML output.

    Args:
        xml_output: Raw XML string from nmap -oX -.

    Returns:
        Dict with keys: ports, technologies, os_detections, vulnerabilities.
    """
    ports: list[PortRecord] = []
    technologies: list[TechnologyRecord] = []
    os_detections: list[OSDetectionRecord] = []
    vulnerabilities: list[VulnerabilityRecord] = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.error("Failed to parse nmap XML: %s", exc)
        return {
            "ports": ports,
            "technologies": technologies,
            "os_detections": os_detections,
            "vulnerabilities": vulnerabilities,
        }

    for host in root.findall(".//host"):
        # Get IP address
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            addr_elem = host.find("address[@addrtype='ipv6']")
        if addr_elem is None:
            continue
        ip_address = addr_elem.get("addr", "")

        # Parse ports
        for port_elem in host.findall(".//port"):
            port_id = int(port_elem.get("portid", "0"))
            protocol = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            service_elem = port_elem.find("service")
            service_name = None
            product = None
            version = None
            banner = None
            cpe_text = None

            if service_elem is not None:
                service_name = service_elem.get("name")
                product = service_elem.get("product")
                version = service_elem.get("version")
                extra_info = service_elem.get("extrainfo", "")
                if extra_info:
                    banner = extra_info

                cpe_elem = service_elem.find("cpe")
                if cpe_elem is not None and cpe_elem.text:
                    cpe_text = cpe_elem.text

            ports.append(PortRecord(
                port=port_id,
                protocol=protocol,
                service=service_name,
                product=product,
                version=version,
                banner=banner,
                ip_address=ip_address,
            ))

            if product:
                technologies.append(TechnologyRecord(
                    name=product,
                    version=version,
                    cpe=cpe_text,
                    category="service",
                    ip_address=ip_address,
                    port=port_id,
                ))

            # Parse NSE script output for vulnerabilities
            for script_elem in port_elem.findall("script"):
                _parse_nse_vuln(script_elem, ip_address, port_id, vulnerabilities)

        # Parse OS detection
        for osmatch in host.findall(".//osmatch"):
            os_name = osmatch.get("name", "")
            accuracy = int(osmatch.get("accuracy", "0"))

            os_family = None
            os_gen = None
            os_cpe = None

            osclass = osmatch.find("osclass")
            if osclass is not None:
                os_family = osclass.get("osfamily")
                os_gen = osclass.get("osgen")
                cpe_elem = osclass.find("cpe")
                if cpe_elem is not None and cpe_elem.text:
                    os_cpe = cpe_elem.text

            os_detections.append(OSDetectionRecord(
                ip_address=ip_address,
                os_family=os_family or os_name,
                os_generation=os_gen,
                os_accuracy=accuracy,
                os_cpe=os_cpe,
            ))

        # Parse host-level NSE scripts
        for script_elem in host.findall(".//hostscript/script"):
            _parse_nse_vuln(script_elem, ip_address, 0, vulnerabilities)

    return {
        "ports": ports,
        "technologies": technologies,
        "os_detections": os_detections,
        "vulnerabilities": vulnerabilities,
    }


def _parse_nse_vuln(
    script_elem: ET.Element,
    ip_address: str,
    port: int,
    vulns: list[VulnerabilityRecord],
) -> None:
    """Extract vulnerability info from an NSE script element."""
    script_id = script_elem.get("id", "")
    output = script_elem.get("output", "")

    # Skip non-vulnerability scripts
    vuln_keywords = ["vuln", "CVE", "VULNERABLE", "exploit"]
    if not any(kw.lower() in (script_id + output).lower() for kw in vuln_keywords):
        return

    severity = VulnSeverity.UNKNOWN
    if "VULNERABLE" in output.upper():
        severity = VulnSeverity.HIGH

    # Try to extract CVE IDs
    import re
    cve_matches = re.findall(r"CVE-\d{4}-\d+", output)
    references = list(set(cve_matches))
    vuln_id = references[0] if references else script_id

    vulns.append(VulnerabilityRecord(
        vuln_id=vuln_id,
        title=f"NSE: {script_id}",
        severity=severity,
        affected_host=ip_address,
        affected_port=port if port > 0 else None,
        scanner="nmap",
        references=references,
        description=output[:500] if output else None,
    ))
