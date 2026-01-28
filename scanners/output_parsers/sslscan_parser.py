"""Parse sslscan XML output into structured records."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET

from core.models import SSLRecord

logger = logging.getLogger(__name__)

WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0"}


def parse_sslscan_xml(xml_output: str) -> list[SSLRecord]:
    """Parse sslscan XML output.

    Args:
        xml_output: Raw XML string from sslscan --xml=-.

    Returns:
        List of SSLRecord entries.
    """
    records: list[SSLRecord] = []

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        logger.error("Failed to parse sslscan XML: %s", exc)
        return records

    for test in root.findall(".//ssltest"):
        host = test.get("host", "")
        port_str = test.get("port", "443")
        port = int(port_str) if port_str.isdigit() else 443

        protocols: list[str] = []
        ciphers: list[str] = []
        has_weak = False
        ssl_vulns: list[str] = []

        # Parse protocols
        for proto in test.findall(".//protocol"):
            proto_type = proto.get("type", "")
            proto_version = proto.get("version", "")
            enabled = proto.get("enabled", "0")
            name = f"{proto_type}v{proto_version}" if proto_version else proto_type
            if enabled == "1":
                protocols.append(name)
                if name in WEAK_PROTOCOLS:
                    has_weak = True
                    ssl_vulns.append(f"Weak protocol: {name}")

        # Parse ciphers
        for cipher in test.findall(".//cipher"):
            status = cipher.get("status", "")
            if status not in ("accepted", "preferred"):
                continue
            cipher_name = cipher.get("cipher", "")
            bits = cipher.get("bits", "")
            cipher_str = f"{cipher_name} ({bits}-bit)" if bits else cipher_name
            ciphers.append(cipher_str)

            for weak in WEAK_CIPHERS:
                if weak.lower() in cipher_name.lower():
                    has_weak = True
                    ssl_vulns.append(f"Weak cipher: {cipher_name}")
                    break

        # Parse certificate
        cert_subject = None
        cert_issuer = None
        cert_expiry = None
        cert_san: list[str] = []

        cert_elem = test.find(".//certificate")
        if cert_elem is not None:
            subject_elem = cert_elem.find("subject")
            if subject_elem is not None and subject_elem.text:
                cert_subject = subject_elem.text

            issuer_elem = cert_elem.find("issuer")
            if issuer_elem is not None and issuer_elem.text:
                cert_issuer = issuer_elem.text

            not_after = cert_elem.find("not-valid-after")
            if not_after is not None and not_after.text:
                cert_expiry = not_after.text

            # SANs
            alt_names = cert_elem.find("altnames")
            if alt_names is not None:
                for alt in alt_names.findall("altname"):
                    if alt.text:
                        cert_san.append(alt.text)

        # Check for known vulnerabilities
        heartbleed = test.find(".//heartbleed")
        if heartbleed is not None and heartbleed.get("vulnerable", "0") == "1":
            ssl_vulns.append("Heartbleed (CVE-2014-0160)")

        renegotiation = test.find(".//renegotiation")
        if renegotiation is not None and renegotiation.get("secure", "1") == "0":
            ssl_vulns.append("Insecure renegotiation")

        records.append(SSLRecord(
            host=host,
            port=port,
            protocol_versions=protocols,
            cipher_suites=ciphers,
            certificate_subject=cert_subject,
            certificate_issuer=cert_issuer,
            certificate_expiry=cert_expiry,
            certificate_san=cert_san,
            has_weak_ciphers=has_weak,
            vulnerabilities=ssl_vulns,
        ))

    return records
