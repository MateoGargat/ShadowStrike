"""Input parsing and validation for Shadow-OSINT."""

from __future__ import annotations

import ipaddress
import re

from core.models import InputType, ParsedInput

# RFC 1123 compliant domain regex
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def parse_input(raw: str) -> ParsedInput:
    """Parse and validate user input as domain, IP, or CIDR.

    Args:
        raw: Raw user input string.

    Returns:
        ParsedInput with validated and normalized target.

    Raises:
        ValueError: If input is invalid or unsupported.
    """
    cleaned = raw.strip()
    if not cleaned:
        raise ValueError("Input cannot be empty.")

    # Try CIDR first (contains '/')
    if "/" in cleaned:
        return _parse_cidr(cleaned)

    # Try IP
    try:
        return _parse_ip(cleaned)
    except ValueError:
        pass

    # Try domain
    return _parse_domain(cleaned)


def _parse_domain(value: str) -> ParsedInput:
    """Validate and normalize a domain name."""
    normalized = value.lower().rstrip(".")
    if not _DOMAIN_RE.match(normalized):
        raise ValueError(
            f"Invalid input: '{value}' is not a valid domain, IP address, or CIDR range."
        )
    return ParsedInput(
        raw=value,
        input_type=InputType.DOMAIN,
        target=normalized,
    )


def _parse_ip(value: str) -> ParsedInput:
    """Validate an IPv4 or IPv6 address."""
    addr = ipaddress.ip_address(value)
    return ParsedInput(
        raw=value,
        input_type=InputType.IP,
        target=str(addr),
    )


def _parse_cidr(value: str) -> ParsedInput:
    """Validate a CIDR range (max /24)."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR range: '{value}'. {exc}") from exc

    if network.version == 4 and network.prefixlen < 24:
        raise ValueError(
            f"CIDR range too large: /{network.prefixlen}. "
            f"Maximum allowed is /24 (256 addresses)."
        )
    if network.version == 6 and network.prefixlen < 112:
        raise ValueError(
            f"IPv6 CIDR range too large: /{network.prefixlen}. "
            f"Maximum allowed is /112."
        )

    targets = [str(ip) for ip in network.hosts()]
    return ParsedInput(
        raw=value,
        input_type=InputType.CIDR,
        target=str(network),
        targets=targets,
    )
