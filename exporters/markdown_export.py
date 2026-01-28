"""Markdown report exporter for Shadow-OSINT scan results."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from core.models import AIAnalysis, ScanResult


def export_markdown(
    scan: ScanResult,
    analysis: Optional[AIAnalysis] = None,
) -> str:
    """Generate a complete Markdown report from scan results.

    Args:
        scan: Complete scan results.
        analysis: Optional AI analysis results.

    Returns:
        Markdown formatted report string.
    """
    lines: list[str] = []

    # Header
    lines.append(f"# Shadow-OSINT Report: {scan.target}")
    lines.append("")
    lines.append(f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Input Type:** {scan.input_type.value}")
    lines.append(f"**Sources Used:** {', '.join(scan.sources_used) if scan.sources_used else 'None'}")
    lines.append("")

    # AI Analysis
    if analysis:
        lines.append("---")
        lines.append("")
        lines.append("## AI Security Analysis")
        lines.append("")
        lines.append(f"**Risk Score:** {analysis.risk_score}/100")
        lines.append(f"**Attack Surface:** {analysis.attack_surface_size}")
        lines.append("")
        lines.append("### Executive Summary")
        lines.append("")
        lines.append(analysis.executive_summary)
        lines.append("")

        if analysis.findings:
            lines.append("### Findings")
            lines.append("")
            for i, finding in enumerate(analysis.findings, 1):
                severity_badge = _severity_badge(finding.severity.value)
                lines.append(f"#### {i}. {finding.title} {severity_badge}")
                lines.append("")
                lines.append(finding.description)
                lines.append("")
                if finding.affected_assets:
                    lines.append("**Affected Assets:**")
                    for asset in finding.affected_assets:
                        lines.append(f"- `{asset}`")
                    lines.append("")
                lines.append(f"**Recommendation:** {finding.recommendation}")
                lines.append("")

        lines.append("### Exposed Services Summary")
        lines.append("")
        lines.append(analysis.exposed_services_summary)
        lines.append("")

        if analysis.recommendations:
            lines.append("### Recommendations")
            lines.append("")
            for rec in analysis.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

    # Subdomains
    lines.append("---")
    lines.append("")
    lines.append(f"## Subdomains ({len(scan.subdomains)})")
    lines.append("")
    if scan.subdomains:
        lines.append("| Subdomain | Source |")
        lines.append("|-----------|--------|")
        for sub in scan.subdomains:
            lines.append(f"| `{sub.name}` | {sub.source} |")
    else:
        lines.append("*No subdomains discovered.*")
    lines.append("")

    # IPs
    lines.append(f"## IP Addresses ({len(scan.ips)})")
    lines.append("")
    if scan.ips:
        lines.append("| Address | Version | Hostnames | Country | ASN |")
        lines.append("|---------|---------|-----------|---------|-----|")
        for ip in scan.ips:
            hostnames = ", ".join(ip.hostnames[:3]) if ip.hostnames else "-"
            country = ip.geolocation.country if ip.geolocation else "-"
            asn = f"AS{ip.asn_info.asn}" if ip.asn_info else "-"
            lines.append(f"| `{ip.address}` | IPv{ip.version} | {hostnames} | {country} | {asn} |")
    else:
        lines.append("*No IP addresses discovered.*")
    lines.append("")

    # Ports
    lines.append(f"## Open Ports ({len(scan.ports)})")
    lines.append("")
    if scan.ports:
        lines.append("| IP | Port | Protocol | Service | Product | Version |")
        lines.append("|----|------|----------|---------|---------|---------|")
        for port in scan.ports:
            lines.append(
                f"| `{port.ip_address}` | {port.port} | {port.protocol} | "
                f"{port.service or '-'} | {port.product or '-'} | {port.version or '-'} |"
            )
    else:
        lines.append("*No open ports discovered.*")
    lines.append("")

    # Technologies
    lines.append(f"## Technologies ({len(scan.technologies)})")
    lines.append("")
    if scan.technologies:
        lines.append("| Name | Version | CPE | Category |")
        lines.append("|------|---------|-----|----------|")
        for tech in scan.technologies:
            lines.append(
                f"| {tech.name} | {tech.version or '-'} | "
                f"`{tech.cpe or '-'}` | {tech.category or '-'} |"
            )
    else:
        lines.append("*No technologies identified.*")
    lines.append("")

    # DNS
    if scan.dns_records:
        lines.append(f"## DNS Records ({len(scan.dns_records)} domains)")
        lines.append("")
        for dns_rec in scan.dns_records[:20]:
            lines.append(f"### {dns_rec.domain}")
            lines.append("")
            if dns_rec.a:
                lines.append(f"- **A:** {', '.join(dns_rec.a)}")
            if dns_rec.aaaa:
                lines.append(f"- **AAAA:** {', '.join(dns_rec.aaaa)}")
            if dns_rec.mx:
                lines.append(f"- **MX:** {', '.join(dns_rec.mx)}")
            if dns_rec.ns:
                lines.append(f"- **NS:** {', '.join(dns_rec.ns)}")
            if dns_rec.txt:
                for txt in dns_rec.txt:
                    lines.append(f"- **TXT:** `{txt}`")
            if dns_rec.cname:
                lines.append(f"- **CNAME:** {', '.join(dns_rec.cname)}")
            if dns_rec.soa:
                lines.append(f"- **SOA:** `{dns_rec.soa}`")
            lines.append("")

    # WHOIS
    if scan.whois:
        lines.append("## WHOIS Data")
        lines.append("")
        lines.append(f"- **Domain:** {scan.whois.domain}")
        lines.append(f"- **Registrar:** {scan.whois.registrar or 'N/A'}")
        lines.append(f"- **Organization:** {scan.whois.organization or 'N/A'}")
        lines.append(f"- **Country:** {scan.whois.country or 'N/A'}")
        lines.append(f"- **Created:** {scan.whois.creation_date or 'N/A'}")
        lines.append(f"- **Expires:** {scan.whois.expiration_date or 'N/A'}")
        if scan.whois.nameservers:
            lines.append(f"- **Nameservers:** {', '.join(scan.whois.nameservers)}")
        lines.append("")

    # === Active Scan Results ===
    if scan.active_scan_performed:
        lines.append("---")
        lines.append("")
        lines.append("## Active Scan Results")
        lines.append("")

        # Vulnerabilities
        if scan.vulnerabilities:
            lines.append(f"### Vulnerabilities ({len(scan.vulnerabilities)})")
            lines.append("")
            lines.append("| Severity | ID | Title | Host | Scanner |")
            lines.append("|----------|----|-------|------|---------|")
            for vuln in scan.vulnerabilities:
                sev_badge = _severity_badge(vuln.severity.value)
                vid = vuln.vuln_id or "-"
                host = vuln.affected_host or vuln.affected_url or "-"
                lines.append(f"| {sev_badge} | `{vid}` | {vuln.title[:60]} | {host} | {vuln.scanner} |")
            lines.append("")

        # WAF
        if scan.waf_info:
            lines.append("### WAF Detection")
            lines.append("")
            for waf in scan.waf_info:
                status = f"**{waf.waf_name}** ({waf.waf_vendor or 'Unknown'})" if waf.detected else "No WAF"
                lines.append(f"- `{waf.host}`: {status}")
            lines.append("")

        # SSL
        if scan.ssl_info:
            lines.append("### SSL/TLS Analysis")
            lines.append("")
            for ssl in scan.ssl_info:
                lines.append(f"#### {ssl.host}:{ssl.port}")
                if ssl.protocol_versions:
                    lines.append(f"- **Protocols:** {', '.join(ssl.protocol_versions)}")
                if ssl.has_weak_ciphers:
                    lines.append("- **Warning:** Weak ciphers detected")
                if ssl.vulnerabilities:
                    lines.append(f"- **SSL Vulnerabilities:** {', '.join(ssl.vulnerabilities)}")
                if ssl.certificate_subject:
                    lines.append(f"- **Subject:** {ssl.certificate_subject}")
                if ssl.certificate_expiry:
                    lines.append(f"- **Expires:** {ssl.certificate_expiry}")
                lines.append("")

        # OS Detection
        if scan.os_detection:
            lines.append("### OS Detection")
            lines.append("")
            lines.append("| IP | OS Family | Generation | Accuracy |")
            lines.append("|----|-----------|------------|----------|")
            for os_rec in scan.os_detection:
                lines.append(
                    f"| `{os_rec.ip_address}` | {os_rec.os_family or '-'} | "
                    f"{os_rec.os_generation or '-'} | {os_rec.os_accuracy or '-'}% |"
                )
            lines.append("")

        # Web Directories
        if scan.web_directories:
            lines.append(f"### Web Directories ({len(scan.web_directories)})")
            lines.append("")
            lines.append("| Status | URL | Size |")
            lines.append("|--------|-----|------|")
            for d in scan.web_directories[:100]:
                size = str(d.content_length) if d.content_length else "-"
                lines.append(f"| {d.status_code} | `{d.url}` | {size} |")
            lines.append("")

        # Active DNS
        if scan.active_dns:
            lines.append(f"### Active DNS ({len(scan.active_dns)})")
            lines.append("")
            lines.append("| Type | Host | Value | Method |")
            lines.append("|------|------|-------|--------|")
            for dns in scan.active_dns[:50]:
                lines.append(f"| {dns.record_type} | `{dns.host}` | `{dns.value}` | {dns.source_method} |")
            lines.append("")

    # Errors
    if scan.errors:
        lines.append("## Collection Errors")
        lines.append("")
        for err in scan.errors:
            lines.append(f"- {err}")
        lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    scan_type = "Active + Passive" if scan.active_scan_performed else "Passive"
    lines.append(f"*Report generated by Shadow-OSINT — {scan_type} reconnaissance tool.*")

    return "\n".join(lines)


def _severity_badge(severity: str) -> str:
    """Create a text badge for severity level."""
    badges = {
        "critical": "\U0001f534 CRITICAL",
        "high": "\U0001f7e0 HIGH",
        "medium": "\U0001f7e1 MEDIUM",
        "low": "\U0001f535 LOW",
        "info": "\u26aa INFO",
    }
    return badges.get(severity, severity.upper())
