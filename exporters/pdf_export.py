"""PDF report exporter using fpdf2 + mistune for Markdown parsing."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from fpdf import FPDF

from core.models import AIAnalysis, ScanResult
from exporters.markdown_export import export_markdown


class ShadowPDF(FPDF):
    """Custom PDF class with header/footer for Shadow-OSINT reports."""

    def __init__(self, target: str = ""):
        super().__init__()
        self.target = target
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Shadow-OSINT Report | {self.target}", align="L")
        self.ln(5)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def export_pdf(
    scan: ScanResult,
    analysis: Optional[AIAnalysis] = None,
    output_path: Optional[str] = None,
) -> bytes:
    """Generate a PDF report from scan results.

    Args:
        scan: Complete scan results.
        analysis: Optional AI analysis results.
        output_path: Optional file path to save the PDF.

    Returns:
        PDF content as bytes.
    """
    pdf = ShadowPDF(target=scan.target)
    pdf.alias_nb_pages()
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 15, f"OSINT Report: {scan.target}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 6, f"Input Type: {scan.input_type.value}", new_x="LMARGIN", new_y="NEXT")
    sources = ", ".join(scan.sources_used) if scan.sources_used else "None"
    pdf.cell(0, 6, f"Sources: {sources}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # AI Analysis
    if analysis:
        _add_section(pdf, "AI Security Analysis")

        # Risk score
        pdf.set_font("Helvetica", "B", 14)
        color = _risk_color(analysis.risk_score)
        pdf.set_text_color(*color)
        pdf.cell(0, 10, f"Risk Score: {analysis.risk_score}/100", new_x="LMARGIN", new_y="NEXT")

        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 8, f"Attack Surface: {analysis.attack_surface_size}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        # Executive Summary
        _add_subsection(pdf, "Executive Summary")
        _add_body(pdf, analysis.executive_summary)

        # Findings
        if analysis.findings:
            _add_subsection(pdf, "Findings")
            for i, finding in enumerate(analysis.findings, 1):
                pdf.set_font("Helvetica", "B", 10)
                severity_label = finding.severity.value.upper()
                pdf.cell(0, 7, f"{i}. [{severity_label}] {finding.title}", new_x="LMARGIN", new_y="NEXT")
                _add_body(pdf, finding.description)
                if finding.affected_assets:
                    pdf.set_font("Helvetica", "I", 9)
                    assets = ", ".join(finding.affected_assets[:10])
                    pdf.cell(0, 6, f"  Affected: {assets}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(0, 100, 0)
                pdf.multi_cell(0, 5, f"  Recommendation: {finding.recommendation}")
                pdf.set_text_color(0, 0, 0)
                pdf.ln(2)

        # Recommendations
        if analysis.recommendations:
            _add_subsection(pdf, "Recommendations")
            for rec in analysis.recommendations:
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 6, f"  - {rec}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

    # Subdomains
    _add_section(pdf, f"Subdomains ({len(scan.subdomains)})")
    if scan.subdomains:
        for sub in scan.subdomains[:100]:
            pdf.set_font("Courier", "", 8)
            pdf.cell(0, 5, f"  {sub.name}  ({sub.source})", new_x="LMARGIN", new_y="NEXT")
    else:
        _add_body(pdf, "No subdomains discovered.")

    # IPs
    _add_section(pdf, f"IP Addresses ({len(scan.ips)})")
    if scan.ips:
        for ip in scan.ips[:50]:
            pdf.set_font("Courier", "", 8)
            extras = []
            if ip.geolocation and ip.geolocation.country:
                extras.append(ip.geolocation.country)
            if ip.asn_info:
                extras.append(f"AS{ip.asn_info.asn}")
            suffix = f"  [{', '.join(extras)}]" if extras else ""
            pdf.cell(0, 5, f"  {ip.address}{suffix}", new_x="LMARGIN", new_y="NEXT")
    else:
        _add_body(pdf, "No IP addresses discovered.")

    # Ports
    _add_section(pdf, f"Open Ports ({len(scan.ports)})")
    if scan.ports:
        for port in scan.ports[:80]:
            pdf.set_font("Courier", "", 8)
            svc = f" ({port.service})" if port.service else ""
            pdf.cell(0, 5, f"  {port.ip_address}:{port.port}/{port.protocol}{svc}", new_x="LMARGIN", new_y="NEXT")
    else:
        _add_body(pdf, "No open ports discovered.")

    # Technologies
    _add_section(pdf, f"Technologies ({len(scan.technologies)})")
    if scan.technologies:
        for tech in scan.technologies[:50]:
            pdf.set_font("Courier", "", 8)
            ver = f" {tech.version}" if tech.version else ""
            pdf.cell(0, 5, f"  {tech.name}{ver}", new_x="LMARGIN", new_y="NEXT")
    else:
        _add_body(pdf, "No technologies identified.")

    # WHOIS
    if scan.whois:
        _add_section(pdf, "WHOIS Data")
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 6, f"  Registrar: {scan.whois.registrar or 'N/A'}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"  Organization: {scan.whois.organization or 'N/A'}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"  Created: {scan.whois.creation_date or 'N/A'}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 6, f"  Expires: {scan.whois.expiration_date or 'N/A'}", new_x="LMARGIN", new_y="NEXT")

    # === Active Scan Results ===
    if scan.active_scan_performed:
        _add_section(pdf, "Active Scan Results")

        if scan.vulnerabilities:
            _add_subsection(pdf, f"Vulnerabilities ({len(scan.vulnerabilities)})")
            for vuln in scan.vulnerabilities[:50]:
                pdf.set_font("Helvetica", "B", 9)
                sev = vuln.severity.value.upper()
                pdf.cell(0, 6, f"  [{sev}] {vuln.title[:80]}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Courier", "", 7)
                if vuln.vuln_id:
                    pdf.cell(0, 4, f"    ID: {vuln.vuln_id}", new_x="LMARGIN", new_y="NEXT")
                host_str = vuln.affected_host or vuln.affected_url or ""
                if host_str:
                    pdf.cell(0, 4, f"    Target: {host_str}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        if scan.waf_info:
            _add_subsection(pdf, "WAF Detection")
            for waf in scan.waf_info:
                pdf.set_font("Helvetica", "", 9)
                status = f"{waf.waf_name} ({waf.waf_vendor or 'Unknown'})" if waf.detected else "No WAF"
                pdf.cell(0, 6, f"  {waf.host}: {status}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        if scan.ssl_info:
            _add_subsection(pdf, "SSL/TLS Analysis")
            for ssl in scan.ssl_info:
                pdf.set_font("Helvetica", "B", 9)
                pdf.cell(0, 6, f"  {ssl.host}:{ssl.port}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 8)
                if ssl.protocol_versions:
                    pdf.cell(0, 5, f"    Protocols: {', '.join(ssl.protocol_versions)}", new_x="LMARGIN", new_y="NEXT")
                if ssl.has_weak_ciphers:
                    pdf.set_text_color(200, 0, 0)
                    pdf.cell(0, 5, "    WARNING: Weak ciphers detected", new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(0, 0, 0)
                if ssl.certificate_expiry:
                    pdf.cell(0, 5, f"    Cert expires: {ssl.certificate_expiry}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        if scan.os_detection:
            _add_subsection(pdf, "OS Detection")
            for os_rec in scan.os_detection:
                pdf.set_font("Courier", "", 8)
                acc = f" ({os_rec.os_accuracy}%)" if os_rec.os_accuracy else ""
                pdf.cell(0, 5, f"  {os_rec.ip_address}: {os_rec.os_family or 'Unknown'}{acc}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

        if scan.web_directories:
            _add_subsection(pdf, f"Web Directories ({len(scan.web_directories)})")
            for d in scan.web_directories[:50]:
                pdf.set_font("Courier", "", 7)
                pdf.cell(0, 4, f"  [{d.status_code}] {d.url[:90]}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)

    # Errors
    if scan.errors:
        _add_section(pdf, "Collection Errors")
        for err in scan.errors:
            pdf.set_font("Helvetica", "", 8)
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 5, f"  - {err}", new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    # Output
    content = pdf.output()
    if output_path:
        Path(output_path).write_bytes(content)
    return content


def _add_section(pdf: FPDF, title: str) -> None:
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(0, 0, 0)
    pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(200, 200, 200)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)


def _add_subsection(pdf: FPDF, title: str) -> None:
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(50, 50, 50)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _add_body(pdf: FPDF, text: str) -> None:
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(0, 0, 0)
    pdf.multi_cell(0, 5, text)
    pdf.ln(2)


def _risk_color(score: int) -> tuple[int, int, int]:
    if score >= 80:
        return (200, 0, 0)
    elif score >= 60:
        return (230, 126, 34)
    elif score >= 40:
        return (241, 196, 15)
    elif score >= 20:
        return (52, 152, 219)
    else:
        return (46, 204, 113)
