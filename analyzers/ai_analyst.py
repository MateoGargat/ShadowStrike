"""AI-powered security analyst using Mixture of Agents (MoA) architecture.

Supports multiple LLM providers (Groq, OpenAI, Anthropic) with structured output
via instructor. Implements propose/aggregate/reflect pattern for robust analysis.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

from core.models import (
    AIAnalysis,
    AppConfig,
    Finding,
    ProposerAnalysis,
    RiskLevel,
    ScanResult,
)
from analyzers.graph_rag import GraphRAGExtractor
from analyzers.llm_providers import LLMProvider
from analyzers.prompts import (
    AGGREGATOR_PROMPT,
    PROPOSER_PROMPT,
    REFLECTION_PROMPT,
    build_adaptive_prompt,
)

logger = logging.getLogger(__name__)


class AIAnalyst:
    """Security analyst powered by Mixture of Agents with structured output."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.provider = LLMProvider(config)
        self.graph_rag = GraphRAGExtractor()

    def analyze(self, scan_result: ScanResult) -> AIAnalysis:
        """Analyze scan results using single-provider mode (backward compatible).

        This is the original entry point used by the workflow when operating
        in non-MoA mode. For MoA, the workflow calls propose/aggregate/reflect
        directly.

        Args:
            scan_result: Complete scan results to analyze.

        Returns:
            AIAnalysis with risk score, findings, and recommendations.
        """
        context = self._build_context(scan_result)
        adaptive = build_adaptive_prompt(scan_result)
        system_prompt = PROPOSER_PROMPT
        if adaptive:
            system_prompt += adaptive

        try:
            analysis = self.provider.call(
                provider="groq",
                model=self.config.llm_model,
                system_prompt=system_prompt,
                user_prompt=context,
                response_model=AIAnalysis,
                temperature=self.config.llm_temperature,
                max_tokens=self.config.llm_max_tokens,
            )
            return analysis

        except Exception as exc:
            logger.error("AI analysis failed: %s", exc)
            return AIAnalysis(
                risk_score=0,
                executive_summary=f"AI analysis failed: {exc}",
                attack_surface_size="Unknown",
                findings=[],
                exposed_services_summary="Analysis unavailable",
                recommendations=["Retry the analysis with a valid API key."],
                methodology_notes=f"Error during analysis: {type(exc).__name__}",
            )

    def propose(
        self,
        provider: str,
        model: str,
        system_prompt: str,
        context: str,
    ) -> ProposerAnalysis:
        """Layer 1: A single proposer produces its analysis.

        Args:
            provider: LLM provider name.
            model: Model identifier.
            system_prompt: The proposer-specific system prompt.
            context: OSINT data + GraphRAG context.

        Returns:
            ProposerAnalysis with the proposer's findings.
        """
        result = self.provider.call(
            provider=provider,
            model=model,
            system_prompt=system_prompt,
            user_prompt=context,
            response_model=ProposerAnalysis,
            temperature=self.config.llm_temperature,
            max_tokens=self.config.llm_max_tokens,
        )
        # Ensure provider/model fields are set
        result.provider = provider
        result.model = model
        return result

    def aggregate(
        self,
        proposals: list[ProposerAnalysis],
        context: str,
    ) -> AIAnalysis:
        """Layer 2: Aggregate multiple proposer analyses into a final assessment.

        Args:
            proposals: List of individual proposer analyses.
            context: Original OSINT context for reference.

        Returns:
            AIAnalysis with the consolidated assessment.
        """
        analyses_text = self._format_proposals_for_aggregator(proposals)
        aggregator_prompt = AGGREGATOR_PROMPT.format(
            n=len(proposals),
            analyses=analyses_text,
        )

        # Use the configured aggregator provider/model
        agg_config = self.config.moa_config.aggregator
        agg_provider = agg_config.get("provider", "groq")
        agg_model = agg_config.get("model", self.config.llm_model)

        # If the configured aggregator provider is unavailable, fall back
        available = self.provider.get_available_providers()
        if agg_provider not in available and available:
            agg_provider = available[0]
            agg_model = self.config.llm_model

        result = self.provider.call(
            provider=agg_provider,
            model=agg_model,
            system_prompt=aggregator_prompt,
            user_prompt=context,
            response_model=AIAnalysis,
            temperature=self.config.llm_temperature,
            max_tokens=self.config.llm_max_tokens,
        )
        result.proposer_count = len(proposals)
        return result

    def reflect(self, analysis: AIAnalysis, context: str) -> AIAnalysis:
        """Reflection: self-critique and refinement of the final analysis.

        Args:
            analysis: The aggregated analysis to review.
            context: Original OSINT context for verification.

        Returns:
            Improved AIAnalysis after reflection.
        """
        analysis_json = analysis.model_dump_json(indent=2)
        reflection_prompt = REFLECTION_PROMPT.format(
            analysis=analysis_json,
            context=context[:8000],  # Limit context to avoid token overflow
        )

        # Use the aggregator provider for reflection
        agg_config = self.config.moa_config.aggregator
        agg_provider = agg_config.get("provider", "groq")
        agg_model = agg_config.get("model", self.config.llm_model)

        available = self.provider.get_available_providers()
        if agg_provider not in available and available:
            agg_provider = available[0]
            agg_model = self.config.llm_model

        result = self.provider.call(
            provider=agg_provider,
            model=agg_model,
            system_prompt=reflection_prompt,
            user_prompt="Review and improve the analysis above. Return the improved version.",
            response_model=AIAnalysis,
            temperature=self.config.llm_temperature,
            max_tokens=self.config.llm_max_tokens,
        )
        result.analysis_version = analysis.analysis_version + 1
        result.proposer_count = analysis.proposer_count
        return result

    def _format_proposals_for_aggregator(
        self, proposals: list[ProposerAnalysis]
    ) -> str:
        """Format proposer analyses for the aggregator prompt."""
        sections = []
        for i, p in enumerate(proposals, 1):
            findings_text = "\n".join(
                f"  - [{f.severity.value.upper()}] {f.title}: {f.description}"
                for f in p.findings
            )
            sections.append(
                f"### Analyst {i} ({p.provider}/{p.model}, confidence={p.confidence})\n"
                f"Risk Score: {p.risk_score}/100\n"
                f"Summary: {p.executive_summary}\n"
                f"Findings:\n{findings_text}\n"
                f"Recommendations: {', '.join(p.recommendations)}"
            )
        return "\n\n".join(sections)

    def _build_context(self, scan: ScanResult) -> str:
        """Build analysis context from scan results."""
        sections: list[str] = []

        sections.append(f"# OSINT Reconnaissance Report for: {scan.target}")
        sections.append(f"Input type: {scan.input_type.value}")
        sections.append(f"Sources used: {', '.join(scan.sources_used)}")

        # Subdomains
        if scan.subdomains:
            sections.append(f"\n## Subdomains ({len(scan.subdomains)} found)")
            for sub in scan.subdomains[:50]:
                sections.append(f"- {sub.name} (source: {sub.source})")
            if len(scan.subdomains) > 50:
                sections.append(f"... and {len(scan.subdomains) - 50} more")

        # IPs
        if scan.ips:
            sections.append(f"\n## IP Addresses ({len(scan.ips)} found)")
            for ip in scan.ips[:30]:
                geo_str = ""
                if ip.geolocation:
                    geo_str = f" [{ip.geolocation.country or '?'}, {ip.geolocation.city or '?'}]"
                asn_str = ""
                if ip.asn_info:
                    asn_str = f" (AS{ip.asn_info.asn} {ip.asn_info.name or ''})"
                sections.append(f"- {ip.address}{geo_str}{asn_str}")

        # Ports
        if scan.ports:
            sections.append(f"\n## Open Ports ({len(scan.ports)} found)")
            for port in scan.ports[:50]:
                svc = f" ({port.service})" if port.service else ""
                prod = f" - {port.product}" if port.product else ""
                ver = f" {port.version}" if port.version else ""
                sections.append(f"- {port.ip_address}:{port.port}/{port.protocol}{svc}{prod}{ver}")

        # Technologies
        if scan.technologies:
            sections.append(f"\n## Technologies ({len(scan.technologies)} found)")
            for tech in scan.technologies[:30]:
                ver = f" {tech.version}" if tech.version else ""
                cpe = f" (CPE: {tech.cpe})" if tech.cpe else ""
                sections.append(f"- {tech.name}{ver}{cpe}")

        # DNS
        if scan.dns_records:
            sections.append(f"\n## DNS Records ({len(scan.dns_records)} domains)")
            for dns_rec in scan.dns_records[:10]:
                sections.append(f"\n### {dns_rec.domain}")
                if dns_rec.a:
                    sections.append(f"  A: {', '.join(dns_rec.a)}")
                if dns_rec.mx:
                    sections.append(f"  MX: {', '.join(dns_rec.mx)}")
                if dns_rec.ns:
                    sections.append(f"  NS: {', '.join(dns_rec.ns)}")
                if dns_rec.txt:
                    for txt in dns_rec.txt:
                        sections.append(f"  TXT: {txt}")

        # WHOIS
        if scan.whois:
            sections.append("\n## WHOIS Data")
            sections.append(f"  Registrar: {scan.whois.registrar or 'N/A'}")
            sections.append(f"  Organization: {scan.whois.organization or 'N/A'}")
            sections.append(f"  Creation: {scan.whois.creation_date or 'N/A'}")
            sections.append(f"  Expiration: {scan.whois.expiration_date or 'N/A'}")
            if scan.whois.nameservers:
                sections.append(f"  Nameservers: {', '.join(scan.whois.nameservers)}")

        # Errors
        if scan.errors:
            sections.append(f"\n## Data Collection Errors ({len(scan.errors)})")
            for err in scan.errors:
                sections.append(f"- {err}")

        # Active Scan Data
        if scan.active_scan_performed:
            sections.append("\n---")
            sections.append("\n## ACTIVE SCAN RESULTS (confirmed by direct scanning)")
            sections.append("The following data was obtained through active scanning tools, not just passive OSINT.")

            if scan.vulnerabilities:
                sections.append(f"\n### Confirmed Vulnerabilities ({len(scan.vulnerabilities)})")
                for vuln in scan.vulnerabilities[:30]:
                    sev = vuln.severity.value.upper()
                    refs = ", ".join(vuln.references[:3]) if vuln.references else ""
                    cvss_str = f" (CVSS: {vuln.cvss})" if vuln.cvss else ""
                    sections.append(f"- [{sev}]{cvss_str} {vuln.title}")
                    if vuln.affected_url:
                        sections.append(f"  URL: {vuln.affected_url}")
                    elif vuln.affected_host:
                        port_str = f":{vuln.affected_port}" if vuln.affected_port else ""
                        sections.append(f"  Host: {vuln.affected_host}{port_str}")
                    if refs:
                        sections.append(f"  References: {refs}")

            if scan.waf_info:
                sections.append(f"\n### WAF Detection ({len(scan.waf_info)} hosts)")
                for waf in scan.waf_info:
                    status = f"{waf.waf_name} ({waf.waf_vendor or 'Unknown vendor'})" if waf.detected else "No WAF detected"
                    sections.append(f"- {waf.host}: {status}")

            if scan.ssl_info:
                sections.append(f"\n### SSL/TLS Analysis ({len(scan.ssl_info)} endpoints)")
                for ssl in scan.ssl_info:
                    sections.append(f"- {ssl.host}:{ssl.port}")
                    if ssl.protocol_versions:
                        sections.append(f"  Protocols: {', '.join(ssl.protocol_versions)}")
                    if ssl.has_weak_ciphers:
                        sections.append("  WARNING: Weak ciphers detected")
                    if ssl.vulnerabilities:
                        sections.append(f"  SSL Vulns: {', '.join(ssl.vulnerabilities)}")
                    if ssl.certificate_expiry:
                        sections.append(f"  Cert expires: {ssl.certificate_expiry}")

            if scan.os_detection:
                sections.append(f"\n### OS Detection ({len(scan.os_detection)} hosts)")
                for os_rec in scan.os_detection:
                    acc = f" ({os_rec.os_accuracy}% confidence)" if os_rec.os_accuracy else ""
                    sections.append(f"- {os_rec.ip_address}: {os_rec.os_family or 'Unknown'}{acc}")

            if scan.web_directories:
                sections.append(f"\n### Web Directories ({len(scan.web_directories)} found)")
                for d in scan.web_directories[:20]:
                    sections.append(f"- [{d.status_code}] {d.url}")

            if scan.active_dns:
                sections.append(f"\n### Active DNS Records ({len(scan.active_dns)} records)")
                for dns in scan.active_dns[:20]:
                    sections.append(f"- {dns.record_type} {dns.host} -> {dns.value}")

        sections.append("\n---")
        sections.append("Analyze the above data and provide a comprehensive security assessment.")
        if scan.active_scan_performed:
            sections.append("IMPORTANT: Active scan data provides confirmed findings. "
                          "Weight confirmed CVEs and vulnerabilities higher than passive observations. "
                          "Distinguish between passive observations and active confirmations in your analysis.")

        return "\n".join(sections)
