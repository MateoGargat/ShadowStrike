"""Shadow-OSINT — Streamlit User Interface."""

from __future__ import annotations

import json
import os
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

from cache.cache_manager import CacheManager
from core.graph import build_graph, get_graph_stats
from core.models import (
    ActiveScanConfig,
    AIAnalysis,
    AppConfig,
    GraphData,
    MoAConfig,
    ProposerAnalysis,
    ScanIntensity,
    ScanResult,
)
from exporters.markdown_export import export_markdown
from exporters.pdf_export import export_pdf
from visualization.graph_renderer import get_legend_html, render_graph
from workflow import WorkflowRunner

# === Page Config ===
st.set_page_config(
    page_title="Shadow-OSINT",
    page_icon="🕵️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# === Custom CSS ===
st.markdown("""
<style>
    .stApp { background-color: #0e1117; }
    .risk-critical { color: #e74c3c; font-size: 2em; font-weight: bold; }
    .risk-high { color: #e67e22; font-size: 2em; font-weight: bold; }
    .risk-medium { color: #f1c40f; font-size: 2em; font-weight: bold; }
    .risk-low { color: #3498db; font-size: 2em; font-weight: bold; }
    .risk-info { color: #2ecc71; font-size: 2em; font-weight: bold; }
    .vuln-critical { background-color: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; }
    .vuln-high { background-color: #e67e22; color: white; padding: 2px 8px; border-radius: 4px; }
    .vuln-medium { background-color: #f1c40f; color: black; padding: 2px 8px; border-radius: 4px; }
    .vuln-low { background-color: #3498db; color: white; padding: 2px 8px; border-radius: 4px; }
    .vuln-info { background-color: #2ecc71; color: white; padding: 2px 8px; border-radius: 4px; }
    .consensus-high { color: #2ecc71; font-weight: bold; }
    .consensus-medium { color: #f1c40f; font-weight: bold; }
    .consensus-low { color: #e74c3c; font-weight: bold; }
</style>
""", unsafe_allow_html=True)


def _get_config(
    active_scan_config: ActiveScanConfig | None = None,
    moa_config: MoAConfig | None = None,
) -> AppConfig:
    """Build AppConfig from sidebar inputs and environment."""
    return AppConfig(
        groq_api_key=st.session_state.get("groq_key", os.getenv("GROQ_API_KEY", "")),
        openai_api_key=st.session_state.get("openai_key", os.getenv("OPENAI_API_KEY", "")) or None,
        anthropic_api_key=st.session_state.get("anthropic_key", os.getenv("ANTHROPIC_API_KEY", "")) or None,
        shodan_api_key=st.session_state.get("shodan_key", os.getenv("SHODAN_API_KEY", "")),
        virustotal_api_key=st.session_state.get("vt_key", os.getenv("VIRUSTOTAL_API_KEY", "")),
        ipinfo_token=st.session_state.get("ipinfo_key", os.getenv("IPINFO_TOKEN", "")),
        active_scan=active_scan_config or ActiveScanConfig(),
        moa_config=moa_config or MoAConfig(),
    )


def _risk_class(score: int) -> str:
    if score >= 80:
        return "risk-critical"
    elif score >= 60:
        return "risk-high"
    elif score >= 40:
        return "risk-medium"
    elif score >= 20:
        return "risk-low"
    return "risk-info"


def _severity_color(severity: str) -> str:
    colors = {
        "critical": "🔴", "high": "🟠",
        "medium": "🟡", "low": "🔵", "info": "⚪", "unknown": "⚫",
    }
    return colors.get(severity, "⚫")


def _consensus_class(level: str) -> str:
    return f"consensus-{level}" if level in ("high", "medium", "low") else ""


def main():
    # === Sidebar ===
    with st.sidebar:
        st.title("⚙️ Configuration")
        st.markdown("---")

        st.subheader("API Keys")
        st.text_input(
            "Groq API Key (required)",
            type="password",
            key="groq_key",
            value=os.getenv("GROQ_API_KEY", ""),
        )
        st.text_input(
            "OpenAI API Key (optional - MoA)",
            type="password",
            key="openai_key",
            value=os.getenv("OPENAI_API_KEY", ""),
        )
        st.text_input(
            "Anthropic API Key (optional - MoA)",
            type="password",
            key="anthropic_key",
            value=os.getenv("ANTHROPIC_API_KEY", ""),
        )
        st.text_input(
            "Shodan API Key (optional)",
            type="password",
            key="shodan_key",
            value=os.getenv("SHODAN_API_KEY", ""),
        )
        st.text_input(
            "VirusTotal API Key (optional)",
            type="password",
            key="vt_key",
            value=os.getenv("VIRUSTOTAL_API_KEY", ""),
        )
        st.text_input(
            "IPInfo Token (optional)",
            type="password",
            key="ipinfo_key",
            value=os.getenv("IPINFO_TOKEN", ""),
        )

        st.markdown("---")
        st.subheader("Cache")
        col1, col2 = st.columns(2)
        with col1:
            cache_enabled = st.checkbox("Enable cache", value=True)
        with col2:
            if st.button("Clear cache"):
                cm = CacheManager(enabled=True)
                count = cm.clear_all()
                st.success(f"Cleared {count} entries")

        # === MoA Configuration ===
        st.markdown("---")
        st.subheader("AI Analysis (MoA)")

        # Show which providers are available
        available_providers = []
        if st.session_state.get("groq_key") or os.getenv("GROQ_API_KEY"):
            available_providers.append("Groq")
        if st.session_state.get("openai_key") or os.getenv("OPENAI_API_KEY"):
            available_providers.append("OpenAI")
        if st.session_state.get("anthropic_key") or os.getenv("ANTHROPIC_API_KEY"):
            available_providers.append("Anthropic")

        if available_providers:
            st.caption(f"Providers: {', '.join(available_providers)}")
            if len(available_providers) >= 2:
                st.success(f"Multi-provider MoA ({len(available_providers)} providers)")
            else:
                st.info("Mono-provider (dual-perspective fallback)")
        else:
            st.warning("No AI provider configured")

        with st.expander("MoA Settings"):
            enable_reflection = st.checkbox("Enable reflection", value=True, key="moa_reflection")
            max_reflection = st.number_input(
                "Max reflection iterations",
                min_value=0, max_value=3, value=1, key="moa_max_reflection",
            )

        # Build MoA config
        proposers = []
        if st.session_state.get("groq_key") or os.getenv("GROQ_API_KEY"):
            proposers.append({"provider": "groq", "model": "llama-3.3-70b-versatile"})
        if st.session_state.get("openai_key") or os.getenv("OPENAI_API_KEY"):
            proposers.append({"provider": "openai", "model": "gpt-4o-mini"})
        if st.session_state.get("anthropic_key") or os.getenv("ANTHROPIC_API_KEY"):
            proposers.append({"provider": "anthropic", "model": "claude-3-5-haiku-20241022"})

        # Use strongest available as aggregator
        aggregator = {"provider": "groq", "model": "llama-3.3-70b-versatile"}
        if st.session_state.get("openai_key") or os.getenv("OPENAI_API_KEY"):
            aggregator = {"provider": "openai", "model": "gpt-4o-mini"}

        moa_config = MoAConfig(
            proposers=proposers if proposers else [{"provider": "groq", "model": "llama-3.3-70b-versatile"}],
            aggregator=aggregator,
            enable_reflection=enable_reflection,
            max_reflection_iterations=max_reflection,
        )

        # === Active Scanning Section ===
        st.markdown("---")
        st.subheader("Active Scanning")

        active_scan_enabled = st.toggle("Enable active scanning", value=False, key="active_scan_toggle")

        if active_scan_enabled:
            st.warning(
                "Ensure you have explicit authorization to scan the target. "
                "Active scanning sends probes directly to the target.",
                icon="⚠️",
            )

            # Intensity
            intensity_map = {"Quick": "quick", "Standard": "standard", "Aggressive": "aggressive"}
            intensity_label = st.select_slider(
                "Scan Intensity",
                options=["Quick", "Standard", "Aggressive"],
                value="Standard",
            )
            intensity = ScanIntensity(intensity_map[intensity_label])

            # Detect installed tools
            from scanners.tool_detector import detect_all_tools
            from scanners import ALL_SCANNER_NAMES

            installed_tools = detect_all_tools()
            installed_names = [t.name for t in installed_tools if t.installed]
            missing_names = [t.name for t in installed_tools if not t.installed]

            if installed_names:
                st.success(f"Installed: {', '.join(installed_names)}")
            if missing_names:
                st.caption(f"Not found: {', '.join(missing_names)}")

            # Scanner selection
            available_for_select = [n for n in ALL_SCANNER_NAMES if n in installed_names]
            default_selection = [n for n in available_for_select if n != "ffuf"]
            selected_scanners = st.multiselect(
                "Scanners to run",
                options=available_for_select,
                default=default_selection,
            )

            # Advanced settings
            with st.expander("Advanced Settings"):
                nmap_top_ports = st.number_input(
                    "Nmap top ports (0 = use profile default)",
                    min_value=0, max_value=65535, value=0, step=100,
                )
                scanner_timeout = st.number_input(
                    "Scanner timeout (seconds)",
                    min_value=60, max_value=7200, value=600, step=60,
                )
                max_concurrent = st.number_input(
                    "Max concurrent scanners",
                    min_value=1, max_value=10, value=3,
                )
                custom_wordlist = st.text_input(
                    "Custom wordlist path (optional)",
                    placeholder="/usr/share/wordlists/dirb/common.txt",
                )

            active_scan_config = ActiveScanConfig(
                enabled=True,
                intensity=intensity,
                selected_scanners=selected_scanners,
                nmap_top_ports=nmap_top_ports if nmap_top_ports > 0 else None,
                scanner_timeout=scanner_timeout,
                max_concurrent_scanners=max_concurrent,
                wordlist_path=custom_wordlist if custom_wordlist else None,
            )
        else:
            active_scan_config = ActiveScanConfig(enabled=False)

        st.markdown("---")
        scan_mode = "Active + Passive" if active_scan_enabled else "Passive"
        provider_count = len(available_providers)
        st.caption(f"Shadow-OSINT v2.0 — {scan_mode} | MoA ({provider_count} provider{'s' if provider_count != 1 else ''})")

    # === Main Content ===
    st.title("🕵️ Shadow-OSINT")
    st.markdown("**OSINT Reconnaissance & Attack Surface Analysis**")

    # Input
    col_input, col_btn = st.columns([4, 1])
    with col_input:
        target_input = st.text_input(
            "Target",
            placeholder="Enter domain (example.com), IP (8.8.8.8), or CIDR (8.8.8.0/28)",
            label_visibility="collapsed",
        )
    with col_btn:
        scan_clicked = st.button("🔍 Scan", type="primary", use_container_width=True)

    if scan_clicked and target_input:
        config = _get_config(active_scan_config, moa_config)

        if not config.groq_api_key and not config.openai_api_key and not config.anthropic_api_key:
            st.warning("At least one AI provider API key is required. Configure in the sidebar.")

        cache = CacheManager(
            enabled=cache_enabled,
            ttl_seconds=config.cache_ttl,
        )

        # Progress
        progress_bar = st.progress(0, text="Initializing...")
        status_text = st.empty()

        def on_progress(step: str, progress: float):
            progress_bar.progress(min(progress, 1.0), text=step)
            status_text.text(step)

        # Run workflow
        runner = WorkflowRunner(
            config=config,
            cache=cache,
            progress_callback=on_progress,
        )

        try:
            with st.spinner("Running scan..."):
                final_state = runner.run(target_input)

            progress_bar.progress(1.0, text="Complete!")

            # Check for parse errors
            if final_state.get("current_step") == "error":
                for err in final_state.get("errors", []):
                    st.error(err)
                return

            # Extract results
            scan_result = runner.get_scan_result(final_state)
            analysis = runner.get_analysis(final_state)

            graph_data_dict = final_state.get("graph_data", {})
            graph_data = GraphData(**graph_data_dict) if graph_data_dict.get("nodes") else None

            # Store in session
            st.session_state["scan_result"] = scan_result
            st.session_state["analysis"] = analysis
            st.session_state["graph_data"] = graph_data
            st.session_state["proposer_analyses"] = final_state.get("proposer_analyses", [])

        except Exception as exc:
            st.error(f"Scan failed: {exc}")
            return

    # === Display Results ===
    scan_result: ScanResult | None = st.session_state.get("scan_result")
    analysis: AIAnalysis | None = st.session_state.get("analysis")
    graph_data: GraphData | None = st.session_state.get("graph_data")

    if scan_result is None:
        st.info("Enter a target and click Scan to begin.")
        return

    # Tabs — 6 tabs if active scan was performed, otherwise 4
    if scan_result.active_scan_performed:
        tab_graph, tab_ai, tab_data, tab_active, tab_vulns, tab_export = st.tabs([
            "🔗 Graph", "🤖 AI Analysis", "📊 Data",
            "🎯 Active Scan", "🛡️ Vulnerabilities", "📥 Export",
        ])
    else:
        tab_graph, tab_ai, tab_data, tab_export = st.tabs([
            "🔗 Graph", "🤖 AI Analysis", "📊 Data", "📥 Export"
        ])
        tab_active = None
        tab_vulns = None

    # === Tab 1: Graph ===
    with tab_graph:
        if graph_data and graph_data.nodes:
            stats = get_graph_stats(graph_data)
            cols = st.columns(4)
            cols[0].metric("Nodes", stats["total_nodes"])
            cols[1].metric("Edges", stats["total_edges"])
            cols[2].metric("Subdomains", stats["nodes_by_type"].get("subdomain", 0))
            cols[3].metric("IPs", stats["nodes_by_type"].get("ip", 0))

            st.markdown(get_legend_html(), unsafe_allow_html=True)

            html = render_graph(graph_data)
            st.components.v1.html(html, height=720, scrolling=False)
        else:
            st.warning("No graph data available.")

    # === Tab 2: AI Analysis ===
    with tab_ai:
        if analysis:
            # Risk Score + MoA metadata
            risk_class = _risk_class(analysis.risk_score)
            col_score, col_meta = st.columns([2, 3])

            with col_score:
                st.markdown(
                    f'<div class="{risk_class}">Risk Score: {analysis.risk_score}/100</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(f"**Attack Surface:** {analysis.attack_surface_size}")

            with col_meta:
                # MoA metadata
                if analysis.proposer_count > 1:
                    consensus_cls = _consensus_class(analysis.consensus_level)
                    st.markdown(
                        f'**Consensus:** <span class="{consensus_cls}">'
                        f'{analysis.consensus_level.upper()}</span> '
                        f'({analysis.proposer_count} analysts)',
                        unsafe_allow_html=True,
                    )
                if analysis.confidence_score > 0:
                    st.markdown(f"**Confidence:** {analysis.confidence_score:.0%}")
                if analysis.analysis_version > 1:
                    st.markdown(f"**Version:** {analysis.analysis_version} (reflected)")

            st.markdown("---")

            st.subheader("Executive Summary")
            st.write(analysis.executive_summary)

            if analysis.findings:
                st.subheader("Findings")
                for finding in analysis.findings:
                    icon = _severity_color(finding.severity.value)
                    with st.expander(f"{icon} [{finding.severity.value.upper()}] {finding.title}"):
                        st.write(finding.description)
                        if finding.affected_assets:
                            st.write("**Affected Assets:**")
                            for asset in finding.affected_assets:
                                st.code(asset)
                        st.success(f"**Recommendation:** {finding.recommendation}")

            st.subheader("Exposed Services")
            st.write(analysis.exposed_services_summary)

            if analysis.recommendations:
                st.subheader("Recommendations")
                for rec in analysis.recommendations:
                    st.markdown(f"- {rec}")

            # Show individual proposer analyses
            proposer_data = st.session_state.get("proposer_analyses", [])
            if proposer_data and len(proposer_data) > 1:
                with st.expander(f"Individual Analyses ({len(proposer_data)} proposers)"):
                    for i, pd in enumerate(proposer_data, 1):
                        try:
                            pa = ProposerAnalysis(**pd)
                            st.markdown(f"### Analyst {i}: {pa.provider}/{pa.model}")
                            st.markdown(
                                f"**Risk Score:** {pa.risk_score}/100 | "
                                f"**Confidence:** {pa.confidence:.0%}"
                            )
                            st.write(pa.executive_summary)
                            if pa.findings:
                                for f in pa.findings:
                                    st.markdown(
                                        f"- [{f.severity.value.upper()}] {f.title}"
                                    )
                            st.markdown("---")
                        except Exception:
                            st.caption(f"Analyst {i}: Failed to parse")
        else:
            st.info("AI analysis not available. Ensure at least one AI provider API key is configured.")

    # === Tab 3: Data ===
    with tab_data:
        col1, col2 = st.columns(2)

        with col1:
            st.subheader(f"Subdomains ({len(scan_result.subdomains)})")
            if scan_result.subdomains:
                for sub in scan_result.subdomains:
                    st.text(f"  {sub.name}  ({sub.source})")
            else:
                st.caption("None found")

            st.subheader(f"IP Addresses ({len(scan_result.ips)})")
            if scan_result.ips:
                for ip in scan_result.ips:
                    extras = []
                    if ip.geolocation and ip.geolocation.country:
                        extras.append(ip.geolocation.country)
                    if ip.asn_info:
                        extras.append(f"AS{ip.asn_info.asn}")
                    suffix = f"  [{', '.join(extras)}]" if extras else ""
                    st.text(f"  {ip.address}{suffix}")
            else:
                st.caption("None found")

        with col2:
            st.subheader(f"Open Ports ({len(scan_result.ports)})")
            if scan_result.ports:
                for port in scan_result.ports:
                    svc = f" ({port.service})" if port.service else ""
                    st.text(f"  {port.ip_address}:{port.port}/{port.protocol}{svc}")
            else:
                st.caption("None found")

            st.subheader(f"Technologies ({len(scan_result.technologies)})")
            if scan_result.technologies:
                for tech in scan_result.technologies:
                    ver = f" {tech.version}" if tech.version else ""
                    st.text(f"  {tech.name}{ver}")
            else:
                st.caption("None found")

        # WHOIS
        if scan_result.whois:
            st.subheader("WHOIS Data")
            st.json(scan_result.whois.model_dump(mode="json"), expanded=False)

        # DNS
        if scan_result.dns_records:
            st.subheader("DNS Records")
            for dns_rec in scan_result.dns_records[:10]:
                with st.expander(dns_rec.domain):
                    st.json(dns_rec.model_dump(mode="json"))

        # Errors
        if scan_result.errors:
            st.subheader("Errors")
            for err in scan_result.errors:
                st.error(err)

    # === Tab 4: Active Scan ===
    if tab_active is not None:
        with tab_active:
            st.subheader("Active Scan Results")

            # WAF Detection
            if scan_result.waf_info:
                st.markdown("### WAF Detection")
                for waf in scan_result.waf_info:
                    if waf.detected:
                        st.success(f"**{waf.host}**: {waf.waf_name} ({waf.waf_vendor or 'Unknown vendor'})")
                    else:
                        st.info(f"**{waf.host}**: No WAF detected")

            # SSL/TLS
            if scan_result.ssl_info:
                st.markdown("### SSL/TLS Analysis")
                for ssl in scan_result.ssl_info:
                    with st.expander(f"{ssl.host}:{ssl.port}"):
                        if ssl.protocol_versions:
                            st.write(f"**Protocols:** {', '.join(ssl.protocol_versions)}")
                        if ssl.has_weak_ciphers:
                            st.error("Weak ciphers detected!")
                        if ssl.vulnerabilities:
                            for v in ssl.vulnerabilities:
                                st.warning(v)
                        if ssl.certificate_subject:
                            st.write(f"**Subject:** {ssl.certificate_subject}")
                        if ssl.certificate_issuer:
                            st.write(f"**Issuer:** {ssl.certificate_issuer}")
                        if ssl.certificate_expiry:
                            st.write(f"**Expires:** {ssl.certificate_expiry}")
                        if ssl.certificate_san:
                            st.write(f"**SANs:** {', '.join(ssl.certificate_san[:10])}")

            # OS Detection
            if scan_result.os_detection:
                st.markdown("### OS Detection")
                for os_rec in scan_result.os_detection:
                    acc = f" ({os_rec.os_accuracy}% confidence)" if os_rec.os_accuracy else ""
                    st.text(f"  {os_rec.ip_address}: {os_rec.os_family or 'Unknown'}{acc}")

            # Web Directories
            if scan_result.web_directories:
                st.markdown(f"### Web Directories ({len(scan_result.web_directories)})")
                for d in scan_result.web_directories:
                    st.text(f"  [{d.status_code}] {d.url}")

            # Active DNS
            if scan_result.active_dns:
                st.markdown(f"### Active DNS Records ({len(scan_result.active_dns)})")
                for dns in scan_result.active_dns:
                    st.text(f"  {dns.record_type:6s} {dns.host} -> {dns.value}")

            if not any([
                scan_result.waf_info, scan_result.ssl_info, scan_result.os_detection,
                scan_result.web_directories, scan_result.active_dns,
            ]):
                st.info("No active scan data collected.")

    # === Tab 5: Vulnerabilities ===
    if tab_vulns is not None:
        with tab_vulns:
            vulns = scan_result.vulnerabilities
            if vulns:
                st.subheader(f"Vulnerabilities ({len(vulns)})")

                # Severity counters
                sev_counts = {}
                for v in vulns:
                    key = v.severity.value
                    sev_counts[key] = sev_counts.get(key, 0) + 1

                cols = st.columns(6)
                for i, sev in enumerate(["critical", "high", "medium", "low", "info", "unknown"]):
                    count = sev_counts.get(sev, 0)
                    cols[i].metric(sev.capitalize(), count)

                st.markdown("---")

                # Sort by severity
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
                sorted_vulns = sorted(vulns, key=lambda v: severity_order.get(v.severity.value, 5))

                for vuln in sorted_vulns:
                    icon = _severity_color(vuln.severity.value)
                    title = f"{icon} [{vuln.severity.value.upper()}] {vuln.title}"
                    with st.expander(title):
                        if vuln.vuln_id:
                            st.write(f"**ID:** `{vuln.vuln_id}`")
                        if vuln.cvss:
                            st.write(f"**CVSS:** {vuln.cvss}")
                        if vuln.affected_host:
                            port_str = f":{vuln.affected_port}" if vuln.affected_port else ""
                            st.write(f"**Host:** `{vuln.affected_host}{port_str}`")
                        if vuln.affected_url:
                            st.write(f"**URL:** `{vuln.affected_url}`")
                        if vuln.description:
                            st.write(f"**Description:** {vuln.description[:300]}")
                        if vuln.references:
                            st.write("**References:**")
                            for ref in vuln.references:
                                if ref.startswith("http"):
                                    st.markdown(f"- [{ref}]({ref})")
                                elif ref.startswith("CVE-"):
                                    st.markdown(f"- [{ref}](https://nvd.nist.gov/vuln/detail/{ref})")
                                else:
                                    st.write(f"- {ref}")
                        st.caption(f"Scanner: {vuln.scanner}")
            else:
                st.info("No vulnerabilities found by active scanners.")

    # === Tab: Export ===
    with tab_export:
        st.subheader("Export Report")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("📝 Generate Markdown", use_container_width=True):
                md = export_markdown(scan_result, analysis)
                st.download_button(
                    "Download Markdown",
                    data=md,
                    file_name=f"shadow-osint-{scan_result.target}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
                st.text_area("Preview", md, height=400)

        with col2:
            if st.button("📄 Generate PDF", use_container_width=True):
                pdf_bytes = export_pdf(scan_result, analysis)
                st.download_button(
                    "Download PDF",
                    data=pdf_bytes,
                    file_name=f"shadow-osint-{scan_result.target}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )
                st.success("PDF generated successfully!")


if __name__ == "__main__":
    main()
