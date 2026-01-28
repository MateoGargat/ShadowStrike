"""LangGraph workflow orchestration for Shadow-OSINT scans."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any, Callable, Optional

from langgraph.graph import END, StateGraph
from langgraph.types import Send

from analyzers.ai_analyst import AIAnalyst
from analyzers.graph_rag import GraphRAGExtractor
from analyzers.llm_providers import LLMProvider
from analyzers.prompts import (
    PROPOSER_DEFENSIVE_PROMPT,
    PROPOSER_OFFENSIVE_PROMPT,
    PROPOSER_PROMPT,
    build_adaptive_prompt,
)
from cache.cache_manager import CacheManager
from collectors import get_domain_collectors, get_ip_collectors
from collectors.dns_resolver import DNSCollector
from collectors.shodan_collector import ShodanCollector
from core.graph import build_graph
from core.input_parser import parse_input
from core.models import (
    AIAnalysis,
    ActiveScanConfig,
    ActiveScannerResult,
    AppConfig,
    CollectorResult,
    GraphData,
    IPRecord,
    ProposerAnalysis,
    ProposerInput,
    ScanResult,
    ScanState,
    SubdomainRecord,
    VulnerabilityRecord,
    WebDirectoryRecord,
    WAFRecord,
    SSLRecord,
    ActiveDNSRecord,
    OSDetectionRecord,
)

logger = logging.getLogger(__name__)


def _merge_subdomains(
    existing: list[dict], new_records: list[SubdomainRecord]
) -> list[dict]:
    """Merge new subdomain records, deduplicating by name."""
    seen = {d["name"] for d in existing}
    merged = list(existing)
    for rec in new_records:
        if rec.name not in seen:
            seen.add(rec.name)
            merged.append(rec.model_dump())
    return merged


def _merge_ips(existing: list[dict], new_records: list[IPRecord]) -> list[dict]:
    """Merge new IP records, deduplicating by address."""
    seen = {d["address"] for d in existing}
    merged = list(existing)
    for rec in new_records:
        if rec.address not in seen:
            seen.add(rec.address)
            merged.append(rec.model_dump())
    return merged


def _collect_results(
    state: ScanState, results: list[CollectorResult]
) -> dict[str, Any]:
    """Merge multiple collector results into state update dict."""
    subdomains = list(state.get("subdomains", []))
    ips = list(state.get("ips", []))
    ports = list(state.get("ports", []))
    technologies = list(state.get("technologies", []))
    dns_records = list(state.get("dns_records", []))
    errors = list(state.get("errors", []))
    sources = list(state.get("sources_used", []))
    whois_data = state.get("whois")

    for result in results:
        sources.append(result.source)
        if not result.success:
            if result.error:
                errors.append(f"[{result.source}] {result.error}")
            continue

        subdomains = _merge_subdomains(subdomains, result.subdomains)
        ips = _merge_ips(ips, result.ips)

        for port in result.ports:
            ports.append(port.model_dump())
        for tech in result.technologies:
            technologies.append(tech.model_dump())

        if result.dns:
            dns_records.append(result.dns.model_dump())

        if result.whois and whois_data is None:
            whois_data = result.whois.model_dump()

    return {
        "subdomains": subdomains,
        "ips": ips,
        "ports": ports,
        "technologies": technologies,
        "dns_records": dns_records,
        "whois": whois_data,
        "errors": errors,
        "sources_used": sources,
    }


# === LangGraph Node Functions ===


def parse_input_node(state: ScanState) -> dict[str, Any]:
    """Parse and validate the raw input."""
    raw = state["raw_input"]
    try:
        parsed = parse_input(raw)
        return {
            "input_type": parsed.input_type.value,
            "target": parsed.target,
            "targets": parsed.targets,
            "current_step": "parsed",
            "progress": 0.1,
        }
    except ValueError as exc:
        return {
            "errors": [str(exc)],
            "current_step": "error",
            "progress": 1.0,
        }


def route_by_input_type(state: ScanState) -> str:
    """Route to the appropriate collection node based on input type."""
    if state.get("current_step") == "error":
        return "end"
    input_type = state.get("input_type", "")
    if input_type == "domain":
        return "collect_domain"
    elif input_type == "ip":
        return "collect_ip"
    elif input_type == "cidr":
        return "collect_cidr"
    return "end"


class WorkflowRunner:
    """Builds and executes the LangGraph OSINT workflow."""

    def __init__(
        self,
        config: AppConfig,
        cache: Optional[CacheManager] = None,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ):
        self.config = config
        self.cache = cache
        self.progress_callback = progress_callback
        self.llm_provider = LLMProvider(config)
        self._graph = self._build_graph()

    def _notify(self, step: str, progress: float) -> None:
        if self.progress_callback:
            self.progress_callback(step, progress)

    def _build_graph(self) -> StateGraph:
        """Build the LangGraph state graph with MoA sub-graph."""
        graph = StateGraph(ScanState)

        # Add nodes
        graph.add_node("parse_input", parse_input_node)
        graph.add_node("collect_domain", self._collect_domain_node)
        graph.add_node("collect_ip", self._collect_ip_node)
        graph.add_node("collect_cidr", self._collect_cidr_node)
        graph.add_node("enrich", self._enrich_node)
        graph.add_node("active_scan", self._active_scan_node)
        graph.add_node("build_graph", self._build_graph_node)

        # MoA sub-graph nodes
        graph.add_node("extract_graph_context", self._extract_graph_context_node)
        graph.add_node("propose", self._propose_node)
        graph.add_node("aggregate", self._aggregate_node)
        graph.add_node("reflect", self._reflect_node)

        # Set entry point
        graph.set_entry_point("parse_input")

        # Conditional routing after parse
        graph.add_conditional_edges(
            "parse_input",
            route_by_input_type,
            {
                "collect_domain": "collect_domain",
                "collect_ip": "collect_ip",
                "collect_cidr": "collect_cidr",
                "end": END,
            },
        )

        # Linear flow after collection
        graph.add_edge("collect_domain", "enrich")
        graph.add_edge("collect_ip", "enrich")
        graph.add_edge("collect_cidr", "enrich")

        # Conditional routing after enrich: active scan or straight to graph
        graph.add_conditional_edges(
            "enrich",
            self._route_after_enrich,
            {
                "active_scan": "active_scan",
                "build_graph": "build_graph",
            },
        )

        graph.add_edge("active_scan", "build_graph")

        # MoA flow: build_graph → extract_graph_context → [Send proposers] → aggregate → [reflect] → END
        graph.add_edge("build_graph", "extract_graph_context")
        graph.add_conditional_edges(
            "extract_graph_context",
            self._fan_out_to_proposers,
            ["propose"],
        )
        graph.add_edge("propose", "aggregate")
        graph.add_conditional_edges(
            "aggregate",
            self._should_reflect,
            {
                "reflect": "reflect",
                "end": END,
            },
        )
        graph.add_edge("reflect", END)

        return graph

    @staticmethod
    def _route_after_enrich(state: ScanState) -> str:
        """Route to active_scan if enabled, otherwise to build_graph."""
        if state.get("active_scan_enabled"):
            return "active_scan"
        return "build_graph"

    def _collect_domain_node(self, state: ScanState) -> dict[str, Any]:
        """Collect data for a domain target."""
        self._notify("Collecting domain data...", 0.2)
        target = state["target"]
        collectors = get_domain_collectors(self.config, self.cache)

        # Run all collectors concurrently
        results = asyncio.get_event_loop().run_until_complete(
            self._run_collectors(collectors, target)
        )

        update = _collect_results(state, results)
        update["current_step"] = "collected"
        update["progress"] = 0.4
        return update

    def _collect_ip_node(self, state: ScanState) -> dict[str, Any]:
        """Collect data for an IP target."""
        self._notify("Collecting IP data...", 0.2)
        target = state["target"]
        collectors = get_ip_collectors(self.config, self.cache)

        results = asyncio.get_event_loop().run_until_complete(
            self._run_collectors(collectors, target)
        )

        update = _collect_results(state, results)
        update["current_step"] = "collected"
        update["progress"] = 0.4
        return update

    def _collect_cidr_node(self, state: ScanState) -> dict[str, Any]:
        """Collect data for a CIDR range (scan each IP)."""
        self._notify("Collecting CIDR data...", 0.2)
        targets = state.get("targets", [])
        all_results: list[CollectorResult] = []

        # Create Shodan collector for each IP
        shodan = ShodanCollector(self.config, self.cache)
        tasks = [shodan.safe_collect(ip) for ip in targets]

        results = asyncio.get_event_loop().run_until_complete(
            asyncio.gather(*tasks, return_exceptions=True)
        )

        for r in results:
            if isinstance(r, CollectorResult):
                all_results.append(r)

        update = _collect_results(state, all_results)
        update["current_step"] = "collected"
        update["progress"] = 0.4
        return update

    def _enrich_node(self, state: ScanState) -> dict[str, Any]:
        """Enrich collected data: resolve subdomain DNS, fetch IP details."""
        self._notify("Enriching data...", 0.5)

        subdomains = [SubdomainRecord(**d) for d in state.get("subdomains", [])]
        ips = list(state.get("ips", []))
        dns_records = list(state.get("dns_records", []))
        errors = list(state.get("errors", []))

        # Resolve subdomains DNS
        if subdomains:
            try:
                dns_collector = DNSCollector(self.config, self.cache)
                new_dns, new_ips = asyncio.get_event_loop().run_until_complete(
                    dns_collector.resolve_subdomains(subdomains)
                )
                for d in new_dns:
                    dns_records.append(d.model_dump())
                ips = _merge_ips(ips, new_ips)
            except Exception as exc:
                errors.append(f"[enrich/dns] {exc}")

        # Enrich IPs with Shodan InternetDB
        ip_addresses = [ip["address"] if isinstance(ip, dict) else ip.address for ip in ips]
        unique_ips = list(set(ip_addresses))[:20]  # Limit to 20

        if unique_ips:
            try:
                shodan = ShodanCollector(self.config, self.cache)
                tasks = [shodan.safe_collect(ip) for ip in unique_ips]
                results = asyncio.get_event_loop().run_until_complete(
                    asyncio.gather(*tasks, return_exceptions=True)
                )
                ports = list(state.get("ports", []))
                technologies = list(state.get("technologies", []))
                for r in results:
                    if isinstance(r, CollectorResult) and r.success:
                        for p in r.ports:
                            ports.append(p.model_dump())
                        for t in r.technologies:
                            technologies.append(t.model_dump())
                return {
                    "ips": ips,
                    "dns_records": dns_records,
                    "ports": ports,
                    "technologies": technologies,
                    "errors": errors,
                    "current_step": "enriched",
                    "progress": 0.6,
                }
            except Exception as exc:
                errors.append(f"[enrich/shodan] {exc}")

        return {
            "ips": ips,
            "dns_records": dns_records,
            "errors": errors,
            "current_step": "enriched",
            "progress": 0.6,
        }

    def _active_scan_node(self, state: ScanState) -> dict[str, Any]:
        """Run active scanning tools in two phases."""
        self._notify("Running active scans...", 0.6)

        from scanners import (
            PHASE_1_SCANNERS,
            PHASE_2_SCANNERS,
            get_scanner,
        )
        from scanners.tool_detector import detect_all_tools

        active_config = self.config.active_scan

        # Detect installed tools
        custom_paths = {}
        for name in ("nmap", "gobuster", "nikto", "nuclei", "whatweb",
                      "wafw00f", "sslscan", "dnsrecon", "ffuf", "wpscan"):
            path_val = getattr(active_config, f"{name}_path", None)
            if path_val:
                custom_paths[name] = path_val
        installed_tools = detect_all_tools(custom_paths)
        installed_names = {t.name for t in installed_tools if t.installed}

        # Determine which scanners to run
        selected = active_config.selected_scanners
        if not selected:
            selected = [n for n in (PHASE_1_SCANNERS + PHASE_2_SCANNERS) if n != "ffuf"]

        # Filter to installed only
        selected = [s for s in selected if s in installed_names]

        if not selected:
            return {
                "errors": list(state.get("errors", [])) + [
                    "[active_scan] No active scanning tools found installed"
                ],
                "installed_tools": [t.model_dump() for t in installed_tools],
                "current_step": "active_scan_done",
                "progress": 0.85,
            }

        # Build context from passive results
        context = self._build_active_context(state)

        # Run scans in two phases
        all_results = asyncio.get_event_loop().run_until_complete(
            self._run_active_scanners(active_config, selected, state["target"], context)
        )

        # Merge results
        return self._merge_active_results(state, all_results, installed_tools)

    def _build_active_context(self, state: ScanState) -> dict:
        """Build context dict from passive scan results for active scanners."""
        target = state.get("target", "")
        ports = state.get("ports", [])
        ips = state.get("ips", [])
        technologies = state.get("technologies", [])

        # Determine HTTP/HTTPS targets
        http_targets = []
        https_targets = []
        all_open_ports = set()

        for p in ports:
            port_num = p.get("port", 0) if isinstance(p, dict) else p.port
            ip_addr = p.get("ip_address", "") if isinstance(p, dict) else p.ip_address
            service = (p.get("service", "") if isinstance(p, dict) else p.service) or ""
            all_open_ports.add(port_num)

            if port_num == 443 or "https" in service.lower() or "ssl" in service.lower():
                https_targets.append(f"https://{ip_addr}:{port_num}")
            elif port_num in (80, 8080, 8443, 8000) or "http" in service.lower():
                http_targets.append(f"http://{ip_addr}:{port_num}")

        # If no ports found, use target directly
        if not http_targets and not https_targets:
            http_targets = [f"http://{target}"]
            https_targets = [f"https://{target}"]

        ip_addresses = [
            (ip.get("address", "") if isinstance(ip, dict) else ip.address)
            for ip in ips
        ]

        tech_names = [
            (t.get("name", "") if isinstance(t, dict) else t.name)
            for t in technologies
        ]

        return {
            "target": target,
            "http_targets": http_targets,
            "https_targets": https_targets,
            "all_open_ports": list(all_open_ports),
            "ip_addresses": ip_addresses,
            "technologies": tech_names,
        }

    async def _run_active_scanners(
        self,
        config: ActiveScanConfig,
        selected: list[str],
        target: str,
        context: dict,
    ) -> list[ActiveScannerResult]:
        """Run active scanners in two phases with concurrency control."""
        from scanners import PHASE_1_SCANNERS, PHASE_2_SCANNERS, get_scanner

        semaphore = asyncio.Semaphore(config.max_concurrent_scanners)
        all_results: list[ActiveScannerResult] = []

        async def _run_one(name: str, scan_target: str, ctx: dict) -> ActiveScannerResult:
            async with semaphore:
                scanner = get_scanner(name, config)
                return await scanner.scan(scan_target, ctx)

        # Phase 1
        phase1 = [s for s in selected if s in PHASE_1_SCANNERS]
        if phase1:
            self._notify("Active scan Phase 1...", 0.62)
            phase1_tasks = []
            for name in phase1:
                phase1_tasks.append(_run_one(name, target, context))
            phase1_results = await asyncio.gather(*phase1_tasks, return_exceptions=True)

            for r in phase1_results:
                if isinstance(r, ActiveScannerResult):
                    all_results.append(r)
                    # Enrich context with Phase 1 results
                    if r.scanner_name == "nmap" and r.success:
                        for p in r.ports:
                            port_num = p.port
                            ip = p.ip_address
                            svc = p.service or ""
                            if port_num == 443 or "ssl" in svc.lower() or "https" in svc.lower():
                                context.setdefault("https_targets", []).append(
                                    f"https://{ip}:{port_num}"
                                )
                            elif port_num in (80, 8080, 8000) or "http" in svc.lower():
                                context.setdefault("http_targets", []).append(
                                    f"http://{ip}:{port_num}"
                                )
                            context.setdefault("all_open_ports", []).append(port_num)

        # Phase 2
        phase2 = [s for s in selected if s in PHASE_2_SCANNERS]
        if phase2:
            self._notify("Active scan Phase 2...", 0.72)

            # Determine appropriate targets for Phase 2 scanners
            http_target = context.get("http_targets", [f"http://{target}"])[0]
            https_target = context.get("https_targets", [f"https://{target}"])[0]
            tech_names = [t.lower() for t in context.get("technologies", [])]

            phase2_tasks = []
            for name in phase2:
                if name == "sslscan":
                    scan_target = https_target.replace("https://", "").rstrip("/")
                    phase2_tasks.append(_run_one(name, scan_target, context))
                elif name == "wpscan":
                    # Only run if WordPress detected
                    if any("wordpress" in t for t in tech_names):
                        phase2_tasks.append(_run_one(name, http_target, context))
                    else:
                        logger.info("[wpscan] Skipped: WordPress not detected")
                else:
                    phase2_tasks.append(_run_one(name, http_target, context))

            if phase2_tasks:
                phase2_results = await asyncio.gather(*phase2_tasks, return_exceptions=True)
                for r in phase2_results:
                    if isinstance(r, ActiveScannerResult):
                        all_results.append(r)

        return all_results

    def _merge_active_results(
        self,
        state: ScanState,
        results: list[ActiveScannerResult],
        installed_tools: list,
    ) -> dict[str, Any]:
        """Merge active scanner results into state update dict."""
        ports = list(state.get("ports", []))
        technologies = list(state.get("technologies", []))
        errors = list(state.get("errors", []))
        vulnerabilities: list[dict] = list(state.get("vulnerabilities", []))
        web_directories: list[dict] = list(state.get("web_directories", []))
        waf_info: list[dict] = list(state.get("waf_info", []))
        ssl_info: list[dict] = list(state.get("ssl_info", []))
        active_dns: list[dict] = list(state.get("active_dns", []))
        os_detection: list[dict] = list(state.get("os_detection", []))
        scan_results: list[dict] = []

        for result in results:
            scan_results.append(result.model_dump())

            if not result.success:
                if result.error:
                    errors.append(f"[{result.scanner_name}] {result.error}")
                continue

            for p in result.ports:
                ports.append(p.model_dump())
            for t in result.technologies:
                technologies.append(t.model_dump())
            for v in result.vulnerabilities:
                vulnerabilities.append(v.model_dump())
            for d in result.web_directories:
                web_directories.append(d.model_dump())
            for w in result.waf_records:
                waf_info.append(w.model_dump())
            for s in result.ssl_records:
                ssl_info.append(s.model_dump())
            for dns in result.active_dns_records:
                active_dns.append(dns.model_dump())
            for os_rec in result.os_detections:
                os_detection.append(os_rec.model_dump())

        return {
            "ports": ports,
            "technologies": technologies,
            "errors": errors,
            "vulnerabilities": vulnerabilities,
            "web_directories": web_directories,
            "waf_info": waf_info,
            "ssl_info": ssl_info,
            "active_dns": active_dns,
            "os_detection": os_detection,
            "active_scan_results": scan_results,
            "installed_tools": [t.model_dump() for t in installed_tools],
            "current_step": "active_scan_done",
            "progress": 0.85,
        }

    def _build_graph_node(self, state: ScanState) -> dict[str, Any]:
        """Build the knowledge graph from collected data."""
        self._notify("Building graph...", 0.87)

        scan_result = self._state_to_scan_result(state)
        graph_data = build_graph(scan_result)

        return {
            "graph_data": graph_data.model_dump(),
            "current_step": "graph_built",
            "progress": 0.8,
        }

    # === MoA Sub-graph Nodes ===

    def _extract_graph_context_node(self, state: ScanState) -> dict[str, Any]:
        """Extract GraphRAG context from the knowledge graph."""
        self._notify("Extracting graph context...", 0.85)

        graph_data_dict = state.get("graph_data", {})
        graph_context = ""

        if graph_data_dict and graph_data_dict.get("nodes"):
            try:
                graph_data = GraphData(**graph_data_dict)
                extractor = GraphRAGExtractor()
                graph_context = extractor.extract_context(graph_data)
            except Exception as exc:
                logger.error("GraphRAG extraction failed: %s", exc)

        # Build the full OSINT context
        scan_result = self._state_to_scan_result(state)
        analyst = AIAnalyst(self.config)
        osint_context = analyst._build_context(scan_result)

        # Combine OSINT + GraphRAG context
        full_context = osint_context
        if graph_context:
            full_context = f"{osint_context}\n\n{graph_context}"

        return {
            "graph_context": full_context,
            "current_step": "graph_context_extracted",
            "progress": 0.87,
        }

    def _fan_out_to_proposers(self, state: ScanState) -> list[Send]:
        """Determine which proposers to launch based on available providers."""
        available = self.llm_provider.get_available_providers()
        context = state.get("graph_context", "")
        sends: list[Send] = []

        if not available:
            # No providers available at all — produce empty analysis
            return [Send("propose", ProposerInput(
                provider="groq",
                model=self.config.llm_model,
                system_prompt=PROPOSER_PROMPT,
                context=context,
            ).model_dump())]

        # Build adaptive prompt section
        scan_result = self._state_to_scan_result(state)
        adaptive = build_adaptive_prompt(scan_result)

        if len(available) >= 2:
            # Multi-provider: one proposer per configured provider that is available
            proposer_configs = self.config.moa_config.proposers
            for prop_cfg in proposer_configs:
                if prop_cfg["provider"] in available:
                    prompt = PROPOSER_PROMPT
                    if adaptive:
                        prompt += adaptive
                    sends.append(Send("propose", ProposerInput(
                        provider=prop_cfg["provider"],
                        model=prop_cfg["model"],
                        system_prompt=prompt,
                        context=context,
                    ).model_dump()))

            # If configured proposers didn't cover all available providers, add them
            covered = {p["provider"] for p in proposer_configs}
            for provider in available:
                if provider not in covered:
                    prompt = PROPOSER_PROMPT
                    if adaptive:
                        prompt += adaptive
                    model = self._default_model_for_provider(provider)
                    sends.append(Send("propose", ProposerInput(
                        provider=provider,
                        model=model,
                        system_prompt=prompt,
                        context=context,
                    ).model_dump()))
        else:
            # Mono-provider fallback: 2 calls with different perspectives
            provider = available[0]
            model = self.config.llm_model
            if provider != "groq":
                model = self._default_model_for_provider(provider)

            offensive_prompt = PROPOSER_OFFENSIVE_PROMPT
            defensive_prompt = PROPOSER_DEFENSIVE_PROMPT
            if adaptive:
                offensive_prompt += adaptive
                defensive_prompt += adaptive

            sends.append(Send("propose", ProposerInput(
                provider=provider,
                model=model,
                system_prompt=offensive_prompt,
                context=context,
            ).model_dump()))
            sends.append(Send("propose", ProposerInput(
                provider=provider,
                model=model,
                system_prompt=defensive_prompt,
                context=context,
            ).model_dump()))

        return sends

    def _propose_node(self, state: ScanState) -> dict[str, Any]:
        """Run a single proposer (mapped node, called once per Send)."""
        # State here contains the ProposerInput fields merged in
        provider = state.get("provider", "groq")
        model = state.get("model", self.config.llm_model)
        system_prompt = state.get("system_prompt", PROPOSER_PROMPT)
        context = state.get("context", state.get("graph_context", ""))

        self._notify(f"Proposer ({provider}/{model})...", 0.88)

        analyst = AIAnalyst(self.config)

        try:
            proposal = analyst.propose(
                provider=provider,
                model=model,
                system_prompt=system_prompt,
                context=context,
            )
            return {
                "proposer_analyses": [proposal.model_dump()],
            }
        except Exception as exc:
            logger.error("Proposer %s/%s failed: %s", provider, model, exc)
            return {
                "proposer_analyses": [{
                    "provider": provider,
                    "model": model,
                    "risk_score": 0,
                    "executive_summary": f"Analysis failed: {exc}",
                    "findings": [],
                    "recommendations": [],
                    "confidence": 0.0,
                }],
            }

    def _aggregate_node(self, state: ScanState) -> dict[str, Any]:
        """Aggregate all proposer analyses into a final assessment."""
        self._notify("Aggregating analyses...", 0.92)

        proposals_dicts = state.get("proposer_analyses", [])
        context = state.get("graph_context", "")

        if not proposals_dicts:
            return {
                "ai_analysis": AIAnalysis(
                    risk_score=0,
                    executive_summary="No proposer analyses available.",
                    attack_surface_size="Unknown",
                    findings=[],
                    exposed_services_summary="N/A",
                    recommendations=["Verify API key configuration."],
                ).model_dump(),
                "current_step": "analyzed",
                "progress": 0.95,
            }

        # Reconstruct ProposerAnalysis objects
        proposals = []
        for pd in proposals_dicts:
            try:
                proposals.append(ProposerAnalysis(**pd))
            except Exception as exc:
                logger.warning("Failed to parse proposer analysis: %s", exc)

        if not proposals:
            return {
                "ai_analysis": AIAnalysis(
                    risk_score=0,
                    executive_summary="All proposer analyses failed to parse.",
                    attack_surface_size="Unknown",
                    findings=[],
                    exposed_services_summary="N/A",
                    recommendations=["Check API key configuration and retry."],
                ).model_dump(),
                "current_step": "analyzed",
                "progress": 0.95,
            }

        # If only one successful proposal, skip aggregation and convert directly
        valid_proposals = [p for p in proposals if p.confidence > 0]
        if len(valid_proposals) <= 1:
            p = valid_proposals[0] if valid_proposals else proposals[0]
            analysis = AIAnalysis(
                risk_score=p.risk_score,
                executive_summary=p.executive_summary,
                attack_surface_size="See findings for details",
                findings=p.findings,
                exposed_services_summary="See findings for details",
                recommendations=p.recommendations,
                confidence_score=p.confidence,
                proposer_count=len(proposals),
                consensus_level="single",
            )
            return {
                "ai_analysis": analysis.model_dump(),
                "current_step": "analyzed",
                "progress": 0.95,
            }

        # Multi-proposal aggregation
        analyst = AIAnalyst(self.config)
        try:
            analysis = analyst.aggregate(proposals, context)
            # Determine consensus level
            scores = [p.risk_score for p in valid_proposals]
            score_spread = max(scores) - min(scores) if scores else 0
            if score_spread <= 15:
                analysis.consensus_level = "high"
            elif score_spread <= 30:
                analysis.consensus_level = "medium"
            else:
                analysis.consensus_level = "low"

            return {
                "ai_analysis": analysis.model_dump(),
                "current_step": "analyzed",
                "progress": 0.95,
            }
        except Exception as exc:
            logger.error("Aggregation failed: %s", exc)
            # Fall back to best single proposal
            best = max(valid_proposals, key=lambda p: p.confidence) if valid_proposals else proposals[0]
            analysis = AIAnalysis(
                risk_score=best.risk_score,
                executive_summary=f"{best.executive_summary} (aggregation failed: {exc})",
                attack_surface_size="See findings for details",
                findings=best.findings,
                exposed_services_summary="See findings for details",
                recommendations=best.recommendations,
                confidence_score=best.confidence,
                proposer_count=len(proposals),
                consensus_level="single",
            )
            return {
                "ai_analysis": analysis.model_dump(),
                "current_step": "analyzed",
                "progress": 0.95,
            }

    def _should_reflect(self, state: ScanState) -> str:
        """Determine if reflection should be performed."""
        if not self.config.moa_config.enable_reflection:
            return "end"

        ai_data = state.get("ai_analysis", {})
        if not ai_data or ai_data.get("analysis_version", 1) > self.config.moa_config.max_reflection_iterations:
            return "end"

        # Only reflect if we have at least one valid provider
        available = self.llm_provider.get_available_providers()
        if not available:
            return "end"

        return "reflect"

    def _reflect_node(self, state: ScanState) -> dict[str, Any]:
        """Run reflection on the aggregated analysis."""
        self._notify("Reflecting on analysis...", 0.96)

        ai_data = state.get("ai_analysis", {})
        context = state.get("graph_context", "")

        if not ai_data:
            return {"current_step": "reflected", "progress": 1.0}

        try:
            analysis = AIAnalysis(**ai_data)
            analyst = AIAnalyst(self.config)
            improved = analyst.reflect(analysis, context)
            return {
                "ai_analysis": improved.model_dump(),
                "current_step": "reflected",
                "progress": 1.0,
            }
        except Exception as exc:
            logger.error("Reflection failed: %s", exc)
            return {
                "current_step": "reflected",
                "progress": 1.0,
            }

    def _default_model_for_provider(self, provider: str) -> str:
        """Return the default model for a given provider."""
        defaults = {
            "groq": "llama-3.3-70b-versatile",
            "openai": "gpt-4o-mini",
            "anthropic": "claude-3-5-haiku-20241022",
        }
        return defaults.get(provider, "llama-3.3-70b-versatile")

    def _state_to_scan_result(self, state: ScanState) -> ScanResult:
        """Convert LangGraph state to ScanResult model."""
        from core.models import (
            ActiveDNSRecord,
            DNSRecords,
            IPRecord,
            InputType,
            OSDetectionRecord,
            PortRecord,
            SSLRecord,
            SubdomainRecord,
            TechnologyRecord,
            WAFRecord,
            WebDirectoryRecord,
            WhoisRecord,
            VulnerabilityRecord,
        )

        return ScanResult(
            target=state.get("target", ""),
            input_type=InputType(state.get("input_type", "domain")),
            subdomains=[SubdomainRecord(**d) for d in state.get("subdomains", [])],
            ips=[IPRecord(**d) for d in state.get("ips", [])],
            ports=[PortRecord(**d) for d in state.get("ports", [])],
            technologies=[TechnologyRecord(**d) for d in state.get("technologies", [])],
            whois=WhoisRecord(**state["whois"]) if state.get("whois") else None,
            dns_records=[DNSRecords(**d) for d in state.get("dns_records", [])],
            errors=state.get("errors", []),
            sources_used=state.get("sources_used", []),
            vulnerabilities=[VulnerabilityRecord(**v) for v in state.get("vulnerabilities", [])],
            web_directories=[WebDirectoryRecord(**d) for d in state.get("web_directories", [])],
            waf_info=[WAFRecord(**w) for w in state.get("waf_info", [])],
            ssl_info=[SSLRecord(**s) for s in state.get("ssl_info", [])],
            active_dns=[ActiveDNSRecord(**a) for a in state.get("active_dns", [])],
            os_detection=[OSDetectionRecord(**o) for o in state.get("os_detection", [])],
            active_scan_performed=bool(state.get("active_scan_enabled")),
        )

    async def _run_collectors(
        self, collectors: list, target: str
    ) -> list[CollectorResult]:
        """Run multiple collectors concurrently."""
        tasks = [c.safe_collect(target) for c in collectors]
        return await asyncio.gather(*tasks)

    def compile(self):
        """Compile the LangGraph graph."""
        return self._graph.compile()

    def run(self, raw_input: str) -> ScanState:
        """Execute the full workflow synchronously.

        Args:
            raw_input: User input (domain, IP, or CIDR).

        Returns:
            Final ScanState with all results.
        """
        app = self.compile()
        initial_state: ScanState = {
            "raw_input": raw_input,
            "input_type": "",
            "target": "",
            "targets": [],
            "subdomains": [],
            "ips": [],
            "ports": [],
            "technologies": [],
            "whois": None,
            "dns_records": [],
            "graph_data": {},
            "ai_analysis": {},
            "errors": [],
            "sources_used": [],
            "current_step": "init",
            "progress": 0.0,
            "active_scan_enabled": self.config.active_scan.enabled,
            "active_scan_results": [],
            "vulnerabilities": [],
            "web_directories": [],
            "waf_info": [],
            "ssl_info": [],
            "active_dns": [],
            "os_detection": [],
            "installed_tools": [],
            "proposer_analyses": [],
            "graph_context": "",
        }

        result = app.invoke(initial_state)
        self._notify("Complete", 1.0)
        return result

    def get_scan_result(self, state: ScanState) -> ScanResult:
        """Convert final state to ScanResult for export/display."""
        return self._state_to_scan_result(state)

    def get_analysis(self, state: ScanState) -> Optional[AIAnalysis]:
        """Extract AIAnalysis from state."""
        ai_data = state.get("ai_analysis")
        if ai_data and isinstance(ai_data, dict) and ai_data.get("executive_summary"):
            return AIAnalysis(**ai_data)
        return None
