"""OSINT Knowledge Graph construction from scan results."""

from __future__ import annotations

from typing import Any

import networkx as nx

from core.models import (
    GraphData,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
    ScanResult,
    VulnerabilityRecord,
    WebDirectoryRecord,
    WAFRecord,
    SSLRecord,
)


def _make_node_id(node_type: NodeType, value: str) -> str:
    """Create a deterministic node ID."""
    return f"{node_type.value}:{value}"


def build_graph(scan: ScanResult) -> GraphData:
    """Build a graph from scan results.

    Creates nodes for domains, subdomains, IPs, ports, technologies, and ASNs,
    and connects them with typed relationships.
    """
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    # Root domain node
    root_id = _make_node_id(NodeType.DOMAIN, scan.target)
    nodes[root_id] = GraphNode(
        id=root_id,
        label=scan.target,
        node_type=NodeType.DOMAIN,
        properties={"is_root": True},
    )

    # Subdomains
    for sub in scan.subdomains:
        sub_id = _make_node_id(NodeType.SUBDOMAIN, sub.name)
        if sub_id not in nodes:
            nodes[sub_id] = GraphNode(
                id=sub_id,
                label=sub.name,
                node_type=NodeType.SUBDOMAIN,
                properties={"source": sub.source},
            )
            edges.append(
                GraphEdge(
                    source=root_id,
                    target=sub_id,
                    relation=RelationType.HAS_SUBDOMAIN,
                )
            )

    # IPs
    for ip_rec in scan.ips:
        ip_id = _make_node_id(NodeType.IP, ip_rec.address)
        if ip_id not in nodes:
            props: dict[str, Any] = {"version": ip_rec.version}
            if ip_rec.geolocation:
                props["country"] = ip_rec.geolocation.country
                props["city"] = ip_rec.geolocation.city
            nodes[ip_id] = GraphNode(
                id=ip_id,
                label=ip_rec.address,
                node_type=NodeType.IP,
                properties=props,
            )

        # Link IPs to root domain
        edges.append(
            GraphEdge(
                source=root_id,
                target=ip_id,
                relation=RelationType.RESOLVES_TO,
            )
        )

        # Link hostnames to this IP
        for hostname in ip_rec.hostnames:
            hostname_id = _make_node_id(NodeType.SUBDOMAIN, hostname)
            if hostname_id in nodes:
                edges.append(
                    GraphEdge(
                        source=hostname_id,
                        target=ip_id,
                        relation=RelationType.RESOLVES_TO,
                    )
                )

        # ASN
        if ip_rec.asn_info:
            asn_id = _make_node_id(NodeType.ASN, ip_rec.asn_info.asn)
            if asn_id not in nodes:
                nodes[asn_id] = GraphNode(
                    id=asn_id,
                    label=f"AS{ip_rec.asn_info.asn} ({ip_rec.asn_info.name or 'Unknown'})",
                    node_type=NodeType.ASN,
                    properties={
                        "name": ip_rec.asn_info.name,
                        "route": ip_rec.asn_info.route,
                    },
                )
            edges.append(
                GraphEdge(
                    source=ip_id,
                    target=asn_id,
                    relation=RelationType.BELONGS_TO_ASN,
                )
            )

    # Ports
    for port_rec in scan.ports:
        port_label = f"{port_rec.ip_address}:{port_rec.port}/{port_rec.protocol}"
        port_id = _make_node_id(NodeType.PORT, port_label)
        if port_id not in nodes:
            nodes[port_id] = GraphNode(
                id=port_id,
                label=port_label,
                node_type=NodeType.PORT,
                properties={
                    "port": port_rec.port,
                    "protocol": port_rec.protocol,
                    "service": port_rec.service,
                    "banner": port_rec.banner,
                },
            )
        ip_id = _make_node_id(NodeType.IP, port_rec.ip_address)
        if ip_id in nodes:
            edges.append(
                GraphEdge(
                    source=ip_id,
                    target=port_id,
                    relation=RelationType.HAS_PORT,
                )
            )

    # Technologies
    for tech in scan.technologies:
        tech_label = f"{tech.name}" + (f" {tech.version}" if tech.version else "")
        tech_id = _make_node_id(NodeType.TECHNOLOGY, tech_label)
        if tech_id not in nodes:
            nodes[tech_id] = GraphNode(
                id=tech_id,
                label=tech_label,
                node_type=NodeType.TECHNOLOGY,
                properties={
                    "cpe": tech.cpe,
                    "category": tech.category,
                },
            )

        # Link technology to port or IP
        if tech.ip_address and tech.port:
            port_label = f"{tech.ip_address}:{tech.port}/tcp"
            port_id = _make_node_id(NodeType.PORT, port_label)
            if port_id in nodes:
                edges.append(
                    GraphEdge(
                        source=port_id,
                        target=tech_id,
                        relation=RelationType.RUNS,
                    )
                )
        elif tech.ip_address:
            ip_id = _make_node_id(NodeType.IP, tech.ip_address)
            if ip_id in nodes:
                edges.append(
                    GraphEdge(
                        source=ip_id,
                        target=tech_id,
                        relation=RelationType.RUNS,
                    )
                )

    # DNS-based IP links
    for dns_rec in scan.dns_records:
        for a_ip in dns_rec.a:
            ip_id = _make_node_id(NodeType.IP, a_ip)
            if ip_id not in nodes:
                nodes[ip_id] = GraphNode(
                    id=ip_id,
                    label=a_ip,
                    node_type=NodeType.IP,
                    properties={"version": 4},
                )
            # Link domain to resolved IP
            dns_domain_id = _make_node_id(NodeType.SUBDOMAIN, dns_rec.domain)
            if dns_domain_id in nodes:
                edges.append(
                    GraphEdge(
                        source=dns_domain_id,
                        target=ip_id,
                        relation=RelationType.RESOLVES_TO,
                    )
                )

        for aaaa_ip in dns_rec.aaaa:
            ip_id = _make_node_id(NodeType.IP, aaaa_ip)
            if ip_id not in nodes:
                nodes[ip_id] = GraphNode(
                    id=ip_id,
                    label=aaaa_ip,
                    node_type=NodeType.IP,
                    properties={"version": 6},
                )

    # === Active Scan: Vulnerabilities ===
    for vuln in scan.vulnerabilities:
        vuln_label = vuln.vuln_id or vuln.title[:50]
        vuln_id = _make_node_id(NodeType.VULNERABILITY, vuln_label)
        if vuln_id not in nodes:
            nodes[vuln_id] = GraphNode(
                id=vuln_id,
                label=vuln_label,
                node_type=NodeType.VULNERABILITY,
                properties={
                    "title": vuln.title,
                    "severity": vuln.severity.value,
                    "scanner": vuln.scanner,
                    "cvss": vuln.cvss,
                },
            )

        # Link to affected host/port
        if vuln.affected_host and vuln.affected_port:
            port_label = f"{vuln.affected_host}:{vuln.affected_port}/tcp"
            port_id = _make_node_id(NodeType.PORT, port_label)
            if port_id in nodes:
                edges.append(GraphEdge(
                    source=port_id, target=vuln_id,
                    relation=RelationType.HAS_VULNERABILITY,
                ))
        elif vuln.affected_host:
            ip_id = _make_node_id(NodeType.IP, vuln.affected_host)
            if ip_id in nodes:
                edges.append(GraphEdge(
                    source=ip_id, target=vuln_id,
                    relation=RelationType.HAS_VULNERABILITY,
                ))

    # === Active Scan: Web Directories ===
    for web_dir in scan.web_directories:
        dir_label = web_dir.url[:80]
        dir_id = _make_node_id(NodeType.WEB_DIRECTORY, web_dir.url)
        if dir_id not in nodes:
            nodes[dir_id] = GraphNode(
                id=dir_id,
                label=dir_label,
                node_type=NodeType.WEB_DIRECTORY,
                properties={
                    "status_code": web_dir.status_code,
                    "content_length": web_dir.content_length,
                },
            )
        if web_dir.host:
            ip_id = _make_node_id(NodeType.IP, web_dir.host)
            if ip_id in nodes:
                edges.append(GraphEdge(
                    source=ip_id, target=dir_id,
                    relation=RelationType.HAS_DIRECTORY,
                ))

    # === Active Scan: WAF ===
    for waf in scan.waf_info:
        if waf.detected and waf.waf_name:
            waf_label = waf.waf_name
            waf_id = _make_node_id(NodeType.WAF, f"{waf.host}:{waf_label}")
            if waf_id not in nodes:
                nodes[waf_id] = GraphNode(
                    id=waf_id,
                    label=f"WAF: {waf_label}",
                    node_type=NodeType.WAF,
                    properties={
                        "vendor": waf.waf_vendor,
                        "confidence": waf.confidence,
                    },
                )
            # Link to root domain or IP
            edges.append(GraphEdge(
                source=root_id, target=waf_id,
                relation=RelationType.PROTECTED_BY,
            ))

    # === Active Scan: SSL Certificates ===
    for ssl in scan.ssl_info:
        ssl_label = f"SSL:{ssl.host}:{ssl.port}"
        ssl_id = _make_node_id(NodeType.SSL_CERT, ssl_label)
        if ssl_id not in nodes:
            nodes[ssl_id] = GraphNode(
                id=ssl_id,
                label=ssl_label,
                node_type=NodeType.SSL_CERT,
                properties={
                    "subject": ssl.certificate_subject,
                    "issuer": ssl.certificate_issuer,
                    "expiry": ssl.certificate_expiry,
                    "has_weak_ciphers": ssl.has_weak_ciphers,
                    "protocols": ", ".join(ssl.protocol_versions),
                },
            )
        ip_id = _make_node_id(NodeType.IP, ssl.host)
        if ip_id in nodes:
            edges.append(GraphEdge(
                source=ip_id, target=ssl_id,
                relation=RelationType.HAS_SSL_CERT,
            ))

    return GraphData(nodes=list(nodes.values()), edges=edges)


def to_networkx(graph_data: GraphData) -> nx.DiGraph:
    """Convert GraphData to a NetworkX directed graph."""
    G = nx.DiGraph()
    for node in graph_data.nodes:
        G.add_node(
            node.id,
            label=node.label,
            node_type=node.node_type.value,
            **node.properties,
        )
    for edge in graph_data.edges:
        G.add_edge(
            edge.source,
            edge.target,
            relation=edge.relation.value,
            **edge.properties,
        )
    return G


def get_graph_stats(graph_data: GraphData) -> dict[str, Any]:
    """Compute statistics about the graph."""
    type_counts: dict[str, int] = {}
    for node in graph_data.nodes:
        key = node.node_type.value
        type_counts[key] = type_counts.get(key, 0) + 1

    relation_counts: dict[str, int] = {}
    for edge in graph_data.edges:
        key = edge.relation.value
        relation_counts[key] = relation_counts.get(key, 0) + 1

    return {
        "total_nodes": len(graph_data.nodes),
        "total_edges": len(graph_data.edges),
        "nodes_by_type": type_counts,
        "edges_by_relation": relation_counts,
    }
