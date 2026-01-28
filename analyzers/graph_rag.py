"""GraphRAG context extraction from the NetworkX knowledge graph."""

from __future__ import annotations

import logging
from collections import defaultdict

import networkx as nx

from core.graph import to_networkx
from core.models import GraphData

logger = logging.getLogger(__name__)


class GraphRAGExtractor:
    """Extracts structured context from the NetworkX knowledge graph for LLM analysis."""

    def extract_context(self, graph_data: GraphData) -> str:
        """Produce a structured summary of graph relationships for LLM consumption.

        Args:
            graph_data: The knowledge graph built from scan results.

        Returns:
            A formatted string with graph-derived insights.
        """
        if not graph_data.nodes:
            return ""

        G = to_networkx(graph_data)
        sections: list[str] = []

        sections.append("# Knowledge Graph Context")

        # 1. Graph statistics
        stats = self._graph_stats(G)
        sections.append(stats)

        # 2. Hub nodes (high degree = concentration of risk)
        hubs = self.find_hub_nodes(G, top_n=5)
        if hubs:
            sections.append("\n## High-Connectivity Nodes (Hubs)")
            for hub in hubs:
                sections.append(
                    f"- {hub['label']} (type={hub['node_type']}, "
                    f"connections={hub['degree']})"
                )

        # 3. Attack paths
        paths = self.find_attack_paths(G)
        if paths:
            sections.append(f"\n## Attack Paths ({len(paths)} found)")
            for path in paths[:10]:
                sections.append(f"- {' -> '.join(path)}")

        # 4. Communities / clusters
        communities = self.find_communities(G)
        if communities:
            sections.append(f"\n## Asset Clusters ({len(communities)} groups)")
            for i, community in enumerate(communities[:5], 1):
                members = ", ".join(community[:8])
                extra = f" (+{len(community) - 8} more)" if len(community) > 8 else ""
                sections.append(f"- Cluster {i}: {members}{extra}")

        # 5. Orphan subdomains (no IP resolution)
        orphans = self._find_orphan_subdomains(G)
        if orphans:
            sections.append(f"\n## Orphan Subdomains ({len(orphans)} - no IP resolution)")
            for orphan in orphans[:15]:
                sections.append(f"- {orphan}")

        # 6. Shared technologies
        shared_tech = self._find_shared_technologies(G)
        if shared_tech:
            sections.append("\n## Shared Technologies (common attack surface)")
            for tech_name, hosts in shared_tech.items():
                sections.append(f"- {tech_name}: used by {', '.join(hosts)}")

        # 7. ASN distribution
        asn_dist = self._asn_distribution(G)
        if asn_dist:
            sections.append("\n## ASN Distribution")
            for asn_label, ip_count in asn_dist:
                sections.append(f"- {asn_label}: {ip_count} IPs")

        return "\n".join(sections)

    def find_attack_paths(self, G: nx.DiGraph) -> list[list[str]]:
        """Find shortest paths from domain nodes to port/vulnerability nodes."""
        paths: list[list[str]] = []

        domain_nodes = [
            n for n, d in G.nodes(data=True) if d.get("node_type") == "domain"
        ]
        target_types = {"port", "vulnerability"}
        target_nodes = [
            n for n, d in G.nodes(data=True)
            if d.get("node_type") in target_types
        ]

        undirected = G.to_undirected()

        for domain in domain_nodes:
            for target in target_nodes:
                try:
                    path = nx.shortest_path(undirected, domain, target)
                    labels = [G.nodes[n].get("label", n) for n in path]
                    paths.append(labels)
                except nx.NetworkXNoPath:
                    continue

        # Sort by path length (shorter = more direct = higher risk)
        paths.sort(key=len)
        return paths

    def find_hub_nodes(self, G: nx.DiGraph, top_n: int = 5) -> list[dict]:
        """Identify nodes with the most connections (risk concentration points)."""
        if not G.nodes:
            return []

        undirected = G.to_undirected()
        degree_list = sorted(undirected.degree(), key=lambda x: x[1], reverse=True)

        hubs = []
        for node_id, degree in degree_list[:top_n]:
            data = G.nodes[node_id]
            hubs.append({
                "id": node_id,
                "label": data.get("label", node_id),
                "node_type": data.get("node_type", "unknown"),
                "degree": degree,
            })
        return hubs

    def find_communities(self, G: nx.DiGraph) -> list[list[str]]:
        """Detect communities (groups of related assets) using connected components."""
        if not G.nodes:
            return []

        undirected = G.to_undirected()
        components = list(nx.connected_components(undirected))

        communities = []
        for component in sorted(components, key=len, reverse=True):
            if len(component) < 2:
                continue
            labels = [G.nodes[n].get("label", n) for n in component]
            communities.append(labels)

        return communities

    def _graph_stats(self, G: nx.DiGraph) -> str:
        """Generate basic graph statistics."""
        type_counts: dict[str, int] = defaultdict(int)
        for _, data in G.nodes(data=True):
            type_counts[data.get("node_type", "unknown")] += 1

        edge_counts: dict[str, int] = defaultdict(int)
        for _, _, data in G.edges(data=True):
            edge_counts[data.get("relation", "unknown")] += 1

        lines = [
            f"\n## Graph Statistics",
            f"- Total nodes: {G.number_of_nodes()}",
            f"- Total edges: {G.number_of_edges()}",
        ]
        for ntype, count in sorted(type_counts.items()):
            lines.append(f"- {ntype}: {count}")
        for rtype, count in sorted(edge_counts.items()):
            lines.append(f"- {rtype} edges: {count}")

        return "\n".join(lines)

    def _find_orphan_subdomains(self, G: nx.DiGraph) -> list[str]:
        """Find subdomains that don't resolve to any IP."""
        orphans = []
        for node_id, data in G.nodes(data=True):
            if data.get("node_type") != "subdomain":
                continue
            # Check if any neighbor is an IP
            has_ip = False
            for neighbor in G.successors(node_id):
                if G.nodes[neighbor].get("node_type") == "ip":
                    has_ip = True
                    break
            if not has_ip:
                # Also check predecessors (undirected edges)
                for neighbor in G.predecessors(node_id):
                    if G.nodes[neighbor].get("node_type") == "ip":
                        has_ip = True
                        break
            if not has_ip:
                orphans.append(data.get("label", node_id))
        return orphans

    def _find_shared_technologies(self, G: nx.DiGraph) -> dict[str, list[str]]:
        """Find technologies shared across multiple IPs/ports."""
        tech_hosts: dict[str, set[str]] = defaultdict(set)

        for node_id, data in G.nodes(data=True):
            if data.get("node_type") != "technology":
                continue
            tech_label = data.get("label", node_id)
            # Find which IPs/ports use this technology
            for pred in G.predecessors(node_id):
                pred_data = G.nodes[pred]
                if pred_data.get("node_type") in ("ip", "port"):
                    tech_hosts[tech_label].add(pred_data.get("label", pred))

        # Only return technologies used by 2+ hosts
        return {
            tech: sorted(hosts)
            for tech, hosts in tech_hosts.items()
            if len(hosts) >= 2
        }

    def _asn_distribution(self, G: nx.DiGraph) -> list[tuple[str, int]]:
        """Count IPs per ASN."""
        asn_ips: dict[str, int] = defaultdict(int)

        for node_id, data in G.nodes(data=True):
            if data.get("node_type") != "asn":
                continue
            asn_label = data.get("label", node_id)
            ip_count = sum(
                1 for pred in G.predecessors(node_id)
                if G.nodes[pred].get("node_type") == "ip"
            )
            if ip_count > 0:
                asn_ips[asn_label] = ip_count

        return sorted(asn_ips.items(), key=lambda x: x[1], reverse=True)
