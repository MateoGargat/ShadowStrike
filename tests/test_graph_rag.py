"""Tests for analyzers.graph_rag module."""

import pytest
import networkx as nx

from analyzers.graph_rag import GraphRAGExtractor
from core.models import (
    GraphData,
    GraphEdge,
    GraphNode,
    NodeType,
    RelationType,
)


@pytest.fixture
def extractor():
    return GraphRAGExtractor()


@pytest.fixture
def simple_graph_data():
    """Simple graph: domain -> subdomain -> IP -> port."""
    return GraphData(
        nodes=[
            GraphNode(id="domain:example.com", label="example.com",
                      node_type=NodeType.DOMAIN, properties={"is_root": True}),
            GraphNode(id="subdomain:www.example.com", label="www.example.com",
                      node_type=NodeType.SUBDOMAIN, properties={"source": "crtsh"}),
            GraphNode(id="subdomain:api.example.com", label="api.example.com",
                      node_type=NodeType.SUBDOMAIN, properties={"source": "crtsh"}),
            GraphNode(id="ip:1.2.3.4", label="1.2.3.4",
                      node_type=NodeType.IP, properties={"version": 4}),
            GraphNode(id="port:1.2.3.4:80/tcp", label="1.2.3.4:80/tcp",
                      node_type=NodeType.PORT, properties={"port": 80}),
            GraphNode(id="port:1.2.3.4:443/tcp", label="1.2.3.4:443/tcp",
                      node_type=NodeType.PORT, properties={"port": 443}),
        ],
        edges=[
            GraphEdge(source="domain:example.com", target="subdomain:www.example.com",
                      relation=RelationType.HAS_SUBDOMAIN),
            GraphEdge(source="domain:example.com", target="subdomain:api.example.com",
                      relation=RelationType.HAS_SUBDOMAIN),
            GraphEdge(source="subdomain:www.example.com", target="ip:1.2.3.4",
                      relation=RelationType.RESOLVES_TO),
            GraphEdge(source="ip:1.2.3.4", target="port:1.2.3.4:80/tcp",
                      relation=RelationType.HAS_PORT),
            GraphEdge(source="ip:1.2.3.4", target="port:1.2.3.4:443/tcp",
                      relation=RelationType.HAS_PORT),
        ],
    )


@pytest.fixture
def complex_graph_data():
    """Graph with multiple IPs, ASN, technologies, and an orphan subdomain."""
    return GraphData(
        nodes=[
            GraphNode(id="domain:example.com", label="example.com",
                      node_type=NodeType.DOMAIN, properties={"is_root": True}),
            GraphNode(id="subdomain:www.example.com", label="www.example.com",
                      node_type=NodeType.SUBDOMAIN, properties={}),
            GraphNode(id="subdomain:orphan.example.com", label="orphan.example.com",
                      node_type=NodeType.SUBDOMAIN, properties={}),
            GraphNode(id="ip:1.2.3.4", label="1.2.3.4",
                      node_type=NodeType.IP, properties={"version": 4}),
            GraphNode(id="ip:5.6.7.8", label="5.6.7.8",
                      node_type=NodeType.IP, properties={"version": 4}),
            GraphNode(id="port:1.2.3.4:80/tcp", label="1.2.3.4:80/tcp",
                      node_type=NodeType.PORT, properties={"port": 80}),
            GraphNode(id="port:5.6.7.8:80/tcp", label="5.6.7.8:80/tcp",
                      node_type=NodeType.PORT, properties={"port": 80}),
            GraphNode(id="technology:nginx", label="nginx",
                      node_type=NodeType.TECHNOLOGY, properties={}),
            GraphNode(id="asn:AS12345", label="AS12345 (Cloudflare)",
                      node_type=NodeType.ASN, properties={"name": "Cloudflare"}),
        ],
        edges=[
            GraphEdge(source="domain:example.com", target="subdomain:www.example.com",
                      relation=RelationType.HAS_SUBDOMAIN),
            GraphEdge(source="domain:example.com", target="subdomain:orphan.example.com",
                      relation=RelationType.HAS_SUBDOMAIN),
            GraphEdge(source="subdomain:www.example.com", target="ip:1.2.3.4",
                      relation=RelationType.RESOLVES_TO),
            GraphEdge(source="domain:example.com", target="ip:5.6.7.8",
                      relation=RelationType.RESOLVES_TO),
            GraphEdge(source="ip:1.2.3.4", target="port:1.2.3.4:80/tcp",
                      relation=RelationType.HAS_PORT),
            GraphEdge(source="ip:5.6.7.8", target="port:5.6.7.8:80/tcp",
                      relation=RelationType.HAS_PORT),
            GraphEdge(source="port:1.2.3.4:80/tcp", target="technology:nginx",
                      relation=RelationType.RUNS),
            GraphEdge(source="port:5.6.7.8:80/tcp", target="technology:nginx",
                      relation=RelationType.RUNS),
            GraphEdge(source="ip:1.2.3.4", target="asn:AS12345",
                      relation=RelationType.BELONGS_TO_ASN),
            GraphEdge(source="ip:5.6.7.8", target="asn:AS12345",
                      relation=RelationType.BELONGS_TO_ASN),
        ],
    )


class TestGraphRAGExtractor:
    def test_extract_context_empty(self, extractor):
        graph_data = GraphData(nodes=[], edges=[])
        result = extractor.extract_context(graph_data)
        assert result == ""

    def test_extract_context_has_header(self, extractor, simple_graph_data):
        result = extractor.extract_context(simple_graph_data)
        assert "Knowledge Graph Context" in result

    def test_extract_context_has_stats(self, extractor, simple_graph_data):
        result = extractor.extract_context(simple_graph_data)
        assert "Graph Statistics" in result
        assert "Total nodes" in result

    def test_extract_context_has_hubs(self, extractor, simple_graph_data):
        result = extractor.extract_context(simple_graph_data)
        assert "High-Connectivity Nodes" in result

    def test_extract_context_has_attack_paths(self, extractor, simple_graph_data):
        result = extractor.extract_context(simple_graph_data)
        assert "Attack Paths" in result


class TestFindAttackPaths:
    def test_finds_paths(self, extractor, simple_graph_data):
        from core.graph import to_networkx
        G = to_networkx(simple_graph_data)
        paths = extractor.find_attack_paths(G)
        assert len(paths) > 0
        # Should find path from domain to port
        has_domain_to_port = any(
            "example.com" in path[0] and "80" in path[-1]
            for path in paths
        )
        assert has_domain_to_port

    def test_empty_graph(self, extractor):
        G = nx.DiGraph()
        paths = extractor.find_attack_paths(G)
        assert paths == []


class TestFindHubNodes:
    def test_finds_hubs(self, extractor, simple_graph_data):
        from core.graph import to_networkx
        G = to_networkx(simple_graph_data)
        hubs = extractor.find_hub_nodes(G, top_n=3)
        assert len(hubs) > 0
        # The IP node should be a hub (connected to domain, ports)
        assert any(h["node_type"] == "ip" for h in hubs)

    def test_empty_graph(self, extractor):
        G = nx.DiGraph()
        hubs = extractor.find_hub_nodes(G)
        assert hubs == []


class TestFindCommunities:
    def test_finds_communities(self, extractor, simple_graph_data):
        from core.graph import to_networkx
        G = to_networkx(simple_graph_data)
        communities = extractor.find_communities(G)
        # All nodes are connected, so should be one community
        assert len(communities) >= 1

    def test_empty_graph(self, extractor):
        G = nx.DiGraph()
        communities = extractor.find_communities(G)
        assert communities == []


class TestOrphanSubdomains:
    def test_finds_orphans(self, extractor, complex_graph_data):
        from core.graph import to_networkx
        G = to_networkx(complex_graph_data)
        orphans = extractor._find_orphan_subdomains(G)
        assert "orphan.example.com" in orphans

    def test_no_orphans(self, extractor, simple_graph_data):
        from core.graph import to_networkx
        G = to_networkx(simple_graph_data)
        orphans = extractor._find_orphan_subdomains(G)
        # www.example.com resolves to IP, but api.example.com has no IP edge
        assert "api.example.com" in orphans
        assert "www.example.com" not in orphans


class TestSharedTechnologies:
    def test_finds_shared_tech(self, extractor, complex_graph_data):
        from core.graph import to_networkx
        G = to_networkx(complex_graph_data)
        shared = extractor._find_shared_technologies(G)
        assert "nginx" in shared
        assert len(shared["nginx"]) >= 2

    def test_no_shared_tech(self, extractor, simple_graph_data):
        from core.graph import to_networkx
        G = to_networkx(simple_graph_data)
        shared = extractor._find_shared_technologies(G)
        assert shared == {}


class TestASNDistribution:
    def test_asn_distribution(self, extractor, complex_graph_data):
        from core.graph import to_networkx
        G = to_networkx(complex_graph_data)
        dist = extractor._asn_distribution(G)
        assert len(dist) >= 1
        # AS12345 should have 2 IPs
        asn_names = [name for name, _ in dist]
        assert any("AS12345" in n for n in asn_names)
