"""Tests for core.graph module."""

import pytest
from core.graph import build_graph, get_graph_stats, to_networkx, _make_node_id
from core.models import (
    InputType,
    IPRecord,
    NodeType,
    PortRecord,
    RelationType,
    ScanResult,
    SubdomainRecord,
    TechnologyRecord,
)


def _make_scan(**kwargs) -> ScanResult:
    defaults = {"target": "example.com", "input_type": InputType.DOMAIN}
    defaults.update(kwargs)
    return ScanResult(**defaults)


class TestBuildGraph:
    def test_build_empty(self):
        scan = _make_scan()
        graph = build_graph(scan)
        # Should have at least the root domain node
        assert len(graph.nodes) == 1
        assert graph.nodes[0].node_type == NodeType.DOMAIN

    def test_build_domain_with_subs(self):
        scan = _make_scan(
            subdomains=[
                SubdomainRecord(name="www.example.com", source="test"),
                SubdomainRecord(name="api.example.com", source="test"),
            ]
        )
        graph = build_graph(scan)
        sub_nodes = [n for n in graph.nodes if n.node_type == NodeType.SUBDOMAIN]
        assert len(sub_nodes) == 2
        # Should have HAS_SUBDOMAIN edges
        sub_edges = [e for e in graph.edges if e.relation == RelationType.HAS_SUBDOMAIN]
        assert len(sub_edges) == 2

    def test_build_with_ips(self):
        scan = _make_scan(
            ips=[
                IPRecord(address="1.2.3.4", version=4),
                IPRecord(address="5.6.7.8", version=4),
            ]
        )
        graph = build_graph(scan)
        ip_nodes = [n for n in graph.nodes if n.node_type == NodeType.IP]
        assert len(ip_nodes) == 2

    def test_build_with_ports(self):
        scan = _make_scan(
            ips=[IPRecord(address="1.2.3.4", version=4)],
            ports=[PortRecord(port=80, protocol="tcp", ip_address="1.2.3.4")],
        )
        graph = build_graph(scan)
        port_nodes = [n for n in graph.nodes if n.node_type == NodeType.PORT]
        assert len(port_nodes) == 1

    def test_build_with_tech(self):
        scan = _make_scan(
            ips=[IPRecord(address="1.2.3.4", version=4)],
            ports=[PortRecord(port=80, protocol="tcp", ip_address="1.2.3.4")],
            technologies=[
                TechnologyRecord(name="nginx", version="1.21", ip_address="1.2.3.4", port=80),
            ],
        )
        graph = build_graph(scan)
        tech_nodes = [n for n in graph.nodes if n.node_type == NodeType.TECHNOLOGY]
        assert len(tech_nodes) == 1

    def test_build_complete(self):
        scan = _make_scan(
            subdomains=[SubdomainRecord(name="www.example.com", source="test")],
            ips=[IPRecord(address="1.2.3.4", version=4)],
            ports=[PortRecord(port=443, protocol="tcp", ip_address="1.2.3.4")],
            technologies=[TechnologyRecord(name="nginx", ip_address="1.2.3.4", port=443)],
        )
        graph = build_graph(scan)
        assert len(graph.nodes) >= 4
        assert len(graph.edges) >= 3


class TestNetworkX:
    def test_to_networkx(self):
        scan = _make_scan(
            subdomains=[SubdomainRecord(name="www.example.com", source="test")],
            ips=[IPRecord(address="1.2.3.4", version=4)],
        )
        graph = build_graph(scan)
        G = to_networkx(graph)
        assert G.number_of_nodes() == len(graph.nodes)
        assert G.number_of_edges() == len(graph.edges)


class TestGraphStats:
    def test_graph_stats(self):
        scan = _make_scan(
            subdomains=[SubdomainRecord(name="www.example.com", source="test")],
            ips=[IPRecord(address="1.2.3.4", version=4)],
        )
        graph = build_graph(scan)
        stats = get_graph_stats(graph)
        assert stats["total_nodes"] == len(graph.nodes)
        assert stats["total_edges"] == len(graph.edges)
        assert "nodes_by_type" in stats
        assert "edges_by_relation" in stats


class TestNodeId:
    def test_node_id_deterministic(self):
        id1 = _make_node_id(NodeType.DOMAIN, "example.com")
        id2 = _make_node_id(NodeType.DOMAIN, "example.com")
        assert id1 == id2
        assert id1 == "domain:example.com"
