"""Interactive graph visualization using pyvis."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from pyvis.network import Network

from core.models import GraphData, NodeType

# Color scheme by node type
NODE_COLORS: dict[str, str] = {
    NodeType.DOMAIN.value: "#e74c3c",           # Red
    NodeType.SUBDOMAIN.value: "#e67e22",         # Orange
    NodeType.IP.value: "#3498db",                # Blue
    NodeType.PORT.value: "#2ecc71",              # Green
    NodeType.TECHNOLOGY.value: "#9b59b6",        # Purple
    NodeType.ASN.value: "#1abc9c",               # Teal
    NodeType.VULNERABILITY.value: "#ff1744",     # Bright Red
    NodeType.WEB_DIRECTORY.value: "#ffd600",     # Gold
    NodeType.WAF.value: "#00e676",               # Bright Green
    NodeType.SSL_CERT.value: "#1a237e",          # Dark Blue
}

# Size by node type
NODE_SIZES: dict[str, int] = {
    NodeType.DOMAIN.value: 40,
    NodeType.SUBDOMAIN.value: 20,
    NodeType.IP.value: 30,
    NodeType.PORT.value: 15,
    NodeType.TECHNOLOGY.value: 18,
    NodeType.ASN.value: 35,
    NodeType.VULNERABILITY.value: 22,
    NodeType.WEB_DIRECTORY.value: 14,
    NodeType.WAF.value: 25,
    NodeType.SSL_CERT.value: 20,
}

# Shape by node type
NODE_SHAPES: dict[str, str] = {
    NodeType.DOMAIN.value: "star",
    NodeType.SUBDOMAIN.value: "dot",
    NodeType.IP.value: "diamond",
    NodeType.PORT.value: "square",
    NodeType.TECHNOLOGY.value: "triangle",
    NodeType.ASN.value: "hexagon",
    NodeType.VULNERABILITY.value: "triangleDown",
    NodeType.WEB_DIRECTORY.value: "box",
    NodeType.WAF.value: "ellipse",
    NodeType.SSL_CERT.value: "database",
}


def render_graph(
    graph_data: GraphData,
    height: str = "700px",
    width: str = "100%",
    bgcolor: str = "#0e1117",
    font_color: str = "#ffffff",
    output_path: Optional[str] = None,
) -> str:
    """Render a GraphData object as an interactive HTML visualization.

    Args:
        graph_data: The graph data to visualize.
        height: Height of the visualization.
        width: Width of the visualization.
        bgcolor: Background color.
        font_color: Font color.
        output_path: Optional path to save HTML. If None, uses a temp file.

    Returns:
        HTML string of the interactive graph.
    """
    net = Network(
        height=height,
        width=width,
        bgcolor=bgcolor,
        font_color=font_color,
        directed=True,
        notebook=False,
    )

    # Physics configuration
    net.set_options("""
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -100,
                "centralGravity": 0.01,
                "springLength": 200,
                "springConstant": 0.02,
                "damping": 0.4
            },
            "solver": "forceAtlas2Based",
            "stabilization": {
                "enabled": true,
                "iterations": 200
            }
        },
        "edges": {
            "color": {
                "color": "#555555",
                "highlight": "#ffffff"
            },
            "arrows": {
                "to": {
                    "enabled": true,
                    "scaleFactor": 0.5
                }
            },
            "smooth": {
                "type": "continuous"
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "zoomView": true,
            "dragView": true
        }
    }
    """)

    # Add nodes
    for node in graph_data.nodes:
        node_type = node.node_type.value
        color = NODE_COLORS.get(node_type, "#95a5a6")
        size = NODE_SIZES.get(node_type, 20)
        shape = NODE_SHAPES.get(node_type, "dot")

        # Build tooltip
        tooltip_parts = [f"<b>{node.label}</b>", f"Type: {node_type}"]
        for key, val in node.properties.items():
            if val is not None:
                tooltip_parts.append(f"{key}: {val}")
        tooltip = "<br>".join(tooltip_parts)

        net.add_node(
            node.id,
            label=node.label,
            title=tooltip,
            color=color,
            size=size,
            shape=shape,
            font={"size": 12, "color": font_color},
        )

    # Add edges
    for edge in graph_data.edges:
        net.add_edge(
            edge.source,
            edge.target,
            title=edge.relation.value,
            label=edge.relation.value,
            font={"size": 8, "color": "#888888", "align": "middle"},
        )

    # Generate HTML
    if output_path:
        net.save_graph(output_path)
        return Path(output_path).read_text(encoding="utf-8")
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8")
        net.save_graph(tmp.name)
        html = Path(tmp.name).read_text(encoding="utf-8")
        return html


def get_legend_html() -> str:
    """Generate an HTML legend for node types."""
    items = []
    for ntype in NodeType:
        color = NODE_COLORS.get(ntype.value, "#95a5a6")
        items.append(
            f'<span style="color:{color}; margin-right:15px;">'
            f"&#9679; {ntype.value.capitalize()}</span>"
        )
    return '<div style="padding:10px; font-size:14px;">' + " ".join(items) + "</div>"
