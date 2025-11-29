"""Interactive graph visualization dashboard for TR4C3R.

Creates rich, interactive HTML visualizations of correlation graphs using
vis.js. Includes search functionality, filtering, node details,
timeline views, and export options.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the graph."""

    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    WEBSITE = "website"
    SOCIAL = "social"
    IP_ADDRESS = "ip"
    DOMAIN = "domain"
    IMAGE = "image"
    LOCATION = "location"
    ORGANIZATION = "organization"
    UNKNOWN = "unknown"


class EdgeType(Enum):
    """Types of relationships between nodes."""

    SAME_PERSON = "same_person"
    OWNS = "owns"
    WORKS_AT = "works_at"
    ASSOCIATED = "associated"
    MENTIONS = "mentions"
    LINKED_PROFILE = "linked_profile"
    SIMILAR = "similar"
    UNKNOWN = "unknown"


@dataclass
class NodeStyle:
    """Visual style for a node type."""

    color: str
    shape: str = "dot"
    size: int = 25
    icon: str = "❓"
    border_color: str = "#ffffff"
    border_width: int = 2


@dataclass
class DashboardConfig:
    """Configuration for the dashboard visualization."""

    title: str = "TR4C3R Investigation Graph"
    height: str = "800px"
    width: str = "100%"
    bgcolor: str = "#1a1a2e"
    font_color: str = "#eaeaea"
    physics_enabled: bool = True
    physics_solver: str = "forceAtlas2Based"
    show_navigation: bool = True
    show_search: bool = True
    show_legend: bool = True
    show_timeline: bool = True
    show_statistics: bool = True
    show_filters: bool = True
    dark_mode: bool = True


# Default node styles by type
NODE_STYLES: Dict[NodeType, NodeStyle] = {
    NodeType.USERNAME: NodeStyle(color="#e94560", shape="dot", size=30, icon="👤"),
    NodeType.EMAIL: NodeStyle(color="#0f3460", shape="diamond", size=28, icon="📧"),
    NodeType.PHONE: NodeStyle(color="#16c79a", shape="triangle", size=25, icon="📱"),
    NodeType.NAME: NodeStyle(color="#ff9a3c", shape="star", size=32, icon="🏷️"),
    NodeType.WEBSITE: NodeStyle(color="#7868e6", shape="square", size=25, icon="🌐"),
    NodeType.SOCIAL: NodeStyle(color="#ff6b6b", shape="dot", size=28, icon="💬"),
    NodeType.IP_ADDRESS: NodeStyle(color="#4ecdc4", shape="hexagon", size=22, icon="🔗"),
    NodeType.DOMAIN: NodeStyle(color="#ffe66d", shape="box", size=24, icon="🏠"),
    NodeType.IMAGE: NodeStyle(color="#c44569", shape="circularImage", size=30, icon="🖼️"),
    NodeType.LOCATION: NodeStyle(color="#546de5", shape="triangle", size=22, icon="📍"),
    NodeType.ORGANIZATION: NodeStyle(color="#e15f41", shape="box", size=28, icon="🏢"),
    NodeType.UNKNOWN: NodeStyle(color="#888888", shape="dot", size=20, icon="❓"),
}

# Edge colors by type
EDGE_COLORS: Dict[EdgeType, str] = {
    EdgeType.SAME_PERSON: "#e94560",
    EdgeType.OWNS: "#16c79a",
    EdgeType.WORKS_AT: "#ff9a3c",
    EdgeType.ASSOCIATED: "#7868e6",
    EdgeType.MENTIONS: "#4ecdc4",
    EdgeType.LINKED_PROFILE: "#ff6b6b",
    EdgeType.SIMILAR: "#ffe66d",
    EdgeType.UNKNOWN: "#888888",
}


class GraphVisualizer:
    """Creates interactive graph visualizations with rich features."""

    def __init__(self, config: Optional[DashboardConfig] = None):
        """Initialize the graph visualizer.

        Args:
            config: Dashboard configuration options
        """
        self.config = config or DashboardConfig()
        logger.info("GraphVisualizer initialized with config: %s", self.config.title)

    def _determine_node_type(self, node: Dict[str, Any]) -> NodeType:
        """Determine the type of a node from its attributes."""
        node_type_str = node.get("type", "").lower()
        label = node.get("label", "").lower()
        node_id = str(node.get("id", "")).lower()

        for nt in NodeType:
            if nt.value == node_type_str:
                return nt

        if "@" in node_id or "@" in label or "email" in node_type_str:
            return NodeType.EMAIL
        if any(c.isdigit() for c in node_id) and len(node_id) >= 10:
            if "." in node_id:
                return NodeType.IP_ADDRESS
            return NodeType.PHONE
        if "http" in node_id or "www" in node_id or ".com" in node_id:
            return NodeType.WEBSITE
        if node_type_str in ("twitter", "instagram", "facebook", "linkedin", "reddit"):
            return NodeType.SOCIAL
        if "username" in node_type_str or "user" in node_type_str:
            return NodeType.USERNAME

        return NodeType.UNKNOWN

    def _determine_edge_type(self, edge: Dict[str, Any]) -> EdgeType:
        """Determine the type of an edge from its attributes."""
        edge_type_str = edge.get("type", "").lower()
        relationship = edge.get("relationship", "").lower()
        combined = f"{edge_type_str} {relationship}"

        if "same" in combined or "identity" in combined:
            return EdgeType.SAME_PERSON
        if "own" in combined or "registered" in combined:
            return EdgeType.OWNS
        if "work" in combined or "employ" in combined:
            return EdgeType.WORKS_AT
        if "link" in combined or "profile" in combined:
            return EdgeType.LINKED_PROFILE
        if "mention" in combined or "reference" in combined:
            return EdgeType.MENTIONS
        if "similar" in combined:
            return EdgeType.SIMILAR
        if "associated" in combined or "related" in combined:
            return EdgeType.ASSOCIATED

        return EdgeType.UNKNOWN

    def _generate_node_html(self, node: Dict[str, Any], node_type: NodeType) -> str:
        """Generate HTML popup content for a node."""
        style = NODE_STYLES.get(node_type, NODE_STYLES[NodeType.UNKNOWN])
        metadata = node.get("metadata", {})
        confidence = node.get("confidence", metadata.get("confidence", 0))
        timestamp = node.get("timestamp", metadata.get("timestamp", ""))
        source = node.get("source", metadata.get("source", "Unknown"))

        html = f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; padding: 12px; max-width: 350px; background: #1a1a2e; border-radius: 8px; border: 1px solid #333;">
            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                <span style="font-size: 24px; margin-right: 10px;">{style.icon}</span>
                <div>
                    <div style="font-weight: bold; color: #fff; font-size: 14px;">{node.get('label', node.get('id', 'Unknown'))}</div>
                    <div style="color: {style.color}; font-size: 12px; text-transform: uppercase;">{node_type.value}</div>
                </div>
            </div>
            <div style="border-top: 1px solid #333; padding-top: 10px;">
                <div style="color: #888; font-size: 11px; margin-bottom: 5px;">
                    <strong style="color: #aaa;">Source:</strong> {source}
                </div>
                <div style="color: #888; font-size: 11px; margin-bottom: 5px;">
                    <strong style="color: #aaa;">Confidence:</strong>
                    <span style="color: {'#16c79a' if confidence > 0.7 else '#ff9a3c' if confidence > 0.4 else '#e94560'}">
                        {confidence:.0%}
                    </span>
                </div>
        """

        if timestamp:
            html += f"""
                <div style="color: #888; font-size: 11px; margin-bottom: 5px;">
                    <strong style="color: #aaa;">Discovered:</strong> {timestamp}
                </div>
            """

        for key, value in metadata.items():
            if key not in ("confidence", "timestamp", "source") and value:
                html += f"""
                <div style="color: #888; font-size: 11px; margin-bottom: 3px;">
                    <strong style="color: #aaa;">{key.replace('_', ' ').title()}:</strong> {value}
                </div>
                """

        html += "</div></div>"
        return html

    def _generate_legend_html(self) -> str:
        """Generate HTML for the graph legend."""
        html = """
        <div id="legend" style="
            position: absolute; bottom: 20px; left: 20px;
            background: rgba(26, 26, 46, 0.95); padding: 15px; border-radius: 8px;
            border: 1px solid #333; font-family: 'Segoe UI', Arial, sans-serif;
            z-index: 1000; max-height: 300px; overflow-y: auto;
        ">
            <div style="font-weight: bold; color: #fff; margin-bottom: 10px; font-size: 14px;">Node Types</div>
        """

        for node_type, style in NODE_STYLES.items():
            html += f"""
            <div style="display: flex; align-items: center; margin-bottom: 6px;">
                <div style="width: 16px; height: 16px; background: {style.color}; border-radius: 50%; margin-right: 8px;"></div>
                <span style="color: #ccc; font-size: 12px;">{style.icon} {node_type.value.replace('_', ' ').title()}</span>
            </div>
            """

        html += """
            <div style="font-weight: bold; color: #fff; margin: 15px 0 10px 0; font-size: 14px; border-top: 1px solid #333; padding-top: 10px;">Edge Types</div>
        """

        for edge_type, color in EDGE_COLORS.items():
            html += f"""
            <div style="display: flex; align-items: center; margin-bottom: 6px;">
                <div style="width: 20px; height: 3px; background: {color}; margin-right: 8px;"></div>
                <span style="color: #ccc; font-size: 12px;">{edge_type.value.replace('_', ' ').title()}</span>
            </div>
            """

        html += "</div>"
        return html

    def _generate_search_html(self) -> str:
        """Generate HTML for the search functionality."""
        return """
        <div id="search-container" style="position: absolute; top: 20px; left: 20px; z-index: 1000;">
            <input type="text" id="node-search" placeholder="🔍 Search nodes..." style="
                padding: 10px 15px; font-size: 14px; border: 1px solid #333; border-radius: 20px;
                background: rgba(26, 26, 46, 0.95); color: #fff; width: 250px; outline: none;
            " onkeyup="searchNodes(this.value)">
        </div>
        <script>
            function searchNodes(query) {
                query = query.toLowerCase();
                var nodes = network.body.data.nodes.get();
                var updates = [];
                nodes.forEach(function(node) {
                    var label = (node.label || '').toLowerCase();
                    var id = (node.id || '').toLowerCase();
                    var match = label.includes(query) || id.includes(query);
                    if (query === '') {
                        updates.push({id: node.id, hidden: false, opacity: 1});
                    } else if (match) {
                        updates.push({id: node.id, hidden: false, opacity: 1});
                    } else {
                        updates.push({id: node.id, hidden: false, opacity: 0.2});
                    }
                });
                network.body.data.nodes.update(updates);
            }
        </script>
        """

    def _generate_filters_html(self, node_types: Set[NodeType]) -> str:
        """Generate HTML for filter controls."""
        html = """
        <div id="filters" style="
            position: absolute; top: 20px; right: 20px;
            background: rgba(26, 26, 46, 0.95); padding: 15px; border-radius: 8px;
            border: 1px solid #333; font-family: 'Segoe UI', Arial, sans-serif;
            z-index: 1000; max-width: 200px;
        ">
            <div style="font-weight: bold; color: #fff; margin-bottom: 10px; font-size: 14px;">🎛️ Filters</div>
            <div style="margin-bottom: 10px;">
                <div style="color: #aaa; font-size: 12px; margin-bottom: 5px;">Node Types</div>
        """

        for nt in node_types:
            style = NODE_STYLES.get(nt, NODE_STYLES[NodeType.UNKNOWN])
            html += f"""
                <label style="display: flex; align-items: center; margin-bottom: 4px; cursor: pointer;">
                    <input type="checkbox" checked onchange="toggleNodeType('{nt.value}')" style="margin-right: 8px;">
                    <span style="color: {style.color}; font-size: 12px;">{style.icon} {nt.value.replace('_', ' ').title()}</span>
                </label>
            """

        html += """
            </div>
            <div style="border-top: 1px solid #333; padding-top: 10px;">
                <div style="color: #aaa; font-size: 12px; margin-bottom: 5px;">Confidence Threshold</div>
                <input type="range" id="confidence-slider" min="0" max="100" value="0"
                    style="width: 100%;" onchange="filterByConfidence(this.value)">
                <div style="display: flex; justify-content: space-between; color: #666; font-size: 10px;">
                    <span>0%</span><span id="confidence-value">0%</span><span>100%</span>
                </div>
            </div>
        </div>
        <script>
            var hiddenNodeTypes = new Set();
            function toggleNodeType(nodeType) {
                if (hiddenNodeTypes.has(nodeType)) {
                    hiddenNodeTypes.delete(nodeType);
                } else {
                    hiddenNodeTypes.add(nodeType);
                }
                applyFilters();
            }
            function filterByConfidence(value) {
                document.getElementById('confidence-value').textContent = value + '%';
                applyFilters();
            }
            function applyFilters() {
                var threshold = parseInt(document.getElementById('confidence-slider').value) / 100;
                var nodes = network.body.data.nodes.get();
                var updates = [];
                nodes.forEach(function(node) {
                    var nodeType = node.nodeType || 'unknown';
                    var confidence = node.confidence || 0;
                    var hidden = hiddenNodeTypes.has(nodeType) || confidence < threshold;
                    updates.push({id: node.id, hidden: hidden});
                });
                network.body.data.nodes.update(updates);
            }
        </script>
        """
        return html

    def _generate_statistics_html(self, graph_data: Dict[str, Any]) -> str:
        """Generate HTML for graph statistics panel."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        stats = graph_data.get("statistics", {})

        html = f"""
        <div id="statistics" style="
            position: absolute; bottom: 20px; right: 20px;
            background: rgba(26, 26, 46, 0.95); padding: 15px; border-radius: 8px;
            border: 1px solid #333; font-family: 'Segoe UI', Arial, sans-serif;
            z-index: 1000; min-width: 180px;
        ">
            <div style="font-weight: bold; color: #fff; margin-bottom: 10px; font-size: 14px;">📊 Statistics</div>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                <div style="text-align: center; padding: 10px; background: rgba(233, 69, 96, 0.2); border-radius: 6px;">
                    <div style="font-size: 24px; font-weight: bold; color: #e94560;">{len(nodes)}</div>
                    <div style="font-size: 11px; color: #aaa;">Nodes</div>
                </div>
                <div style="text-align: center; padding: 10px; background: rgba(22, 199, 154, 0.2); border-radius: 6px;">
                    <div style="font-size: 24px; font-weight: bold; color: #16c79a;">{len(edges)}</div>
                    <div style="font-size: 11px; color: #aaa;">Edges</div>
                </div>
            </div>
        """

        if stats:
            html += '<div style="border-top: 1px solid #333; margin-top: 10px; padding-top: 10px;">'
            for key, value in stats.items():
                if isinstance(value, float):
                    value = f"{value:.2f}"
                html += f"""
                <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
                    <span style="color: #888; font-size: 11px;">{key.replace('_', ' ').title()}</span>
                    <span style="color: #fff; font-size: 11px;">{value}</span>
                </div>
                """
            html += "</div>"

        html += "</div>"
        return html

    def _generate_controls_html(self) -> str:
        """Generate HTML for graph controls."""
        return """
        <div id="controls" style="position: absolute; top: 70px; left: 20px; z-index: 1000; display: flex; flex-direction: column; gap: 5px;">
            <button onclick="network.fit()" style="padding: 8px 12px; background: rgba(26, 26, 46, 0.95); border: 1px solid #333; border-radius: 6px; color: #fff; cursor: pointer; font-size: 12px;" title="Fit to screen">🔲 Fit</button>
            <button onclick="togglePhysics()" style="padding: 8px 12px; background: rgba(26, 26, 46, 0.95); border: 1px solid #333; border-radius: 6px; color: #fff; cursor: pointer; font-size: 12px;" title="Toggle physics">⚛️ Physics</button>
            <button onclick="exportPNG()" style="padding: 8px 12px; background: rgba(26, 26, 46, 0.95); border: 1px solid #333; border-radius: 6px; color: #fff; cursor: pointer; font-size: 12px;" title="Export as PNG">📷 Export</button>
            <button onclick="toggleFullscreen()" style="padding: 8px 12px; background: rgba(26, 26, 46, 0.95); border: 1px solid #333; border-radius: 6px; color: #fff; cursor: pointer; font-size: 12px;" title="Fullscreen">⛶ Fullscreen</button>
        </div>
        <script>
            var physicsEnabled = true;
            function togglePhysics() {
                physicsEnabled = !physicsEnabled;
                network.setOptions({physics: {enabled: physicsEnabled}});
            }
            function exportPNG() {
                var canvas = document.getElementsByTagName('canvas')[0];
                var link = document.createElement('a');
                link.download = 'tr4c3r-graph.png';
                link.href = canvas.toDataURL('image/png');
                link.click();
            }
            function toggleFullscreen() {
                var elem = document.getElementById('network');
                if (!document.fullscreenElement) {
                    elem.requestFullscreen();
                } else {
                    document.exitFullscreen();
                }
            }
        </script>
        """

    async def create_dashboard(
        self,
        graph_data: Dict[str, Any],
        output_path: str,
        title: Optional[str] = None,
    ) -> bool:
        """Create an interactive graph dashboard.

        Args:
            graph_data: The graph data to visualize with 'nodes' and 'edges' keys
            output_path: Path where the HTML dashboard should be saved
            title: Optional custom title for the dashboard

        Returns:
            True if creation successful, False otherwise
        """
        try:
            logger.info(f"Creating interactive dashboard: {output_path}")

            if title:
                self.config.title = title

            nodes = graph_data.get("nodes", [])
            edges = graph_data.get("edges", [])

            if not nodes:
                logger.warning("No nodes in graph data")
                return False

            # Process nodes and collect types
            processed_nodes = []
            node_types_present: Set[NodeType] = set()

            for node in nodes:
                node_type = self._determine_node_type(node)
                node_types_present.add(node_type)
                style = NODE_STYLES.get(node_type, NODE_STYLES[NodeType.UNKNOWN])
                confidence = node.get("confidence", node.get("metadata", {}).get("confidence", 0.5))

                processed_node = {
                    "id": node.get("id"),
                    "label": node.get("label", node.get("id", "")),
                    "title": self._generate_node_html(node, node_type),
                    "color": {
                        "background": style.color,
                        "border": style.border_color,
                        "highlight": {"background": style.color, "border": "#fff"},
                    },
                    "shape": style.shape,
                    "size": style.size,
                    "borderWidth": style.border_width,
                    "nodeType": node_type.value,
                    "confidence": confidence,
                    "font": {"color": self.config.font_color},
                }
                processed_nodes.append(processed_node)

            # Process edges
            processed_edges = []
            for edge in edges:
                edge_type = self._determine_edge_type(edge)
                color = EDGE_COLORS.get(edge_type, EDGE_COLORS[EdgeType.UNKNOWN])
                weight = edge.get("weight", 1.0)

                processed_edge = {
                    "from": edge.get("source"),
                    "to": edge.get("target"),
                    "color": {"color": color, "highlight": "#fff"},
                    "width": max(1, min(5, weight * 2)),
                    "arrows": "to" if edge.get("directed", False) else None,
                    "title": f"{edge_type.value.replace('_', ' ').title()} (weight: {weight:.2f})",
                    "smooth": {"type": "continuous"},
                }
                processed_edges.append(processed_edge)

            vis_options = {
                "nodes": {"font": {"size": 12, "color": self.config.font_color}, "shadow": True},
                "edges": {"smooth": {"type": "continuous"}, "shadow": True},
                "physics": {
                    "enabled": self.config.physics_enabled,
                    "solver": self.config.physics_solver,
                    "forceAtlas2Based": {
                        "gravitationalConstant": -50,
                        "centralGravity": 0.01,
                        "springLength": 100,
                        "springConstant": 0.08,
                    },
                    "stabilization": {"iterations": 150},
                },
                "interaction": {
                    "hover": True,
                    "tooltipDelay": 100,
                    "navigationButtons": self.config.show_navigation,
                    "keyboard": True,
                    "zoomView": True,
                    "dragView": True,
                },
            }

            html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.config.title}</title>
    <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: {self.config.bgcolor}; color: {self.config.font_color}; overflow: hidden; }}
        #network {{ width: 100vw; height: 100vh; }}
        #header {{ position: absolute; top: 0; left: 0; right: 0; height: 50px; background: linear-gradient(180deg, rgba(26, 26, 46, 0.98) 0%, rgba(26, 26, 46, 0) 100%); display: flex; align-items: center; padding: 0 20px; z-index: 1001; }}
        #header h1 {{ font-size: 18px; font-weight: 600; color: #fff; }}
        #header .subtitle {{ font-size: 12px; color: #888; margin-left: 15px; }}
        .loading {{ position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 18px; color: #888; z-index: 2000; }}
        .loading.hidden {{ display: none; }}
    </style>
</head>
<body>
    <div id="header">
        <h1>🔍 {self.config.title}</h1>
        <span class="subtitle">Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</span>
    </div>
    <div class="loading" id="loading">Loading graph...</div>
    <div id="network"></div>
    {self._generate_search_html() if self.config.show_search else ''}
    {self._generate_controls_html()}
    {self._generate_filters_html(node_types_present) if self.config.show_filters else ''}
    {self._generate_legend_html() if self.config.show_legend else ''}
    {self._generate_statistics_html(graph_data) if self.config.show_statistics else ''}
    <script>
        var nodes = new vis.DataSet({json.dumps(processed_nodes)});
        var edges = new vis.DataSet({json.dumps(processed_edges)});
        var container = document.getElementById('network');
        var data = {{ nodes: nodes, edges: edges }};
        var options = {json.dumps(vis_options)};
        var network = new vis.Network(container, data, options);
        network.once('stabilizationIterationsDone', function() {{ document.getElementById('loading').classList.add('hidden'); }});
        network.on('doubleClick', function(params) {{ if (params.nodes.length > 0) {{ network.focus(params.nodes[0], {{ scale: 1.5, animation: {{duration: 500}} }}); }} }});
        document.addEventListener('keydown', function(e) {{ if (e.key === 'f' || e.key === 'F') {{ network.fit(); }} if (e.key === 'Escape') {{ network.unselectAll(); }} }});
    </script>
</body>
</html>
"""

            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            output_path_obj.write_text(html, encoding="utf-8")

            logger.info(
                f"Successfully created dashboard with {len(nodes)} nodes and {len(edges)} edges at {output_path}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to create dashboard: {e}", exc_info=True)
            return False

    async def create_mini_dashboard(self, graph_data: Dict[str, Any], output_path: str) -> bool:
        """Create a minimal embedded dashboard suitable for iframes."""
        mini_config = DashboardConfig(
            title="",
            show_navigation=False,
            show_search=False,
            show_legend=False,
            show_timeline=False,
            show_statistics=False,
            show_filters=False,
        )
        original_config = self.config
        self.config = mini_config
        try:
            return await self.create_dashboard(graph_data, output_path)
        finally:
            self.config = original_config
