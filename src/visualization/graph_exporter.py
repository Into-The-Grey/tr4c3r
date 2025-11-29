"""Graph export functionality for TR4C3R.

Exports correlation graphs to various formats including Gephi (GEXF),
Pyvis interactive HTML, and JSON for custom visualization.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import networkx as nx

logger = logging.getLogger(__name__)


class GraphExporter:
    """Exports graph data to various visualization formats."""

    def __init__(self):
        """Initialize the graph exporter."""
        logger.info("GraphExporter initialized")

    def _networkx_from_dict(self, graph_data: Dict[str, Any]) -> nx.Graph:
        """Convert graph dictionary to NetworkX graph.

        Parameters
        ----------
        graph_data : Dict[str, Any]
            Graph data with 'nodes' and 'edges' keys.

        Returns
        -------
        nx.Graph
            NetworkX graph object.
        """
        G = nx.Graph()

        # Add nodes with attributes
        for node in graph_data.get("nodes", []):
            node_id = node.get("id")
            if node_id:
                G.add_node(node_id, **node)

        # Add edges with attributes
        for edge in graph_data.get("edges", []):
            source = edge.get("source")
            target = edge.get("target")
            if source and target:
                weight = edge.get("weight", 1.0)
                edge_type = edge.get("type", "unknown")
                G.add_edge(source, target, weight=weight, type=edge_type)

        return G

    def export_to_gephi(
        self, graph_data: Dict[str, Any], output_path: str, include_stats: bool = True
    ) -> bool:
        """Export graph data to Gephi GEXF format.

        Parameters
        ----------
        graph_data : Dict[str, Any]
            Graph data with 'nodes' and 'edges' keys.
        output_path : str
            Path where the GEXF file should be saved.
        include_stats : bool
            Whether to include graph statistics as attributes.

        Returns
        -------
        bool
            True if export successful, False otherwise.
        """
        try:
            logger.info(f"Exporting graph to Gephi GEXF format: {output_path}")

            # Convert to NetworkX graph
            G = self._networkx_from_dict(graph_data)

            if include_stats and "statistics" in graph_data:
                # Add statistics as graph attributes
                for key, value in graph_data["statistics"].items():
                    G.graph[key] = value

            # Write GEXF file
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            nx.write_gexf(G, str(output_path_obj))

            logger.info(
                f"Successfully exported {G.number_of_nodes()} nodes and "
                f"{G.number_of_edges()} edges to {output_path}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to export to Gephi format: {e}", exc_info=True)
            return False

    def export_to_pyvis(
        self,
        graph_data: Dict[str, Any],
        output_path: str,
        notebook: bool = False,
        height: str = "750px",
        width: str = "100%",
        bgcolor: str = "#222222",
        font_color: str = "white",
        physics_enabled: bool = True,
    ) -> bool:
        """Export graph to Pyvis interactive HTML.

        Parameters
        ----------
        graph_data : Dict[str, Any]
            Graph data with 'nodes' and 'edges' keys.
        output_path : str
            Path where the HTML file should be saved.
        notebook : bool
            Whether to generate notebook-compatible output.
        height : str
            Height of the visualization canvas.
        width : str
            Width of the visualization canvas.
        bgcolor : str
            Background color.
        font_color : str
            Font color for labels.
        physics_enabled : bool
            Whether to enable physics simulation.

        Returns
        -------
        bool
            True if export successful, False otherwise.
        """
        try:
            from pyvis.network import Network

            logger.info(f"Exporting graph to Pyvis HTML format: {output_path}")

            # Create Pyvis network
            net = Network(
                height=height,
                width=width,
                bgcolor=bgcolor,
                font_color=font_color,
                notebook=notebook,
            )

            # Add nodes
            for node in graph_data.get("nodes", []):
                node_id = node.get("id")
                if not node_id:
                    continue

                # Extract node properties
                source = node.get("source", "")
                confidence = node.get("confidence", 0.0)
                label = node.get("identifier", node_id)

                # Color nodes by source type
                color = self._get_node_color(source)

                # Size nodes by confidence
                size = 10 + (confidence * 20)

                title = f"{source}<br>Confidence: {confidence:.2f}"

                net.add_node(node_id, label=label, title=title, color=color, size=size)

            # Add edges
            for edge in graph_data.get("edges", []):
                source = edge.get("source")
                target = edge.get("target")
                if not (source and target):
                    continue

                weight = edge.get("weight", 1.0)
                edge_type = edge.get("type", "unknown")

                # Edge width based on weight
                width = 1 + (weight * 3)

                title = f"Type: {edge_type}<br>Weight: {weight:.2f}"

                net.add_edge(source, target, value=width, title=title)

            # Configure physics
            if physics_enabled:
                net.set_options(
                    """
                {
                  "physics": {
                    "forceAtlas2Based": {
                      "gravitationalConstant": -50,
                      "centralGravity": 0.01,
                      "springLength": 100,
                      "springConstant": 0.08
                    },
                    "maxVelocity": 50,
                    "solver": "forceAtlas2Based",
                    "timestep": 0.35,
                    "stabilization": {"iterations": 150}
                  }
                }
                """
                )
            else:
                net.toggle_physics(False)

            # Save to HTML
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            net.save_graph(str(output_path_obj))

            logger.info(f"Successfully exported interactive HTML to {output_path}")
            return True

        except ImportError:
            logger.error("Pyvis not installed. Install with: pip install pyvis")
            return False
        except Exception as e:
            logger.error(f"Failed to export to Pyvis format: {e}", exc_info=True)
            return False

    def _get_node_color(self, source: str) -> str:
        """Get color for node based on source type.

        Parameters
        ----------
        source : str
            Node source identifier.

        Returns
        -------
        str
            Hex color code.
        """
        color_map = {
            "email": "#3498db",  # Blue
            "phone": "#2ecc71",  # Green
            "username": "#9b59b6",  # Purple
            "social": "#e74c3c",  # Red
            "name": "#f39c12",  # Orange
            "location": "#1abc9c",  # Turquoise
            "dark_web": "#34495e",  # Dark gray
        }

        for key, color in color_map.items():
            if key in source.lower():
                return color

        return "#95a5a6"  # Default gray

    def export_to_json(
        self, graph_data: Dict[str, Any], output_path: str, pretty: bool = True
    ) -> bool:
        """Export graph data to JSON format.

        Parameters
        ----------
        graph_data : Dict[str, Any]
            Graph data to export.
        output_path : str
            Path where the JSON file should be saved.
        pretty : bool
            Whether to use pretty printing (indented).

        Returns
        -------
        bool
            True if export successful, False otherwise.
        """
        try:
            logger.info(f"Exporting graph to JSON format: {output_path}")

            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)

            with open(output_path_obj, "w") as f:
                if pretty:
                    json.dump(graph_data, f, indent=2, default=str)
                else:
                    json.dump(graph_data, f, default=str)

            logger.info(f"Successfully exported JSON to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export to JSON format: {e}", exc_info=True)
            return False

    def export_to_graphml(self, graph_data: Dict[str, Any], output_path: str) -> bool:
        """Export graph data to GraphML format.

        Parameters
        ----------
        graph_data : Dict[str, Any]
            Graph data with 'nodes' and 'edges' keys.
        output_path : str
            Path where the GraphML file should be saved.

        Returns
        -------
        bool
            True if export successful, False otherwise.
        """
        try:
            logger.info(f"Exporting graph to GraphML format: {output_path}")

            # Convert to NetworkX graph
            G = self._networkx_from_dict(graph_data)

            # Write GraphML file
            output_path_obj = Path(output_path)
            output_path_obj.parent.mkdir(parents=True, exist_ok=True)
            nx.write_graphml(G, str(output_path_obj))

            logger.info(f"Successfully exported GraphML to {output_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export to GraphML format: {e}", exc_info=True)
            return False

    def filter_graph(
        self,
        graph_data: Dict[str, Any],
        min_confidence: Optional[float] = None,
        source_types: Optional[List[str]] = None,
        max_nodes: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Filter graph data based on criteria.

        Parameters
        ----------
        graph_data : Dict[str, Any]
            Original graph data.
        min_confidence : Optional[float]
            Minimum confidence threshold for nodes.
        source_types : Optional[List[str]]
            List of source types to include.
        max_nodes : Optional[int]
            Maximum number of nodes to keep (highest confidence).

        Returns
        -------
        Dict[str, Any]
            Filtered graph data.
        """
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])

        # Filter by confidence
        if min_confidence is not None:
            nodes = [n for n in nodes if n.get("confidence", 0.0) >= min_confidence]

        # Filter by source type
        if source_types:
            source_types_lower = [s.lower() for s in source_types]
            nodes = [
                n
                for n in nodes
                if any(st in n.get("source", "").lower() for st in source_types_lower)
            ]

        # Limit number of nodes
        if max_nodes and len(nodes) > max_nodes:
            # Sort by confidence descending
            nodes = sorted(nodes, key=lambda n: n.get("confidence", 0.0), reverse=True)[:max_nodes]

        # Get set of valid node IDs
        valid_node_ids = {n.get("id") for n in nodes}

        # Filter edges to only include those between valid nodes
        edges = [
            e
            for e in edges
            if e.get("source") in valid_node_ids and e.get("target") in valid_node_ids
        ]

        return {"nodes": nodes, "edges": edges, "statistics": graph_data.get("statistics", {})}
