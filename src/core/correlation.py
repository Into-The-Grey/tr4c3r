"""Correlation engine for TR4C3R.

Builds relationship graphs between search results using NetworkX.
Discovers connections, calculates relationship strength, and detects patterns.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

import networkx as nx

from src.core.data_models import Result


class CorrelationEngine:
    """Correlates search results to build relationship graphs."""

    def __init__(self, min_confidence: float = 0.5, max_depth: int = 3):
        """
        Initialize the correlation engine.

        Args:
            min_confidence: Minimum confidence for correlations
            max_depth: Maximum graph traversal depth
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.graph = nx.Graph()
        self.min_confidence = min_confidence
        self.max_depth = max_depth
        self.logger.info(
            f"CorrelationEngine initialized (min_confidence={min_confidence}, "
            f"max_depth={max_depth})"
        )

    def add_result(self, result: Result) -> None:
        """
        Add a search result to the correlation graph.

        Args:
            result: Search result to add
        """
        # Add the result identifier as a node
        node_id = f"{result.source}:{result.identifier}"

        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                identifier=result.identifier,
                source=result.source,
                url=result.url,
                confidence=result.confidence,
                timestamp=result.timestamp.isoformat(),
                metadata=result.metadata,
            )

        # Create edges based on metadata connections
        self._create_edges_from_metadata(node_id, result)

    def _create_edges_from_metadata(self, node_id: str, result: Result) -> None:
        """
        Create edges based on metadata connections.

        Args:
            node_id: Node ID in the graph
            result: Search result
        """
        metadata = result.metadata

        # Connect email results
        if "email" in metadata:
            email_node = f"email:{metadata['email']}"
            self._add_edge(node_id, email_node, weight=0.8, relation="has_email")

        # Connect phone results
        if "phone" in metadata:
            phone_node = f"phone:{metadata['phone']}"
            self._add_edge(node_id, phone_node, weight=0.8, relation="has_phone")

        # Connect name results
        if "full_name" in metadata:
            name_node = f"name:{metadata['full_name']}"
            self._add_edge(node_id, name_node, weight=0.7, relation="has_name")

        # Connect username results
        if "username" in metadata or "potential_usernames" in metadata:
            usernames = metadata.get("potential_usernames", [metadata.get("username", "")])
            for username in usernames:
                if username:
                    username_node = f"username:{username}"
                    self._add_edge(node_id, username_node, weight=0.6, relation="has_username")

        # Connect location results
        if "location" in metadata:
            location_node = f"location:{metadata['location']}"
            self._add_edge(node_id, location_node, weight=0.5, relation="located_in")

    def _add_edge(
        self, node1: str, node2: str, weight: float = 0.5, relation: str = "related_to"
    ) -> None:
        """
        Add an edge between two nodes.

        Args:
            node1: First node ID
            node2: Second node ID
            weight: Edge weight (relationship strength)
            relation: Type of relationship
        """
        # Create node2 if it doesn't exist
        if not self.graph.has_node(node2):
            parts = node2.split(":", 1)
            self.graph.add_node(
                node2,
                type=parts[0] if len(parts) > 1 else "unknown",
                value=parts[1] if len(parts) > 1 else node2,
            )

        # Add or update edge
        if self.graph.has_edge(node1, node2):
            # Strengthen existing connection
            current_weight = self.graph[node1][node2].get("weight", 0)
            new_weight = min(1.0, current_weight + weight * 0.3)
            self.graph[node1][node2]["weight"] = new_weight
        else:
            self.graph.add_edge(node1, node2, weight=weight, relation=relation)

    def build_graph_from_results(self, results: List[Result]) -> None:
        """
        Build correlation graph from a list of results.

        Args:
            results: List of search results to correlate
        """
        self.logger.info(f"Building correlation graph from {len(results)} results")

        for result in results:
            if result.confidence >= self.min_confidence:
                self.add_result(result)

        self.logger.info(
            f"Graph built: {self.graph.number_of_nodes()} nodes, "
            f"{self.graph.number_of_edges()} edges"
        )

    def find_connections(self, identifier: str, max_depth: Optional[int] = None) -> List[Dict]:
        """
        Find connections for a given identifier.

        Args:
            identifier: The identifier to find connections for
            max_depth: Maximum traversal depth (uses self.max_depth if None)

        Returns:
            List of connected nodes with relationship information
        """
        max_depth = max_depth or self.max_depth

        # Find matching nodes
        matching_nodes = [n for n in self.graph.nodes() if identifier in n]

        if not matching_nodes:
            self.logger.warning(f"No nodes found for identifier: {identifier}")
            return []

        connections = []
        visited = set()

        for start_node in matching_nodes:
            # BFS to find connections up to max_depth
            queue = [(start_node, 0)]

            while queue:
                current_node, depth = queue.pop(0)

                if current_node in visited or depth > max_depth:
                    continue

                visited.add(current_node)

                if current_node != start_node:
                    # Get path to this node
                    try:
                        path = nx.shortest_path(self.graph, start_node, current_node)
                        path_length = len(path) - 1

                        # Calculate connection strength
                        strength = self._calculate_path_strength(path)

                        connections.append(
                            {
                                "node": current_node,
                                "depth": depth,
                                "path_length": path_length,
                                "strength": strength,
                                "attributes": dict(self.graph.nodes[current_node]),
                            }
                        )
                    except nx.NetworkXNoPath:
                        continue

                # Add neighbors to queue
                if depth < max_depth:
                    for neighbor in self.graph.neighbors(current_node):
                        if neighbor not in visited:
                            queue.append((neighbor, depth + 1))

        # Sort by strength and depth
        connections.sort(key=lambda x: (-x["strength"], x["depth"]))

        return connections

    def _calculate_path_strength(self, path: List[str]) -> float:
        """
        Calculate the strength of a connection path.

        Args:
            path: List of node IDs forming a path

        Returns:
            Connection strength (0.0 to 1.0)
        """
        if len(path) < 2:
            return 0.0

        # Product of edge weights along the path
        strength = 1.0
        for i in range(len(path) - 1):
            edge_data = self.graph.get_edge_data(path[i], path[i + 1])
            if edge_data:
                weight = edge_data.get("weight", 0.5)
                strength *= weight

        # Decay based on path length
        decay = 0.9 ** (len(path) - 1)

        return strength * decay

    def get_clusters(self, min_size: int = 2) -> List[Set[str]]:
        """
        Find clusters of related identifiers.

        Args:
            min_size: Minimum cluster size

        Returns:
            List of node ID sets forming clusters
        """
        # Use connected components
        components = list(nx.connected_components(self.graph))

        # Filter by size
        clusters = [c for c in components if len(c) >= min_size]

        self.logger.info(f"Found {len(clusters)} clusters (min_size={min_size})")

        return clusters

    def find_patterns(self) -> Dict[str, List]:
        """
        Detect patterns in the correlation graph.

        Returns:
            Dictionary of detected patterns
        """
        patterns = {
            "hubs": [],  # Nodes with many connections
            "bridges": [],  # Nodes connecting clusters
            "triangles": [],  # Groups of 3 mutually connected nodes
            "isolated": [],  # Nodes with no connections
        }

        # Find hubs (high degree nodes)
        degree_threshold = max(3, self.graph.number_of_nodes() * 0.1)
        for node, degree in self.graph.degree():
            if degree >= degree_threshold:
                patterns["hubs"].append(
                    {"node": node, "degree": degree, "attributes": dict(self.graph.nodes[node])}
                )

        # Find bridges (articulation points)
        articulation_points = list(nx.articulation_points(self.graph))
        for node in articulation_points:
            patterns["bridges"].append({"node": node, "attributes": dict(self.graph.nodes[node])})

        # Find triangles
        triangles = [
            list(triangle)
            for triangle in nx.enumerate_all_cliques(self.graph)
            if len(triangle) == 3
        ]
        patterns["triangles"] = triangles[:50]  # Limit to first 50

        # Find isolated nodes
        isolated = list(nx.isolates(self.graph))
        patterns["isolated"] = [
            {"node": node, "attributes": dict(self.graph.nodes[node])} for node in isolated
        ]

        self.logger.info(
            f"Patterns found: {len(patterns['hubs'])} hubs, "
            f"{len(patterns['bridges'])} bridges, {len(patterns['triangles'])} triangles"
        )

        return patterns

    def calculate_relationship_score(self, node1: str, node2: str) -> float:
        """
        Calculate relationship strength between two nodes.

        Args:
            node1: First node ID
            node2: Second node ID

        Returns:
            Relationship score (0.0 to 1.0)
        """
        if not self.graph.has_node(node1) or not self.graph.has_node(node2):
            return 0.0

        # Direct connection
        if self.graph.has_edge(node1, node2):
            return self.graph[node1][node2].get("weight", 0.5)

        # Indirect connection via shortest path
        try:
            path = nx.shortest_path(self.graph, node1, node2)
            return self._calculate_path_strength(path)
        except nx.NetworkXNoPath:
            return 0.0

    def get_statistics(self) -> Dict:
        """
        Get graph statistics.

        Returns:
            Dictionary with graph statistics
        """
        stats = {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "density": nx.density(self.graph),
            "connected_components": nx.number_connected_components(self.graph),
        }

        if stats["nodes"] > 0:
            stats["average_degree"] = sum(d for _, d in self.graph.degree()) / stats["nodes"]
        else:
            stats["average_degree"] = 0.0

        return stats

    def export_graph(self) -> Dict:
        """
        Export graph data for visualization.

        Returns:
            Dictionary with nodes and edges
        """
        nodes = [{"id": node, **dict(self.graph.nodes[node])} for node in self.graph.nodes()]

        edges = [{"source": u, "target": v, **data} for u, v, data in self.graph.edges(data=True)]

        return {"nodes": nodes, "edges": edges, "statistics": self.get_statistics()}

    def clear(self) -> None:
        """Clear the correlation graph."""
        self.graph.clear()
        self.logger.info("Correlation graph cleared")
