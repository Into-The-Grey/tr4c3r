"""Tests for graph exporter module."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

import networkx as nx
import pytest

from src.visualization.graph_exporter import GraphExporter


class TestGraphExporter:
    """Test the GraphExporter class."""

    @pytest.fixture
    def exporter(self) -> GraphExporter:
        """Create a GraphExporter instance."""
        return GraphExporter()

    @pytest.fixture
    def sample_graph_data(self) -> Dict[str, Any]:
        """Create sample graph data for testing."""
        return {
            "nodes": [
                {
                    "id": "email:test@example.com",
                    "source": "email",
                    "identifier": "test@example.com",
                    "confidence": 0.9,
                },
                {
                    "id": "username:testuser",
                    "source": "username",
                    "identifier": "testuser",
                    "confidence": 0.8,
                },
                {
                    "id": "phone:+1234567890",
                    "source": "phone",
                    "identifier": "+1234567890",
                    "confidence": 0.7,
                },
            ],
            "edges": [
                {
                    "source": "email:test@example.com",
                    "target": "username:testuser",
                    "weight": 0.85,
                    "type": "email",
                },
                {
                    "source": "username:testuser",
                    "target": "phone:+1234567890",
                    "weight": 0.75,
                    "type": "phone",
                },
            ],
            "statistics": {
                "nodes": 3,
                "edges": 2,
                "density": 0.67,
            },
        }

    def test_initialization(self, exporter: GraphExporter) -> None:
        """Test that GraphExporter initializes correctly."""
        assert exporter is not None

    def test_networkx_from_dict(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test converting dict to NetworkX graph."""
        G = exporter._networkx_from_dict(sample_graph_data)

        assert G.number_of_nodes() == 3
        assert G.number_of_edges() == 2

        # Check nodes have attributes
        assert G.has_node("email:test@example.com")
        assert G.nodes["email:test@example.com"]["confidence"] == 0.9

        # Check edges have attributes
        assert G.has_edge("email:test@example.com", "username:testuser")
        assert G["email:test@example.com"]["username:testuser"]["weight"] == 0.85

    def test_export_to_gephi(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to Gephi GEXF format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_graph.gexf"

            success = exporter.export_to_gephi(sample_graph_data, str(output_path))

            assert success is True
            assert output_path.exists()

            # Verify the file can be read by NetworkX
            G = nx.read_gexf(str(output_path))
            assert G.number_of_nodes() == 3
            assert G.number_of_edges() == 2

    def test_export_to_gephi_with_stats(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to Gephi with statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_graph_stats.gexf"

            success = exporter.export_to_gephi(
                sample_graph_data, str(output_path), include_stats=True
            )

            assert success is True
            assert output_path.exists()

    def test_export_to_gephi_creates_directory(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test that export creates missing directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "test_graph.gexf"

            success = exporter.export_to_gephi(sample_graph_data, str(output_path))

            assert success is True
            assert output_path.exists()

    def test_export_to_pyvis(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to Pyvis HTML format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_graph.html"

            success = exporter.export_to_pyvis(sample_graph_data, str(output_path))

            assert success is True
            assert output_path.exists()

            # Check that HTML file contains expected content
            content = output_path.read_text()
            assert "<html>" in content or "<!DOCTYPE" in content
            assert "test@example.com" in content or "testuser" in content

    def test_export_to_pyvis_custom_settings(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to Pyvis with custom settings."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_custom.html"

            success = exporter.export_to_pyvis(
                sample_graph_data,
                str(output_path),
                height="500px",
                width="800px",
                bgcolor="#ffffff",
                font_color="black",
                physics_enabled=False,
            )

            assert success is True
            assert output_path.exists()

    def test_export_to_json(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to JSON format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_graph.json"

            success = exporter.export_to_json(sample_graph_data, str(output_path))

            assert success is True
            assert output_path.exists()

            # Verify JSON can be loaded
            with open(output_path) as f:
                data = json.load(f)

            assert "nodes" in data
            assert "edges" in data
            assert len(data["nodes"]) == 3

    def test_export_to_json_not_pretty(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to JSON without pretty printing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_compact.json"

            success = exporter.export_to_json(sample_graph_data, str(output_path), pretty=False)

            assert success is True
            assert output_path.exists()

            # Compact JSON should be smaller
            content = output_path.read_text()
            assert "\n  " not in content  # No indentation

    def test_export_to_graphml(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test exporting to GraphML format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_graph.graphml"

            success = exporter.export_to_graphml(sample_graph_data, str(output_path))

            assert success is True
            assert output_path.exists()

            # Verify the file can be read by NetworkX
            G = nx.read_graphml(str(output_path))
            assert G.number_of_nodes() == 3
            assert G.number_of_edges() == 2

    def test_get_node_color(self, exporter: GraphExporter) -> None:
        """Test node color assignment based on source type."""
        assert exporter._get_node_color("email") == "#3498db"
        assert exporter._get_node_color("phone") == "#2ecc71"
        assert exporter._get_node_color("username") == "#9b59b6"
        assert exporter._get_node_color("social:twitter") == "#e74c3c"
        assert exporter._get_node_color("name") == "#f39c12"
        assert exporter._get_node_color("location") == "#1abc9c"
        assert exporter._get_node_color("dark_web") == "#34495e"
        assert exporter._get_node_color("unknown") == "#95a5a6"  # Default

    def test_filter_graph_by_confidence(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test filtering graph by minimum confidence."""
        filtered = exporter.filter_graph(sample_graph_data, min_confidence=0.75)

        # Should keep nodes with confidence >= 0.75
        assert len(filtered["nodes"]) == 2  # email (0.9) and username (0.8)
        assert len(filtered["edges"]) == 1  # Only edge between remaining nodes

    def test_filter_graph_by_source_type(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test filtering graph by source type."""
        filtered = exporter.filter_graph(sample_graph_data, source_types=["email", "username"])

        # Should keep only email and username nodes
        assert len(filtered["nodes"]) == 2
        assert len(filtered["edges"]) == 1

        # Check that phone node is removed
        node_ids = [n["id"] for n in filtered["nodes"]]
        assert "phone:+1234567890" not in node_ids

    def test_filter_graph_by_max_nodes(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test limiting number of nodes."""
        filtered = exporter.filter_graph(sample_graph_data, max_nodes=2)

        # Should keep top 2 nodes by confidence
        assert len(filtered["nodes"]) == 2

        # Should be email (0.9) and username (0.8)
        node_ids = [n["id"] for n in filtered["nodes"]]
        assert "email:test@example.com" in node_ids
        assert "username:testuser" in node_ids
        assert "phone:+1234567890" not in node_ids

    def test_filter_graph_combined(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test filtering with multiple criteria."""
        filtered = exporter.filter_graph(
            sample_graph_data, min_confidence=0.75, source_types=["email"], max_nodes=1
        )

        # Should keep only email node (highest confidence email)
        assert len(filtered["nodes"]) == 1
        assert filtered["nodes"][0]["id"] == "email:test@example.com"
        assert len(filtered["edges"]) == 0  # No valid edges

    def test_filter_graph_preserves_statistics(
        self, exporter: GraphExporter, sample_graph_data: Dict[str, Any]
    ) -> None:
        """Test that filtering preserves statistics."""
        filtered = exporter.filter_graph(sample_graph_data, min_confidence=0.8)

        assert "statistics" in filtered
        assert filtered["statistics"] == sample_graph_data["statistics"]

    def test_export_empty_graph(self, exporter: GraphExporter) -> None:
        """Test exporting an empty graph."""
        empty_data = {"nodes": [], "edges": [], "statistics": {}}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "empty.gexf"

            success = exporter.export_to_gephi(empty_data, str(output_path))

            assert success is True
            assert output_path.exists()

    def test_export_handles_errors(self, exporter: GraphExporter) -> None:
        """Test that export handles errors gracefully."""
        invalid_data = {"nodes": "not a list"}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "invalid.gexf"

            # Should not crash
            success = exporter.export_to_gephi(invalid_data, str(output_path))

            # May succeed or fail depending on error handling
            assert isinstance(success, bool)
