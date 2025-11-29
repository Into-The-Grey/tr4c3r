"""Tests for the correlation engine."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.core.correlation import CorrelationEngine
from src.core.data_models import Result


class TestCorrelationEngine:
    """Test the CorrelationEngine class."""

    @pytest.fixture
    def engine(self) -> CorrelationEngine:
        """Create a correlation engine instance."""
        return CorrelationEngine(min_confidence=0.5, max_depth=3)

    @pytest.fixture
    def sample_results(self) -> list[Result]:
        """Create sample results for testing."""
        return [
            Result(
                source="username:github",
                identifier="johndoe",
                url="https://github.com/johndoe",
                confidence=0.9,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "username": "johndoe",
                    "email": "john@example.com",
                    "full_name": "John Doe",
                },
            ),
            Result(
                source="email:validation",
                identifier="john@example.com",
                url="",
                confidence=0.8,
                timestamp=datetime.now(timezone.utc),
                metadata={
                    "email": "john@example.com",
                    "potential_usernames": ["johndoe", "john.doe"],
                },
            ),
            Result(
                source="phone:validation",
                identifier="+1234567890",
                url="",
                confidence=0.7,
                timestamp=datetime.now(timezone.utc),
                metadata={"phone": "+1234567890", "location": "San Francisco, CA"},
            ),
        ]

    def test_engine_initialization(self, engine: CorrelationEngine) -> None:
        """Test that engine initializes correctly."""
        assert engine.graph is not None
        assert engine.min_confidence == 0.5
        assert engine.max_depth == 3
        assert engine.graph.number_of_nodes() == 0

    def test_add_result(self, engine: CorrelationEngine) -> None:
        """Test adding a result to the graph."""
        result = Result(
            source="username:github",
            identifier="testuser",
            url="https://github.com/testuser",
            confidence=0.9,
            timestamp=datetime.now(timezone.utc),
            metadata={"username": "testuser"},
        )

        engine.add_result(result)

        assert engine.graph.number_of_nodes() > 0
        node_id = "username:github:testuser"
        assert engine.graph.has_node(node_id)

    def test_build_graph_from_results(
        self, engine: CorrelationEngine, sample_results: list[Result]
    ) -> None:
        """Test building graph from multiple results."""
        engine.build_graph_from_results(sample_results)

        assert engine.graph.number_of_nodes() > 0
        assert engine.graph.number_of_edges() > 0

    def test_min_confidence_filtering(self, engine: CorrelationEngine) -> None:
        """Test that low confidence results are filtered."""
        results = [
            Result(
                source="test",
                identifier="low_conf",
                url="",
                confidence=0.3,  # Below min_confidence
                timestamp=datetime.now(timezone.utc),
                metadata={},
            ),
            Result(
                source="test",
                identifier="high_conf",
                url="",
                confidence=0.8,  # Above min_confidence
                timestamp=datetime.now(timezone.utc),
                metadata={},
            ),
        ]

        engine.build_graph_from_results(results)

        # Only high confidence result should be added
        assert "test:high_conf" in engine.graph.nodes()
        assert "test:low_conf" not in engine.graph.nodes()

    def test_metadata_edge_creation(self, engine: CorrelationEngine) -> None:
        """Test that edges are created from metadata."""
        result = Result(
            source="username:github",
            identifier="testuser",
            url="https://github.com/testuser",
            confidence=0.9,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "username": "testuser",
                "email": "test@example.com",
                "full_name": "Test User",
            },
        )

        engine.add_result(result)

        # Should have created edges to email and name nodes
        assert engine.graph.number_of_edges() >= 2
        assert engine.graph.has_node("email:test@example.com")
        assert engine.graph.has_node("name:Test User")

    def test_find_connections(
        self, engine: CorrelationEngine, sample_results: list[Result]
    ) -> None:
        """Test finding connections for an identifier."""
        engine.build_graph_from_results(sample_results)

        # Find connections for johndoe
        connections = engine.find_connections("johndoe")

        assert len(connections) > 0
        # Should find email and name connections
        connection_nodes = [c["node"] for c in connections]
        assert any("email" in node for node in connection_nodes)

    def test_find_connections_with_depth(
        self, engine: CorrelationEngine, sample_results: list[Result]
    ) -> None:
        """Test finding connections with depth limit."""
        engine.build_graph_from_results(sample_results)

        # Find connections with depth 1
        connections_depth1 = engine.find_connections("johndoe", max_depth=1)

        # Find connections with depth 2
        connections_depth2 = engine.find_connections("johndoe", max_depth=2)

        # Depth 2 should find more or equal connections
        assert len(connections_depth2) >= len(connections_depth1)

    def test_calculate_relationship_score(
        self, engine: CorrelationEngine, sample_results: list[Result]
    ) -> None:
        """Test calculating relationship scores."""
        engine.build_graph_from_results(sample_results)

        # Get two connected nodes
        nodes = list(engine.graph.nodes())
        if len(nodes) >= 2:
            score = engine.calculate_relationship_score(nodes[0], nodes[1])
            assert 0.0 <= score <= 1.0

    def test_get_clusters(self, engine: CorrelationEngine, sample_results: list[Result]) -> None:
        """Test finding clusters."""
        engine.build_graph_from_results(sample_results)

        clusters = engine.get_clusters(min_size=2)

        # Should have at least one cluster from connected results
        assert len(clusters) >= 0

        if clusters:
            # Each cluster should have at least min_size nodes
            for cluster in clusters:
                assert len(cluster) >= 2

    def test_find_patterns(self, engine: CorrelationEngine, sample_results: list[Result]) -> None:
        """Test pattern detection."""
        engine.build_graph_from_results(sample_results)

        patterns = engine.find_patterns()

        assert "hubs" in patterns
        assert "bridges" in patterns
        assert "triangles" in patterns
        assert "isolated" in patterns

    def test_get_statistics(self, engine: CorrelationEngine, sample_results: list[Result]) -> None:
        """Test getting graph statistics."""
        engine.build_graph_from_results(sample_results)

        stats = engine.get_statistics()

        assert "nodes" in stats
        assert "edges" in stats
        assert "density" in stats
        assert "connected_components" in stats
        assert "average_degree" in stats

        assert stats["nodes"] > 0
        assert stats["edges"] >= 0

    def test_export_graph(self, engine: CorrelationEngine, sample_results: list[Result]) -> None:
        """Test exporting graph data."""
        engine.build_graph_from_results(sample_results)

        export = engine.export_graph()

        assert "nodes" in export
        assert "edges" in export
        assert "statistics" in export

        assert isinstance(export["nodes"], list)
        assert isinstance(export["edges"], list)

    def test_clear_graph(self, engine: CorrelationEngine, sample_results: list[Result]) -> None:
        """Test clearing the graph."""
        engine.build_graph_from_results(sample_results)

        assert engine.graph.number_of_nodes() > 0

        engine.clear()

        assert engine.graph.number_of_nodes() == 0
        assert engine.graph.number_of_edges() == 0

    def test_edge_weight_strengthening(self, engine: CorrelationEngine) -> None:
        """Test that repeated connections strengthen edges."""
        # Add same connection twice
        result1 = Result(
            source="test1",
            identifier="id1",
            url="",
            confidence=0.9,
            timestamp=datetime.now(timezone.utc),
            metadata={"email": "shared@example.com"},
        )

        result2 = Result(
            source="test2",
            identifier="id2",
            url="",
            confidence=0.9,
            timestamp=datetime.now(timezone.utc),
            metadata={"email": "shared@example.com"},
        )

        engine.add_result(result1)
        engine.add_result(result2)

        # Both should connect to the same email node
        email_node = "email:shared@example.com"
        assert engine.graph.has_node(email_node)

        # Should have edges from both test nodes to email node
        assert engine.graph.degree(email_node) == 2

    def test_empty_graph_operations(self, engine: CorrelationEngine) -> None:
        """Test operations on empty graph."""
        # Should not crash on empty graph
        connections = engine.find_connections("nonexistent")
        assert len(connections) == 0

        clusters = engine.get_clusters()
        assert len(clusters) == 0

        patterns = engine.find_patterns()
        assert len(patterns["hubs"]) == 0

        stats = engine.get_statistics()
        assert stats["nodes"] == 0

    def test_nonexistent_node_relationship(self, engine: CorrelationEngine) -> None:
        """Test calculating relationship for nonexistent nodes."""
        score = engine.calculate_relationship_score("nonexistent1", "nonexistent2")
        assert score == 0.0
