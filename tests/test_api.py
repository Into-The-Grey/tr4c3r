"""Tests for TR4C3R Web API.

Tests FastAPI endpoints, authentication, search operations, correlations,
exports, and WebSocket functionality.
"""

import asyncio
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Import the FastAPI app
from src.api.main import app, db, correlation_engine
from src.core.data_models import Result


@pytest.fixture
def client():
    """Test client fixture."""
    return TestClient(app)


@pytest.fixture
def mock_token():
    """Mock authentication token."""
    return "demo_token"


@pytest.fixture
def auth_headers(mock_token):
    """Authentication headers."""
    return {"Authorization": f"Bearer {mock_token}"}


@pytest.fixture
def sample_results():
    """Sample search results."""
    return [
        Result(
            source="test_source",
            identifier="test@example.com",
            url="https://example.com/test",
            confidence=0.9,
            metadata={"found": True},
        ),
        Result(
            source="test_source2",
            identifier="test@example.com",
            url="https://example.com/test2",
            confidence=0.8,
            metadata={"found": True},
        ),
    ]


class TestHealthCheck:
    """Test health check endpoint."""

    def test_health_check(self, client):
        """Test health check returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["version"] == "1.0.0"


class TestAuthentication:
    """Test authentication."""

    def test_missing_auth_token(self, client):
        """Test request without auth token is rejected."""
        response = client.get("/api/v1/searches")
        assert response.status_code == 403

    def test_invalid_auth_token(self, client):
        """Test request with invalid token is rejected."""
        headers = {"Authorization": "Bearer invalid_token"}
        response = client.get("/api/v1/searches", headers=headers)
        assert response.status_code == 401

    def test_valid_auth_token(self, client, auth_headers):
        """Test request with valid token succeeds."""
        response = client.get("/api/v1/searches", headers=auth_headers)
        assert response.status_code == 200


class TestSearchEndpoints:
    """Test search endpoints."""

    @patch("src.api.main.EmailSearch")
    def test_email_search(self, mock_search_class, client, auth_headers, sample_results):
        """Test email search endpoint."""
        # Mock the search
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "test@example.com",
                "search_type": "email",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["identifier"] == "test@example.com"
        assert data["search_type"] == "email"
        assert data["result_count"] == 2
        assert "search_id" in data
        assert len(data["results"]) == 2

    @patch("src.api.main.PhoneSearch")
    def test_phone_search(self, mock_search_class, client, auth_headers):
        """Test phone search endpoint."""
        mock_search = AsyncMock()
        mock_search.search.return_value = []
        mock_search_class.return_value = mock_search

        response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "+1234567890",
                "search_type": "phone",
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert data["result_count"] == 0

    @patch("src.api.main.UsernameSearch")
    def test_username_search(self, mock_search_class, client, auth_headers):
        """Test username search endpoint."""
        mock_search = AsyncMock()
        mock_search.search.return_value = []
        mock_search_class.return_value = mock_search

        response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "testuser",
                "search_type": "username",
            },
        )

        assert response.status_code == 200

    @patch("src.api.main.SocialMediaSearch")
    def test_social_search(self, mock_search_class, client, auth_headers):
        """Test social media search endpoint."""
        mock_search = AsyncMock()
        mock_search.search.return_value = []
        mock_search_class.return_value = mock_search

        response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "testuser",
                "search_type": "social",
            },
        )

        assert response.status_code == 200

    def test_invalid_search_type(self, client, auth_headers):
        """Test invalid search type returns error."""
        response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "test",
                "search_type": "invalid_type",
            },
        )

        assert response.status_code == 400
        assert "Unsupported search type" in response.json()["detail"]

    @patch("src.api.main.EmailSearch")
    def test_list_searches(self, mock_search_class, client, auth_headers, sample_results):
        """Test listing recent searches."""
        # Create a search first
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "test@example.com",
                "search_type": "email",
            },
        )

        # List searches
        response = client.get("/api/v1/searches", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "searches" in data
        assert "count" in data

    @patch("src.api.main.EmailSearch")
    def test_get_search_by_id(self, mock_search_class, client, auth_headers, sample_results):
        """Test getting specific search by ID."""
        # Create a search
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        create_response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={
                "identifier": "test@example.com",
                "search_type": "email",
            },
        )
        search_id = create_response.json()["search_id"]

        # Get the search
        response = client.get(f"/api/v1/search/{search_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "search" in data
        assert "results" in data

    def test_get_nonexistent_search(self, client, auth_headers):
        """Test getting non-existent search returns 404."""
        response = client.get("/api/v1/search/99999", headers=auth_headers)
        assert response.status_code == 404


class TestCorrelationEndpoints:
    """Test correlation endpoints."""

    @patch("src.api.main.EmailSearch")
    def test_correlate_searches(self, mock_search_class, client, auth_headers, sample_results):
        """Test correlation analysis."""
        # Create searches
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        response1 = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={"identifier": "test1@example.com", "search_type": "email"},
        )
        search_id1 = response1.json()["search_id"]

        response2 = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={"identifier": "test2@example.com", "search_type": "email"},
        )
        search_id2 = response2.json()["search_id"]

        # Correlate
        response = client.post(
            "/api/v1/correlate",
            headers=auth_headers,
            json={
                "search_ids": [search_id1, search_id2],
                "min_confidence": 0.5,
            },
        )

        assert response.status_code == 200
        data = response.json()
        assert "statistics" in data
        assert "clusters" in data
        assert "patterns" in data
        assert "graph" in data

    def test_correlate_no_results(self, client, auth_headers):
        """Test correlation with no results."""
        response = client.post(
            "/api/v1/correlate",
            headers=auth_headers,
            json={"search_ids": [99999]},
        )

        assert response.status_code == 404

    @patch("src.api.main.EmailSearch")
    def test_find_connections(self, mock_search_class, client, auth_headers, sample_results):
        """Test finding connections for identifier."""
        # Create search
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={"identifier": "test@example.com", "search_type": "email"},
        )

        # Find connections
        response = client.post(
            "/api/v1/connections",
            headers=auth_headers,
            params={"identifier": "test@example.com", "max_depth": 2},
        )

        assert response.status_code == 200
        data = response.json()
        assert "identifier" in data
        assert "connections" in data
        assert "count" in data


class TestExportEndpoints:
    """Test export endpoints."""

    @patch("src.api.main.EmailSearch")
    def test_export_search_json(self, mock_search_class, client, auth_headers, sample_results):
        """Test exporting search results as JSON."""
        # Create search
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        create_response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={"identifier": "test@example.com", "search_type": "email"},
        )
        search_id = create_response.json()["search_id"]

        # Export
        response = client.post(
            "/api/v1/export/search",
            headers=auth_headers,
            json={"search_id": search_id, "format": "json"},
        )

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/octet-stream"

    @patch("src.api.main.EmailSearch")
    def test_export_search_csv(self, mock_search_class, client, auth_headers, sample_results):
        """Test exporting search results as CSV."""
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        create_response = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={"identifier": "test@example.com", "search_type": "email"},
        )
        search_id = create_response.json()["search_id"]

        response = client.post(
            "/api/v1/export/search",
            headers=auth_headers,
            json={"search_id": search_id, "format": "csv"},
        )

        assert response.status_code == 200

    @patch("src.api.main.EmailSearch")
    def test_export_graph_gexf(self, mock_search_class, client, auth_headers, sample_results):
        """Test exporting correlation graph as GEXF."""
        mock_search = AsyncMock()
        mock_search.search.return_value = sample_results
        mock_search_class.return_value = mock_search

        response1 = client.post(
            "/api/v1/search",
            headers=auth_headers,
            json={"identifier": "test@example.com", "search_type": "email"},
        )
        search_id = response1.json()["search_id"]

        # Export graph
        response = client.post(
            "/api/v1/export/graph",
            headers=auth_headers,
            json={
                "search_ids": [search_id],
                "format": "gexf",
                "output_filename": "test_graph.gexf",
            },
        )

        assert response.status_code == 200

    def test_export_graph_invalid_format(self, client, auth_headers):
        """Test export with invalid format."""
        response = client.post(
            "/api/v1/export/graph",
            headers=auth_headers,
            json={
                "search_ids": [1],
                "format": "invalid",
            },
        )

        assert response.status_code == 400


class TestStatistics:
    """Test statistics endpoint."""

    def test_get_statistics(self, client, auth_headers):
        """Test getting database statistics."""
        response = client.get("/api/v1/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_searches" in data
        assert "total_results" in data


class TestWebSocket:
    """Test WebSocket functionality."""

    def test_websocket_connection(self, client):
        """Test WebSocket connection."""
        with client.websocket_connect("/ws") as websocket:
            # Send ping
            websocket.send_text("ping")

            # Receive pong
            data = websocket.receive_json()
            assert data["type"] == "pong"
            assert "timestamp" in data

    @patch("src.api.main.EmailSearch")
    def test_websocket_broadcast(self, mock_search_class, client, auth_headers, sample_results):
        """Test WebSocket receives search updates."""
        # Connect WebSocket
        with client.websocket_connect("/ws") as websocket:
            # Perform search (will broadcast to WebSocket)
            mock_search = AsyncMock()
            mock_search.search.return_value = sample_results
            mock_search_class.return_value = mock_search

            # Note: In real scenario, would need async context
            # This test verifies the endpoint exists and accepts connections
            websocket.send_text("ping")
            data = websocket.receive_json()
            assert data["type"] == "pong"


class TestErrorHandling:
    """Test error handling."""

    def test_search_exception_handling(self, client, auth_headers):
        """Test search handles exceptions gracefully."""
        with patch("src.api.main.EmailSearch") as mock_class:
            mock_search = AsyncMock()
            mock_search.search.side_effect = Exception("Test error")
            mock_class.return_value = mock_search

            response = client.post(
                "/api/v1/search",
                headers=auth_headers,
                json={"identifier": "test@example.com", "search_type": "email"},
            )

            assert response.status_code == 500

    def test_correlation_exception_handling(self, client, auth_headers):
        """Test correlation handles exceptions gracefully."""
        with patch("src.storage.database.Database.get_search_results") as mock_get:
            mock_get.side_effect = Exception("Database error")

            response = client.post(
                "/api/v1/correlate",
                headers=auth_headers,
                json={"search_ids": [1]},
            )

            assert response.status_code == 500
