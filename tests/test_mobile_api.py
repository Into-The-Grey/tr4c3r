"""Tests for mobile API endpoints and features.

Tests cover:
- Mobile-optimized search endpoints
- Threat intelligence feed
- Push notification system
- Offline mode capabilities
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

from src.api.mobile import (
    MobileSearchRequest,
    MobileResult,
    MobileSearchResponse,
    ThreatIndicator,
    ThreatFeedRequest,
    ThreatIntelligenceFeed,
    PushNotification,
    PushSubscription,
    PushPreferences,
    PushNotificationManager,
    OfflineCache,
    OfflineSyncRequest,
    OfflineManager,
    ThreatLevel,
    ThreatCategory,
    NotificationType,
    Priority,
)


class TestMobileSearch:
    """Test mobile-optimized search functionality."""

    def test_mobile_search_request(self):
        """Test mobile search request model."""
        request = MobileSearchRequest(
            query="test@example.com", search_type="email", max_results=20, include_metadata=True
        )

        assert request.query == "test@example.com"
        assert request.search_type == "email"
        assert request.max_results == 20
        assert request.include_metadata is True

    def test_mobile_result(self):
        """Test mobile result model."""
        result = MobileResult(
            id="email_1",
            source="haveibeenpwned",
            identifier="test@example.com",
            url="https://haveibeenpwned.com/...",
            confidence=0.95,
            snippet="Found in data breach",
            timestamp=datetime.now(),
        )

        assert result.id == "email_1"
        assert result.source == "haveibeenpwned"
        assert result.confidence == 0.95

    def test_mobile_search_response(self):
        """Test mobile search response model."""
        results = [
            MobileResult(
                id=f"result_{i}",
                source="test",
                identifier=f"user{i}",
                url=None,
                confidence=0.8,
                snippet="Test result",
                timestamp=datetime.now(),
            )
            for i in range(5)
        ]

        response = MobileSearchResponse(
            search_id="search_123",
            query="testuser",
            total_results=10,
            results=results,
            has_more=True,
            execution_time=0.5,
        )

        assert response.search_id == "search_123"
        assert response.total_results == 10
        assert len(response.results) == 5
        assert response.has_more is True
        assert response.execution_time == 0.5


class TestThreatIntelligence:
    """Test threat intelligence feed functionality."""

    @pytest.fixture
    def threat_feed(self):
        """Create threat feed instance."""
        return ThreatIntelligenceFeed()

    @pytest.fixture
    def sample_threat(self):
        """Create sample threat indicator."""
        return ThreatIndicator(
            indicator_type="email",
            value="malicious@example.com",
            threat_level=ThreatLevel.HIGH,
            category=ThreatCategory.PHISHING,
            description="Phishing campaign detected",
            first_seen=datetime.now() - timedelta(days=7),
            last_seen=datetime.now(),
            source="threat_intel_provider",
            confidence=0.95,
            tags=["phishing", "credential-theft"],
            references=["https://example.com/report"],
        )

    def test_threat_indicator_model(self, sample_threat):
        """Test threat indicator model."""
        assert sample_threat.indicator_type == "email"
        assert sample_threat.value == "malicious@example.com"
        assert sample_threat.threat_level == ThreatLevel.HIGH
        assert sample_threat.category == ThreatCategory.PHISHING
        assert sample_threat.confidence == 0.95
        assert len(sample_threat.tags) == 2

    def test_add_threat(self, threat_feed, sample_threat):
        """Test adding threat to feed."""
        threat_feed.add_threat(sample_threat)

        # Check threat was added
        result = threat_feed.check_indicator("email", "malicious@example.com")
        assert result is not None
        assert result.value == "malicious@example.com"

    def test_check_indicator_found(self, threat_feed, sample_threat):
        """Test checking indicator that exists."""
        threat_feed.add_threat(sample_threat)

        result = threat_feed.check_indicator("email", "malicious@example.com")
        assert result is not None
        assert result.threat_level == ThreatLevel.HIGH

    def test_check_indicator_not_found(self, threat_feed):
        """Test checking indicator that doesn't exist."""
        result = threat_feed.check_indicator("email", "safe@example.com")
        assert result is None

    def test_get_threats_all(self, threat_feed, sample_threat):
        """Test getting all threats."""
        threat_feed.add_threat(sample_threat)

        threats = threat_feed.get_threats()
        assert len(threats) == 1
        assert threats[0].value == "malicious@example.com"

    def test_get_threats_by_level(self, threat_feed):
        """Test filtering threats by level."""
        high_threat = ThreatIndicator(
            indicator_type="ip",
            value="1.2.3.4",
            threat_level=ThreatLevel.HIGH,
            category=ThreatCategory.MALWARE,
            description="Malware C2",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9,
        )

        low_threat = ThreatIndicator(
            indicator_type="domain",
            value="suspicious.com",
            threat_level=ThreatLevel.LOW,
            category=ThreatCategory.SUSPICIOUS_ACTIVITY,
            description="Low priority",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.5,
        )

        threat_feed.add_threat(high_threat)
        threat_feed.add_threat(low_threat)

        high_only = threat_feed.get_threats(threat_levels=[ThreatLevel.HIGH])
        assert len(high_only) == 1
        assert high_only[0].threat_level == ThreatLevel.HIGH

    def test_get_threats_by_category(self, threat_feed, sample_threat):
        """Test filtering threats by category."""
        threat_feed.add_threat(sample_threat)

        phishing = threat_feed.get_threats(categories=[ThreatCategory.PHISHING])
        assert len(phishing) == 1
        assert phishing[0].category == ThreatCategory.PHISHING

    def test_get_threats_by_type(self, threat_feed, sample_threat):
        """Test filtering threats by indicator type."""
        threat_feed.add_threat(sample_threat)

        emails = threat_feed.get_threats(indicator_types=["email"])
        assert len(emails) == 1
        assert emails[0].indicator_type == "email"

    def test_get_threats_since(self, threat_feed):
        """Test filtering threats by time."""
        old_threat = ThreatIndicator(
            indicator_type="hash",
            value="abc123",
            threat_level=ThreatLevel.MEDIUM,
            category=ThreatCategory.MALWARE,
            description="Old malware",
            first_seen=datetime.now() - timedelta(days=30),
            last_seen=datetime.now() - timedelta(days=20),
            source="test",
            confidence=0.8,
        )

        threat_feed.add_threat(old_threat)

        # Get threats from last 10 days
        since = datetime.now() - timedelta(days=10)
        recent = threat_feed.get_threats(since=since)
        assert len(recent) == 0  # Old threat should be filtered out

    def test_update_threat(self, threat_feed, sample_threat):
        """Test updating existing threat."""
        threat_feed.add_threat(sample_threat)

        success = threat_feed.update_threat(
            "email", "malicious@example.com", threat_level=ThreatLevel.CRITICAL
        )

        assert success is True
        updated = threat_feed.check_indicator("email", "malicious@example.com")
        assert updated.threat_level == ThreatLevel.CRITICAL

    def test_update_nonexistent_threat(self, threat_feed):
        """Test updating threat that doesn't exist."""
        success = threat_feed.update_threat(
            "email", "nonexistent@example.com", threat_level=ThreatLevel.HIGH
        )

        assert success is False

    def test_get_statistics(self, threat_feed):
        """Test threat feed statistics."""
        # Add multiple threats
        threats = [
            ThreatIndicator(
                indicator_type="email",
                value=f"threat{i}@example.com",
                threat_level=ThreatLevel.HIGH if i % 2 == 0 else ThreatLevel.LOW,
                category=ThreatCategory.PHISHING if i % 2 == 0 else ThreatCategory.MALWARE,
                description="Test",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                source="test",
                confidence=0.8,
            )
            for i in range(4)
        ]

        for threat in threats:
            threat_feed.add_threat(threat)

        stats = threat_feed.get_statistics()
        assert stats["total_threats"] == 4
        assert "by_level" in stats
        assert "by_category" in stats
        assert "by_type" in stats


class TestPushNotifications:
    """Test push notification system."""

    @pytest.fixture
    def push_manager(self):
        """Create push notification manager."""
        return PushNotificationManager()

    @pytest.fixture
    def subscription(self):
        """Create sample subscription."""
        return PushSubscription(
            user_id="user123",
            device_token="device_abc",
            device_type="ios",
            enabled=True,
            notification_types=[NotificationType.THREAT_ALERT, NotificationType.SEARCH_COMPLETE],
        )

    @pytest.fixture
    def notification(self):
        """Create sample notification."""
        return PushNotification(
            notification_id="notif_123",
            notification_type=NotificationType.THREAT_ALERT,
            priority=Priority.HIGH,
            title="Security Alert",
            body="Threat detected in your search",
            data={"threat_id": "123"},
            action_url="tr4c3r://threats/123",
            created_at=datetime.now(),
        )

    def test_subscription_model(self, subscription):
        """Test push subscription model."""
        assert subscription.user_id == "user123"
        assert subscription.device_token == "device_abc"
        assert subscription.device_type == "ios"
        assert subscription.enabled is True
        assert len(subscription.notification_types) == 2

    def test_notification_model(self, notification):
        """Test push notification model."""
        assert notification.notification_id == "notif_123"
        assert notification.notification_type == NotificationType.THREAT_ALERT
        assert notification.priority == Priority.HIGH
        assert notification.title == "Security Alert"

    def test_subscribe(self, push_manager, subscription):
        """Test device subscription."""
        success = push_manager.subscribe(subscription)
        assert success is True

    def test_unsubscribe(self, push_manager, subscription):
        """Test device unsubscription."""
        push_manager.subscribe(subscription)

        success = push_manager.unsubscribe("user123", "device_abc")
        assert success is True

    def test_unsubscribe_nonexistent(self, push_manager):
        """Test unsubscribing non-existent device."""
        success = push_manager.unsubscribe("user123", "nonexistent")
        assert success is False

    def test_set_preferences(self, push_manager):
        """Test setting user preferences."""
        preferences = PushPreferences(
            enabled=True,
            quiet_hours_start=22,
            quiet_hours_end=7,
            notification_types=[NotificationType.THREAT_ALERT],
            priority_filter=Priority.HIGH,
        )

        push_manager.set_preferences("user123", preferences)

        retrieved = push_manager.get_preferences("user123")
        assert retrieved.enabled is True
        assert retrieved.quiet_hours_start == 22

    def test_get_default_preferences(self, push_manager):
        """Test getting default preferences for new user."""
        preferences = push_manager.get_preferences("newuser")
        assert preferences.enabled is True  # Default

    def test_send_notification(self, push_manager, subscription, notification):
        """Test sending notification."""
        push_manager.subscribe(subscription)

        count = push_manager.send_notification("user123", notification)
        assert count == 1  # One device

    def test_send_notification_disabled(self, push_manager, subscription, notification):
        """Test notification not sent when disabled."""
        push_manager.subscribe(subscription)

        # Disable notifications
        prefs = PushPreferences(enabled=False)
        push_manager.set_preferences("user123", prefs)

        count = push_manager.send_notification("user123", notification)
        assert count == 0  # No devices notified

    def test_send_notification_type_filter(self, push_manager, subscription):
        """Test notification filtered by type."""
        push_manager.subscribe(subscription)

        # Set preferences to only allow SEARCH_COMPLETE
        prefs = PushPreferences(enabled=True, notification_types=[NotificationType.SEARCH_COMPLETE])
        push_manager.set_preferences("user123", prefs)

        # Try to send THREAT_ALERT (not in allowed types)
        notification = PushNotification(
            notification_id="notif_123",
            notification_type=NotificationType.THREAT_ALERT,
            priority=Priority.HIGH,
            title="Test",
            body="Test",
            created_at=datetime.now(),
        )

        count = push_manager.send_notification("user123", notification)
        assert count == 0  # Filtered out

    def test_send_notification_priority_filter(self, push_manager, subscription):
        """Test notification filtered by priority."""
        push_manager.subscribe(subscription)

        # Set minimum priority to HIGH
        prefs = PushPreferences(enabled=True, priority_filter=Priority.HIGH)
        push_manager.set_preferences("user123", prefs)

        # Try to send LOW priority notification
        notification = PushNotification(
            notification_id="notif_123",
            notification_type=NotificationType.SEARCH_COMPLETE,
            priority=Priority.LOW,
            title="Test",
            body="Test",
            created_at=datetime.now(),
        )

        count = push_manager.send_notification("user123", notification)
        assert count == 0  # Priority too low

    def test_get_notifications(self, push_manager, subscription, notification):
        """Test retrieving notifications."""
        push_manager.subscribe(subscription)
        push_manager.send_notification("user123", notification)

        notifications = push_manager.get_notifications("user123")
        assert len(notifications) == 1
        assert notifications[0].notification_id == "notif_123"

    def test_get_notifications_with_limit(self, push_manager, subscription):
        """Test retrieving notifications with limit."""
        push_manager.subscribe(subscription)

        # Send multiple notifications
        for i in range(10):
            notif = PushNotification(
                notification_id=f"notif_{i}",
                notification_type=NotificationType.SEARCH_COMPLETE,
                priority=Priority.NORMAL,
                title=f"Notification {i}",
                body="Test",
                created_at=datetime.now(),
            )
            push_manager.send_notification("user123", notif)

        notifications = push_manager.get_notifications("user123", limit=5)
        assert len(notifications) == 5


class TestOfflineMode:
    """Test offline mode functionality."""

    @pytest.fixture
    def offline_manager(self):
        """Create offline manager instance."""
        return OfflineManager()

    @pytest.fixture
    def cache_entry(self):
        """Create sample cache entry."""
        return OfflineCache(
            cache_key="search_123",
            cache_type="search",
            data={"query": "test", "results": []},
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24),
            size_bytes=1024,
        )

    def test_cache_model(self, cache_entry):
        """Test cache entry model."""
        assert cache_entry.cache_key == "search_123"
        assert cache_entry.cache_type == "search"
        assert cache_entry.size_bytes == 1024

    def test_add_cache(self, offline_manager, cache_entry):
        """Test adding cache entry."""
        offline_manager.add_cache(cache_entry)

        retrieved = offline_manager.get_cache("search_123")
        assert retrieved is not None
        assert retrieved.cache_key == "search_123"

    def test_get_cache_not_found(self, offline_manager):
        """Test getting non-existent cache."""
        result = offline_manager.get_cache("nonexistent")
        assert result is None

    def test_get_cache_expired(self, offline_manager):
        """Test getting expired cache."""
        expired_cache = OfflineCache(
            cache_key="expired_123",
            cache_type="search",
            data={"test": "data"},
            created_at=datetime.now() - timedelta(days=2),
            expires_at=datetime.now() - timedelta(days=1),  # Expired
            size_bytes=512,
        )

        offline_manager.add_cache(expired_cache)

        result = offline_manager.get_cache("expired_123")
        assert result is None  # Should be None because expired

    def test_sync_data_all(self, offline_manager):
        """Test syncing all data."""
        # Add multiple cache entries
        for i in range(5):
            cache = OfflineCache(
                cache_key=f"cache_{i}",
                cache_type="search",
                data={"id": i},
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=24),
                size_bytes=1024,
            )
            offline_manager.add_cache(cache)

        results = offline_manager.sync_data()
        assert len(results) == 5

    def test_sync_data_with_keys(self, offline_manager):
        """Test syncing specific keys."""
        # Add cache entries
        for i in range(5):
            cache = OfflineCache(
                cache_key=f"cache_{i}",
                cache_type="search",
                data={"id": i},
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=24),
                size_bytes=1024,
            )
            offline_manager.add_cache(cache)

        # Sync only specific keys
        results = offline_manager.sync_data(cache_keys=["cache_1", "cache_3"])
        assert len(results) == 2

    def test_sync_data_size_limit(self, offline_manager):
        """Test syncing with size limit."""
        # Add large cache entries (each 10MB)
        for i in range(10):
            cache = OfflineCache(
                cache_key=f"large_cache_{i}",
                cache_type="search",
                data={"id": i},
                created_at=datetime.now(),
                expires_at=datetime.now() + timedelta(hours=24),
                size_bytes=10 * 1024 * 1024,  # 10MB
            )
            offline_manager.add_cache(cache)

        # Limit to 25MB (should get only 2 entries)
        results = offline_manager.sync_data(max_size_mb=25)
        assert len(results) <= 3  # Max 2-3 entries within 25MB

    def test_cleanup_expired(self, offline_manager):
        """Test cleaning up expired cache."""
        # Add expired entries
        for i in range(3):
            cache = OfflineCache(
                cache_key=f"expired_{i}",
                cache_type="search",
                data={"id": i},
                created_at=datetime.now() - timedelta(days=2),
                expires_at=datetime.now() - timedelta(days=1),
                size_bytes=1024,
            )
            offline_manager.add_cache(cache)

        # Add valid entry
        valid_cache = OfflineCache(
            cache_key="valid",
            cache_type="search",
            data={"id": "valid"},
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24),
            size_bytes=1024,
        )
        offline_manager.add_cache(valid_cache)

        removed = offline_manager.cleanup_expired()
        assert removed == 3  # 3 expired entries removed

        # Valid entry should still be there
        assert offline_manager.get_cache("valid") is not None

    def test_get_cache_size(self, offline_manager):
        """Test cache size statistics."""
        # Add entries of different types
        search_cache = OfflineCache(
            cache_key="search_1",
            cache_type="search",
            data={},
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24),
            size_bytes=2048,
        )

        result_cache = OfflineCache(
            cache_key="result_1",
            cache_type="result",
            data={},
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(hours=24),
            size_bytes=4096,
        )

        offline_manager.add_cache(search_cache)
        offline_manager.add_cache(result_cache)

        stats = offline_manager.get_cache_size()
        assert stats["total_entries"] == 2
        assert stats["total_size_mb"] > 0
        assert "by_type" in stats
        assert stats["by_type"]["search"] == 1
        assert stats["by_type"]["result"] == 1
