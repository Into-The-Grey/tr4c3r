"""Mobile-optimized API endpoints for TR4C3R.

Provides lightweight, mobile-friendly endpoints with:
- Reduced payload sizes
- Threat intelligence feed
- Push notification support
- Offline mode capabilities
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from enum import Enum

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ThreatLevel(str, Enum):
    """Threat severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatCategory(str, Enum):
    """Threat intelligence categories."""

    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    CREDENTIAL_LEAK = "credential_leak"
    DARKWEB_MENTION = "darkweb_mention"
    REPUTATION = "reputation"
    VULNERABILITY = "vulnerability"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"


class NotificationType(str, Enum):
    """Push notification types."""

    SEARCH_COMPLETE = "search_complete"
    NEW_RESULT = "new_result"
    THREAT_ALERT = "threat_alert"
    CORRELATION_FOUND = "correlation_found"
    SYSTEM = "system"


class Priority(str, Enum):
    """Notification priority levels."""

    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


# Mobile-optimized models (lightweight)
class MobileSearchRequest(BaseModel):
    """Lightweight search request for mobile."""

    query: str = Field(..., description="Search query")
    search_type: str = Field(..., description="Type: email, phone, username, name")
    max_results: int = Field(default=20, ge=1, le=100, description="Max results")
    include_metadata: bool = Field(default=False, description="Include full metadata")


class MobileResult(BaseModel):
    """Lightweight result for mobile."""

    id: str = Field(..., description="Result ID")
    source: str = Field(..., description="Source platform")
    identifier: str = Field(..., description="Username, email, etc.")
    url: Optional[str] = Field(None, description="Profile URL")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    snippet: Optional[str] = Field(None, description="Brief description")
    timestamp: datetime = Field(..., description="When found")


class MobileSearchResponse(BaseModel):
    """Lightweight search response for mobile."""

    search_id: str = Field(..., description="Search ID")
    query: str = Field(..., description="Original query")
    total_results: int = Field(..., description="Total results found")
    results: List[MobileResult] = Field(..., description="Results (paginated)")
    has_more: bool = Field(..., description="More results available")
    execution_time: float = Field(..., description="Search time in seconds")


# Threat Intelligence models
class ThreatIndicator(BaseModel):
    """Threat intelligence indicator."""

    indicator_type: str = Field(..., description="IP, domain, email, hash, etc.")
    value: str = Field(..., description="Indicator value")
    threat_level: ThreatLevel = Field(..., description="Severity level")
    category: ThreatCategory = Field(..., description="Threat category")
    description: str = Field(..., description="Threat description")
    first_seen: datetime = Field(..., description="First detection time")
    last_seen: datetime = Field(..., description="Last detection time")
    source: str = Field(..., description="Intelligence source")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    tags: List[str] = Field(default_factory=list, description="Additional tags")
    references: List[str] = Field(default_factory=list, description="Reference URLs")


class ThreatFeedRequest(BaseModel):
    """Threat feed query request."""

    indicator: Optional[str] = Field(None, description="Specific indicator to check")
    indicator_types: Optional[List[str]] = Field(None, description="Filter by types")
    threat_levels: Optional[List[ThreatLevel]] = Field(None, description="Filter by levels")
    categories: Optional[List[ThreatCategory]] = Field(None, description="Filter by categories")
    since: Optional[datetime] = Field(None, description="Only threats since this time")
    limit: int = Field(default=50, ge=1, le=500, description="Max results")


class ThreatFeedResponse(BaseModel):
    """Threat feed response."""

    total_threats: int = Field(..., description="Total threats found")
    threats: List[ThreatIndicator] = Field(..., description="Threat indicators")
    last_updated: datetime = Field(..., description="Feed last update time")
    next_update: Optional[datetime] = Field(None, description="Next scheduled update")


# Push Notification models
class PushNotification(BaseModel):
    """Push notification payload."""

    notification_id: str = Field(..., description="Unique notification ID")
    notification_type: NotificationType = Field(..., description="Notification type")
    priority: Priority = Field(..., description="Notification priority")
    title: str = Field(..., max_length=100, description="Notification title")
    body: str = Field(..., max_length=500, description="Notification body")
    data: Optional[Dict[str, Any]] = Field(None, description="Additional data")
    action_url: Optional[str] = Field(None, description="Deep link URL")
    created_at: datetime = Field(..., description="Notification creation time")
    expires_at: Optional[datetime] = Field(None, description="Expiration time")


class PushSubscription(BaseModel):
    """Push notification subscription."""

    user_id: str = Field(..., description="User identifier")
    device_token: str = Field(..., description="Device push token")
    device_type: str = Field(..., description="ios, android, web")
    enabled: bool = Field(default=True, description="Subscription active")
    notification_types: List[NotificationType] = Field(
        default_factory=lambda: list(NotificationType), description="Subscribed notification types"
    )
    created_at: datetime = Field(default_factory=datetime.now, description="Subscription time")
    last_active: datetime = Field(default_factory=datetime.now, description="Last activity")


class PushPreferences(BaseModel):
    """User push notification preferences."""

    enabled: bool = Field(default=True, description="Notifications enabled")
    quiet_hours_start: Optional[int] = Field(None, ge=0, le=23, description="Quiet start hour")
    quiet_hours_end: Optional[int] = Field(None, ge=0, le=23, description="Quiet end hour")
    notification_types: List[NotificationType] = Field(
        default_factory=lambda: list(NotificationType), description="Enabled notification types"
    )
    priority_filter: Optional[Priority] = Field(None, description="Minimum priority")


# Offline Mode models
class OfflineCache(BaseModel):
    """Offline cache entry."""

    cache_key: str = Field(..., description="Cache key")
    cache_type: str = Field(..., description="search, result, graph, etc.")
    data: Dict[str, Any] = Field(..., description="Cached data")
    created_at: datetime = Field(..., description="Cache creation time")
    expires_at: datetime = Field(..., description="Cache expiration time")
    size_bytes: int = Field(..., description="Data size in bytes")


class OfflineSyncRequest(BaseModel):
    """Offline data sync request."""

    last_sync: Optional[datetime] = Field(None, description="Last sync time")
    cache_keys: Optional[List[str]] = Field(None, description="Specific keys to sync")
    max_size_mb: int = Field(default=50, ge=1, le=500, description="Max download size")


class OfflineSyncResponse(BaseModel):
    """Offline data sync response."""

    sync_id: str = Field(..., description="Sync session ID")
    synced_items: int = Field(..., description="Items synced")
    cache_entries: List[OfflineCache] = Field(..., description="Cache entries")
    total_size_mb: float = Field(..., description="Total size in MB")
    sync_time: datetime = Field(..., description="Sync completion time")
    next_sync: Optional[datetime] = Field(None, description="Suggested next sync")


class ThreatIntelligenceFeed:
    """Threat intelligence feed manager."""

    def __init__(self):
        """Initialize threat intelligence feed."""
        self.threats: Dict[str, ThreatIndicator] = {}
        self.last_update = datetime.now()
        logger.info("ThreatIntelligenceFeed initialized")

    def add_threat(self, threat: ThreatIndicator) -> None:
        """Add threat indicator to feed.

        Args:
            threat: Threat indicator to add
        """
        key = f"{threat.indicator_type}:{threat.value}"
        self.threats[key] = threat
        self.last_update = datetime.now()
        logger.info(f"Added threat indicator: {key} ({threat.threat_level})")

    def get_threats(
        self,
        indicator: Optional[str] = None,
        indicator_types: Optional[List[str]] = None,
        threat_levels: Optional[List[ThreatLevel]] = None,
        categories: Optional[List[ThreatCategory]] = None,
        since: Optional[datetime] = None,
        limit: int = 50,
    ) -> List[ThreatIndicator]:
        """Get threats matching filters.

        Args:
            indicator: Specific indicator to check
            indicator_types: Filter by indicator types
            threat_levels: Filter by threat levels
            categories: Filter by categories
            since: Only threats since this time
            limit: Maximum results

        Returns:
            List of matching threat indicators
        """
        results = []

        for threat in self.threats.values():
            # Specific indicator check
            if indicator and threat.value != indicator:
                continue

            # Type filter
            if indicator_types and threat.indicator_type not in indicator_types:
                continue

            # Threat level filter
            if threat_levels and threat.threat_level not in threat_levels:
                continue

            # Category filter
            if categories and threat.category not in categories:
                continue

            # Time filter
            if since and threat.last_seen < since:
                continue

            results.append(threat)

            if len(results) >= limit:
                break

        # Sort by threat level and last seen
        threat_order = {
            ThreatLevel.CRITICAL: 0,
            ThreatLevel.HIGH: 1,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 3,
            ThreatLevel.INFO: 4,
        }
        results.sort(key=lambda t: (threat_order[t.threat_level], -t.last_seen.timestamp()))

        return results

    def check_indicator(self, indicator_type: str, value: str) -> Optional[ThreatIndicator]:
        """Check if indicator is in threat feed.

        Args:
            indicator_type: Type of indicator
            value: Indicator value

        Returns:
            ThreatIndicator if found, None otherwise
        """
        key = f"{indicator_type}:{value}"
        return self.threats.get(key)

    def update_threat(self, indicator_type: str, value: str, **kwargs) -> bool:
        """Update existing threat indicator.

        Args:
            indicator_type: Type of indicator
            value: Indicator value
            **kwargs: Fields to update

        Returns:
            True if updated, False if not found
        """
        key = f"{indicator_type}:{value}"
        threat = self.threats.get(key)

        if not threat:
            return False

        # Update fields
        for field, new_value in kwargs.items():
            if hasattr(threat, field):
                setattr(threat, field, new_value)

        threat.last_seen = datetime.now()
        self.last_update = datetime.now()
        logger.info(f"Updated threat indicator: {key}")

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get threat feed statistics.

        Returns:
            Dictionary with statistics
        """
        by_level = {}
        by_category = {}
        by_type = {}

        for threat in self.threats.values():
            # By level
            level = threat.threat_level.value
            by_level[level] = by_level.get(level, 0) + 1

            # By category
            category = threat.category.value
            by_category[category] = by_category.get(category, 0) + 1

            # By type
            itype = threat.indicator_type
            by_type[itype] = by_type.get(itype, 0) + 1

        return {
            "total_threats": len(self.threats),
            "by_level": by_level,
            "by_category": by_category,
            "by_type": by_type,
            "last_update": self.last_update.isoformat(),
        }


class PushNotificationManager:
    """Push notification manager."""

    def __init__(self):
        """Initialize push notification manager."""
        self.subscriptions: Dict[str, PushSubscription] = {}
        self.notifications: List[PushNotification] = []
        self.preferences: Dict[str, PushPreferences] = {}
        logger.info("PushNotificationManager initialized")

    def subscribe(self, subscription: PushSubscription) -> bool:
        """Subscribe device for push notifications.

        Args:
            subscription: Push subscription details

        Returns:
            True if successful
        """
        key = f"{subscription.user_id}:{subscription.device_token}"
        self.subscriptions[key] = subscription
        logger.info(f"Device subscribed: {key}")
        return True

    def unsubscribe(self, user_id: str, device_token: str) -> bool:
        """Unsubscribe device from push notifications.

        Args:
            user_id: User identifier
            device_token: Device push token

        Returns:
            True if unsubscribed, False if not found
        """
        key = f"{user_id}:{device_token}"
        if key in self.subscriptions:
            del self.subscriptions[key]
            logger.info(f"Device unsubscribed: {key}")
            return True
        return False

    def set_preferences(self, user_id: str, preferences: PushPreferences) -> None:
        """Set user push preferences.

        Args:
            user_id: User identifier
            preferences: User preferences
        """
        self.preferences[user_id] = preferences
        logger.info(f"Preferences updated for user: {user_id}")

    def get_preferences(self, user_id: str) -> PushPreferences:
        """Get user push preferences.

        Args:
            user_id: User identifier

        Returns:
            User preferences or defaults
        """
        return self.preferences.get(user_id, PushPreferences())

    def send_notification(self, user_id: str, notification: PushNotification) -> int:
        """Send push notification to user's devices.

        Args:
            user_id: User identifier
            notification: Notification to send

        Returns:
            Number of devices notified
        """
        # Get user preferences
        prefs = self.get_preferences(user_id)

        # Check if notifications enabled
        if not prefs.enabled:
            logger.debug(f"Notifications disabled for user: {user_id}")
            return 0

        # Check notification type allowed
        if notification.notification_type not in prefs.notification_types:
            logger.debug(f"Notification type {notification.notification_type} not enabled")
            return 0

        # Check priority filter
        if prefs.priority_filter:
            priority_order = {Priority.HIGH: 2, Priority.NORMAL: 1, Priority.LOW: 0}
            if priority_order[notification.priority] < priority_order[prefs.priority_filter]:
                logger.debug(f"Notification priority too low")
                return 0

        # Check quiet hours
        now = datetime.now()
        if prefs.quiet_hours_start and prefs.quiet_hours_end:
            current_hour = now.hour
            if prefs.quiet_hours_start <= current_hour < prefs.quiet_hours_end:
                logger.debug(f"In quiet hours, skipping notification")
                return 0

        # Find user's subscriptions
        user_subs = [
            sub for key, sub in self.subscriptions.items() if sub.user_id == user_id and sub.enabled
        ]

        if not user_subs:
            logger.debug(f"No active subscriptions for user: {user_id}")
            return 0

        # Store notification
        self.notifications.append(notification)

        # Send to devices (in production, integrate with FCM/APNS)
        count = len(user_subs)
        logger.info(f"Sent notification to {count} devices for user: {user_id}")

        return count

    def get_notifications(
        self, user_id: str, since: Optional[datetime] = None, limit: int = 50
    ) -> List[PushNotification]:
        """Get notifications for user.

        Args:
            user_id: User identifier
            since: Only notifications since this time
            limit: Maximum results

        Returns:
            List of notifications
        """
        # Filter by user's subscriptions
        user_device_tokens = [
            sub.device_token for sub in self.subscriptions.values() if sub.user_id == user_id
        ]

        if not user_device_tokens:
            return []

        results = []
        for notif in reversed(self.notifications):  # Most recent first
            if since and notif.created_at < since:
                continue

            results.append(notif)

            if len(results) >= limit:
                break

        return results


class OfflineManager:
    """Offline mode data manager."""

    def __init__(self):
        """Initialize offline manager."""
        self.cache: Dict[str, OfflineCache] = {}
        logger.info("OfflineManager initialized")

    def add_cache(self, cache: OfflineCache) -> None:
        """Add cache entry.

        Args:
            cache: Cache entry to add
        """
        self.cache[cache.cache_key] = cache
        logger.info(f"Added cache entry: {cache.cache_key}")

    def get_cache(self, cache_key: str) -> Optional[OfflineCache]:
        """Get cache entry by key.

        Args:
            cache_key: Cache key

        Returns:
            Cache entry if found and not expired
        """
        entry = self.cache.get(cache_key)

        if not entry:
            return None

        # Check expiration
        if entry.expires_at < datetime.now():
            del self.cache[cache_key]
            logger.debug(f"Cache expired: {cache_key}")
            return None

        return entry

    def sync_data(
        self,
        last_sync: Optional[datetime] = None,
        cache_keys: Optional[List[str]] = None,
        max_size_mb: int = 50,
    ) -> List[OfflineCache]:
        """Sync data for offline use.

        Args:
            last_sync: Last sync time
            cache_keys: Specific keys to sync
            max_size_mb: Maximum download size

        Returns:
            List of cache entries
        """
        results = []
        total_size = 0
        max_size_bytes = max_size_mb * 1024 * 1024

        # Get cache entries
        for key, entry in self.cache.items():
            # Filter by keys if specified
            if cache_keys and key not in cache_keys:
                continue

            # Filter by last sync time
            if last_sync and entry.created_at <= last_sync:
                continue

            # Check size limit
            if total_size + entry.size_bytes > max_size_bytes:
                logger.debug(f"Size limit reached: {total_size / 1024 / 1024:.2f} MB")
                break

            results.append(entry)
            total_size += entry.size_bytes

        logger.info(f"Synced {len(results)} cache entries ({total_size / 1024 / 1024:.2f} MB)")
        return results

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        now = datetime.now()
        expired_keys = [key for key, entry in self.cache.items() if entry.expires_at < now]

        for key in expired_keys:
            del self.cache[key]

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")

        return len(expired_keys)

    def get_cache_size(self) -> Dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        total_entries = len(self.cache)
        total_size = sum(entry.size_bytes for entry in self.cache.values())
        by_type = {}

        for entry in self.cache.values():
            cache_type = entry.cache_type
            by_type[cache_type] = by_type.get(cache_type, 0) + 1

        return {
            "total_entries": total_entries,
            "total_size_mb": total_size / 1024 / 1024,
            "by_type": by_type,
        }
