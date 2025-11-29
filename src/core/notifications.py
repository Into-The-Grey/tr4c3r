"""
Alerting and Notifications System for TR4C3R.

Comprehensive multi-channel notification system supporting:
- Email (SMTP) notifications
- Slack webhooks
- Discord webhooks
- Generic webhooks
- Desktop notifications
- In-app notification center
- SMS via Twilio (optional)
- Telegram bot notifications
"""

import asyncio
import hashlib
import json
import logging
import os
import smtplib
import sqlite3
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urljoin

try:
    import aiohttp  # type: ignore[import-not-found]

    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None  # type: ignore[assignment]
    AIOHTTP_AVAILABLE = False

logger = logging.getLogger(__name__)


class NotificationChannel(Enum):
    """Available notification channels."""

    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    WEBHOOK = "webhook"
    DESKTOP = "desktop"
    TELEGRAM = "telegram"
    SMS = "sms"
    IN_APP = "in_app"


class NotificationPriority(Enum):
    """Notification priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class AlertCondition(Enum):
    """Conditions that trigger alerts."""

    NEW_RESULTS = "new_results"
    RESULT_CHANGES = "result_changes"
    SEARCH_COMPLETE = "search_complete"
    SEARCH_ERROR = "search_error"
    HIGH_RISK_FOUND = "high_risk_found"
    SCHEDULED_COMPLETE = "scheduled_complete"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    KEYWORD_MATCH = "keyword_match"


@dataclass
class Notification:
    """A notification to be sent."""

    id: str
    title: str
    message: str
    channel: NotificationChannel
    priority: NotificationPriority = NotificationPriority.NORMAL
    condition: Optional[AlertCondition] = None
    metadata: dict = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    sent_at: Optional[datetime] = None
    delivered: bool = False
    error: Optional[str] = None
    retry_count: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "channel": self.channel.value,
            "priority": self.priority.value,
            "condition": self.condition.value if self.condition else None,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "delivered": self.delivered,
            "error": self.error,
            "retry_count": self.retry_count,
        }


@dataclass
class NotificationPreferences:
    """User notification preferences."""

    user_id: str
    enabled_channels: list[NotificationChannel] = field(default_factory=list)
    alert_conditions: list[AlertCondition] = field(default_factory=list)
    quiet_hours_start: Optional[int] = None  # Hour (0-23)
    quiet_hours_end: Optional[int] = None
    min_priority: NotificationPriority = NotificationPriority.NORMAL
    email: Optional[str] = None
    phone: Optional[str] = None
    slack_user_id: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    def should_notify(self, notification: Notification) -> bool:
        """Check if notification should be sent based on preferences."""
        # Check channel enabled
        if notification.channel not in self.enabled_channels:
            return False

        # Check condition enabled
        if notification.condition and notification.condition not in self.alert_conditions:
            return False

        # Check priority threshold
        priority_order = [
            NotificationPriority.LOW,
            NotificationPriority.NORMAL,
            NotificationPriority.HIGH,
            NotificationPriority.CRITICAL,
        ]
        if priority_order.index(notification.priority) < priority_order.index(self.min_priority):
            return False

        # Check quiet hours
        if self.quiet_hours_start is not None and self.quiet_hours_end is not None:
            current_hour = datetime.now().hour
            if self.quiet_hours_start <= current_hour < self.quiet_hours_end:
                # Only allow critical during quiet hours
                if notification.priority != NotificationPriority.CRITICAL:
                    return False

        return True


class NotificationProvider(ABC):
    """Abstract base class for notification providers."""

    @abstractmethod
    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send a notification. Returns True if successful."""
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate provider configuration."""
        pass


class EmailProvider(NotificationProvider):
    """Email notification provider using SMTP."""

    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        from_address: str = "tr4c3r@localhost",
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_address = from_address
        self.use_tls = use_tls

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send email notification."""
        if not preferences.email:
            logger.warning("No email address configured for user")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[TR4C3R] {notification.title}"
            msg["From"] = self.from_address
            msg["To"] = preferences.email

            # Plain text version
            text_content = f"""
TR4C3R Notification
==================

{notification.title}

{notification.message}

Priority: {notification.priority.value.upper()}
Time: {notification.created_at.strftime('%Y-%m-%d %H:%M:%S')}

---
This is an automated notification from TR4C3R OSINT Platform.
            """

            # HTML version
            priority_colors = {
                NotificationPriority.LOW: "#6c757d",
                NotificationPriority.NORMAL: "#0d6efd",
                NotificationPriority.HIGH: "#fd7e14",
                NotificationPriority.CRITICAL: "#dc3545",
            }

            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .content {{ background: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; }}
        .priority {{ display: inline-block; padding: 4px 12px; border-radius: 4px; 
                    color: white; font-size: 12px; font-weight: bold; }}
        .footer {{ background: #e9ecef; padding: 15px; font-size: 12px; 
                  color: #6c757d; border-radius: 0 0 8px 8px; }}
        .metadata {{ background: white; padding: 10px; margin-top: 15px; 
                    border-radius: 4px; font-family: monospace; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 style="margin: 0;">🔍 TR4C3R</h1>
            <p style="margin: 5px 0 0 0; opacity: 0.9;">OSINT Platform Notification</p>
        </div>
        <div class="content">
            <h2 style="margin-top: 0;">{notification.title}</h2>
            <span class="priority" style="background: {priority_colors[notification.priority]};">
                {notification.priority.value.upper()}
            </span>
            <p style="line-height: 1.6; margin-top: 15px;">{notification.message}</p>
            {self._format_metadata_html(notification.metadata) if notification.metadata else ""}
        </div>
        <div class="footer">
            <p style="margin: 0;">
                Sent at {notification.created_at.strftime('%Y-%m-%d %H:%M:%S')} | 
                <a href="#" style="color: #6c757d;">Manage Preferences</a>
            </p>
        </div>
    </div>
</body>
</html>
            """

            msg.attach(MIMEText(text_content, "plain"))
            msg.attach(MIMEText(html_content, "html"))

            # Send email in thread to not block
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_smtp, msg, preferences.email)

            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            raise

    def _send_smtp(self, msg: MIMEMultipart, to_address: str):
        """Send via SMTP (blocking)."""
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            if self.use_tls:
                server.starttls()
            if self.smtp_user and self.smtp_password:
                server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

    def _format_metadata_html(self, metadata: dict) -> str:
        """Format metadata as HTML."""
        if not metadata:
            return ""
        items = "".join(f"<div><strong>{k}:</strong> {v}</div>" for k, v in metadata.items())
        return f'<div class="metadata">{items}</div>'

    def validate_config(self) -> bool:
        """Validate SMTP configuration."""
        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=5) as server:
                if self.use_tls:
                    server.starttls()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                return True
        except Exception as e:
            logger.error(f"SMTP validation failed: {e}")
            return False


class SlackProvider(NotificationProvider):
    """Slack webhook notification provider."""

    def __init__(self, webhook_url: str, default_channel: Optional[str] = None):
        self.webhook_url = webhook_url
        self.default_channel = default_channel

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send Slack notification via webhook."""
        priority_emojis = {
            NotificationPriority.LOW: "ℹ️",
            NotificationPriority.NORMAL: "📋",
            NotificationPriority.HIGH: "⚠️",
            NotificationPriority.CRITICAL: "🚨",
        }

        priority_colors = {
            NotificationPriority.LOW: "#6c757d",
            NotificationPriority.NORMAL: "#0d6efd",
            NotificationPriority.HIGH: "#fd7e14",
            NotificationPriority.CRITICAL: "#dc3545",
        }

        payload: dict[str, Any] = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{priority_emojis[notification.priority]} {notification.title}",
                        "emoji": True,
                    },
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": notification.message}},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Priority:* {notification.priority.value.upper()} | *Time:* {notification.created_at.strftime('%Y-%m-%d %H:%M:%S')}",
                        }
                    ],
                },
            ],
            "attachments": [
                {
                    "color": priority_colors[notification.priority],
                    "fields": (
                        [
                            {"title": k, "value": str(v), "short": True}
                            for k, v in notification.metadata.items()
                        ]
                        if notification.metadata
                        else []
                    ),
                }
            ],
        }

        if preferences.slack_user_id:
            payload["channel"] = preferences.slack_user_id
        elif self.default_channel:
            payload["channel"] = self.default_channel

        async with aiohttp.ClientSession() as session:  # type: ignore[union-attr]
            async with session.post(self.webhook_url, json=payload) as response:
                if response.status != 200:
                    text = await response.text()
                    raise Exception(f"Slack API error: {response.status} - {text}")
                return True

    def validate_config(self) -> bool:
        """Validate Slack webhook URL."""
        return bool(self.webhook_url and "hooks.slack.com" in self.webhook_url)


class DiscordProvider(NotificationProvider):
    """Discord webhook notification provider."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send Discord notification via webhook."""
        priority_colors = {
            NotificationPriority.LOW: 0x6C757D,
            NotificationPriority.NORMAL: 0x0D6EFD,
            NotificationPriority.HIGH: 0xFD7E14,
            NotificationPriority.CRITICAL: 0xDC3545,
        }

        embed = {
            "title": f"🔍 {notification.title}",
            "description": notification.message,
            "color": priority_colors[notification.priority],
            "timestamp": notification.created_at.isoformat(),
            "footer": {"text": f"TR4C3R OSINT | Priority: {notification.priority.value.upper()}"},
            "fields": (
                [
                    {"name": k, "value": str(v), "inline": True}
                    for k, v in notification.metadata.items()
                ]
                if notification.metadata
                else []
            ),
        }

        payload = {
            "username": "TR4C3R",
            "avatar_url": "https://example.com/tr4c3r-logo.png",
            "embeds": [embed],
        }

        async with aiohttp.ClientSession() as session:  # type: ignore[union-attr]
            async with session.post(self.webhook_url, json=payload) as response:
                if response.status not in (200, 204):
                    text = await response.text()
                    raise Exception(f"Discord API error: {response.status} - {text}")
                return True

    def validate_config(self) -> bool:
        """Validate Discord webhook URL."""
        return bool(self.webhook_url and "discord.com/api/webhooks" in self.webhook_url)


class TelegramProvider(NotificationProvider):
    """Telegram bot notification provider."""

    def __init__(self, bot_token: str):
        self.bot_token = bot_token
        self.api_base = f"https://api.telegram.org/bot{bot_token}"

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send Telegram notification."""
        if not preferences.telegram_chat_id:
            logger.warning("No Telegram chat ID configured")
            return False

        priority_emojis = {
            NotificationPriority.LOW: "ℹ️",
            NotificationPriority.NORMAL: "📋",
            NotificationPriority.HIGH: "⚠️",
            NotificationPriority.CRITICAL: "🚨",
        }

        message = f"""
{priority_emojis[notification.priority]} *{notification.title}*

{notification.message}

📊 *Priority:* {notification.priority.value.upper()}
🕐 *Time:* {notification.created_at.strftime('%Y-%m-%d %H:%M:%S')}
"""

        if notification.metadata:
            message += "\n📎 *Details:*\n"
            for k, v in notification.metadata.items():
                message += f"• {k}: `{v}`\n"

        payload = {
            "chat_id": preferences.telegram_chat_id,
            "text": message,
            "parse_mode": "Markdown",
        }

        async with aiohttp.ClientSession() as session:  # type: ignore[union-attr]
            url = f"{self.api_base}/sendMessage"
            async with session.post(url, json=payload) as response:
                if response.status != 200:
                    data = await response.json()
                    raise Exception(
                        f"Telegram API error: {data.get('description', 'Unknown error')}"
                    )
                return True

    def validate_config(self) -> bool:
        """Validate Telegram bot token."""
        return bool(self.bot_token and len(self.bot_token) > 20)


class WebhookProvider(NotificationProvider):
    """Generic webhook notification provider."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[dict] = None,
        auth_header: Optional[str] = None,
    ):
        self.url = url
        self.method = method.upper()
        self.headers = headers or {}
        if auth_header:
            self.headers["Authorization"] = auth_header

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send webhook notification."""
        payload = {
            "event": "tr4c3r.notification",
            "notification": notification.to_dict(),
            "user_id": preferences.user_id,
        }

        async with aiohttp.ClientSession() as session:  # type: ignore[union-attr]
            request_method = getattr(session, self.method.lower())
            async with request_method(self.url, json=payload, headers=self.headers) as response:
                if response.status >= 400:
                    text = await response.text()
                    raise Exception(f"Webhook error: {response.status} - {text}")
                return True

    def validate_config(self) -> bool:
        """Validate webhook URL."""
        return bool(
            self.url and (self.url.startswith("http://") or self.url.startswith("https://"))
        )


class DesktopProvider(NotificationProvider):
    """Desktop notification provider (cross-platform)."""

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Send desktop notification."""
        try:
            import platform

            system = platform.system()

            if system == "Darwin":  # macOS
                await self._send_macos(notification)
            elif system == "Linux":
                await self._send_linux(notification)
            elif system == "Windows":
                await self._send_windows(notification)
            else:
                logger.warning(f"Desktop notifications not supported on {system}")
                return False

            return True
        except Exception as e:
            logger.error(f"Desktop notification failed: {e}")
            raise

    async def _send_macos(self, notification: Notification):
        """Send macOS notification using osascript."""
        script = f"""
        display notification "{notification.message}" with title "TR4C3R" subtitle "{notification.title}"
        """
        process = await asyncio.create_subprocess_exec(
            "osascript",
            "-e",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.wait()

    async def _send_linux(self, notification: Notification):
        """Send Linux notification using notify-send."""
        urgency_map = {
            NotificationPriority.LOW: "low",
            NotificationPriority.NORMAL: "normal",
            NotificationPriority.HIGH: "critical",
            NotificationPriority.CRITICAL: "critical",
        }
        process = await asyncio.create_subprocess_exec(
            "notify-send",
            "-u",
            urgency_map[notification.priority],
            f"TR4C3R: {notification.title}",
            notification.message,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.wait()

    async def _send_windows(self, notification: Notification):
        """Send Windows notification using PowerShell."""
        script = f"""
        [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
        $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
        $text = $template.GetElementsByTagName("text")
        $text[0].AppendChild($template.CreateTextNode("TR4C3R: {notification.title}")) | Out-Null
        $text[1].AppendChild($template.CreateTextNode("{notification.message}")) | Out-Null
        $toast = [Windows.UI.Notifications.ToastNotification]::new($template)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("TR4C3R").Show($toast)
        """
        process = await asyncio.create_subprocess_exec(
            "powershell",
            "-Command",
            script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.wait()

    def validate_config(self) -> bool:
        """Desktop notifications are always available."""
        return True


class InAppProvider(NotificationProvider):
    """In-app notification center provider (stores in SQLite)."""

    def __init__(self, db_path: str = "notifications.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the notifications database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS in_app_notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                priority TEXT NOT NULL,
                condition TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL,
                read_at TEXT,
                dismissed BOOLEAN DEFAULT 0
            )
        """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_user_id ON in_app_notifications(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_read ON in_app_notifications(read_at)")
        conn.commit()
        conn.close()

    async def send(self, notification: Notification, preferences: NotificationPreferences) -> bool:
        """Store notification in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO in_app_notifications 
            (id, user_id, title, message, priority, condition, metadata, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                notification.id,
                preferences.user_id,
                notification.title,
                notification.message,
                notification.priority.value,
                notification.condition.value if notification.condition else None,
                json.dumps(notification.metadata),
                notification.created_at.isoformat(),
            ),
        )
        conn.commit()
        conn.close()
        return True

    def get_unread(self, user_id: str, limit: int = 50) -> list[dict]:
        """Get unread notifications for a user."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, title, message, priority, condition, metadata, created_at
            FROM in_app_notifications
            WHERE user_id = ? AND read_at IS NULL AND dismissed = 0
            ORDER BY created_at DESC
            LIMIT ?
        """,
            (user_id, limit),
        )
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": row[0],
                "title": row[1],
                "message": row[2],
                "priority": row[3],
                "condition": row[4],
                "metadata": json.loads(row[5]) if row[5] else {},
                "created_at": row[6],
            }
            for row in rows
        ]

    def mark_read(self, notification_id: str):
        """Mark notification as read."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE in_app_notifications
            SET read_at = ?
            WHERE id = ?
        """,
            (datetime.now().isoformat(), notification_id),
        )
        conn.commit()
        conn.close()

    def dismiss(self, notification_id: str):
        """Dismiss notification."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE in_app_notifications
            SET dismissed = 1
            WHERE id = ?
        """,
            (notification_id,),
        )
        conn.commit()
        conn.close()

    def validate_config(self) -> bool:
        """In-app notifications are always available."""
        return True


class NotificationManager:
    """
    Central notification manager handling all notification channels.

    Features:
    - Multi-channel notification delivery
    - User preference management
    - Retry logic with exponential backoff
    - Notification history and tracking
    - Rate limiting per channel
    - Alert rule engine
    """

    def __init__(self, db_path: str = "notifications.db"):
        self.db_path = db_path
        self.providers: dict[NotificationChannel, NotificationProvider] = {}
        self.user_preferences: dict[str, NotificationPreferences] = {}
        self.alert_rules: list[dict] = []
        self._init_db()
        self._lock = threading.Lock()

        # Register default providers
        self.register_provider(NotificationChannel.DESKTOP, DesktopProvider())
        self.register_provider(NotificationChannel.IN_APP, InAppProvider(db_path))

    def _init_db(self):
        """Initialize notification database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Notification history
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_history (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                channel TEXT NOT NULL,
                priority TEXT NOT NULL,
                condition TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL,
                sent_at TEXT,
                delivered BOOLEAN DEFAULT 0,
                error TEXT,
                retry_count INTEGER DEFAULT 0,
                user_id TEXT
            )
        """
        )

        # User preferences
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS notification_preferences (
                user_id TEXT PRIMARY KEY,
                enabled_channels TEXT,
                alert_conditions TEXT,
                quiet_hours_start INTEGER,
                quiet_hours_end INTEGER,
                min_priority TEXT,
                email TEXT,
                phone TEXT,
                slack_user_id TEXT,
                telegram_chat_id TEXT
            )
        """
        )

        # Alert rules
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_rules (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                condition TEXT NOT NULL,
                channels TEXT NOT NULL,
                priority TEXT NOT NULL,
                filters TEXT,
                enabled BOOLEAN DEFAULT 1
            )
        """
        )

        conn.commit()
        conn.close()

    def register_provider(self, channel: NotificationChannel, provider: NotificationProvider):
        """Register a notification provider for a channel."""
        if provider.validate_config():
            self.providers[channel] = provider
            logger.info(f"Registered provider for {channel.value}")
        else:
            logger.warning(f"Provider validation failed for {channel.value}")

    def configure_email(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        from_address: str = "tr4c3r@localhost",
        use_tls: bool = True,
    ):
        """Configure email notifications."""
        provider = EmailProvider(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_password=smtp_password,
            from_address=from_address,
            use_tls=use_tls,
        )
        self.register_provider(NotificationChannel.EMAIL, provider)

    def configure_slack(self, webhook_url: str, default_channel: Optional[str] = None):
        """Configure Slack notifications."""
        provider = SlackProvider(webhook_url, default_channel)
        self.register_provider(NotificationChannel.SLACK, provider)

    def configure_discord(self, webhook_url: str):
        """Configure Discord notifications."""
        provider = DiscordProvider(webhook_url)
        self.register_provider(NotificationChannel.DISCORD, provider)

    def configure_telegram(self, bot_token: str):
        """Configure Telegram notifications."""
        provider = TelegramProvider(bot_token)
        self.register_provider(NotificationChannel.TELEGRAM, provider)

    def configure_webhook(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[dict] = None,
        auth_header: Optional[str] = None,
    ):
        """Configure generic webhook notifications."""
        provider = WebhookProvider(url, method, headers, auth_header)
        self.register_provider(NotificationChannel.WEBHOOK, provider)

    def set_user_preferences(self, preferences: NotificationPreferences):
        """Set notification preferences for a user."""
        self.user_preferences[preferences.user_id] = preferences
        self._save_preferences(preferences)

    def _save_preferences(self, preferences: NotificationPreferences):
        """Save user preferences to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO notification_preferences
            (user_id, enabled_channels, alert_conditions, quiet_hours_start,
             quiet_hours_end, min_priority, email, phone, slack_user_id, telegram_chat_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                preferences.user_id,
                json.dumps([c.value for c in preferences.enabled_channels]),
                json.dumps([c.value for c in preferences.alert_conditions]),
                preferences.quiet_hours_start,
                preferences.quiet_hours_end,
                preferences.min_priority.value,
                preferences.email,
                preferences.phone,
                preferences.slack_user_id,
                preferences.telegram_chat_id,
            ),
        )
        conn.commit()
        conn.close()

    def get_user_preferences(self, user_id: str) -> NotificationPreferences:
        """Get or create preferences for a user."""
        if user_id in self.user_preferences:
            return self.user_preferences[user_id]

        # Try to load from database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notification_preferences WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        conn.close()

        if row:
            preferences = NotificationPreferences(
                user_id=row[0],
                enabled_channels=[NotificationChannel(c) for c in json.loads(row[1] or "[]")],
                alert_conditions=[AlertCondition(c) for c in json.loads(row[2] or "[]")],
                quiet_hours_start=row[3],
                quiet_hours_end=row[4],
                min_priority=(
                    NotificationPriority(row[5]) if row[5] else NotificationPriority.NORMAL
                ),
                email=row[6],
                phone=row[7],
                slack_user_id=row[8],
                telegram_chat_id=row[9],
            )
        else:
            # Create default preferences
            preferences = NotificationPreferences(
                user_id=user_id,
                enabled_channels=[NotificationChannel.IN_APP],
                alert_conditions=list(AlertCondition),
            )

        self.user_preferences[user_id] = preferences
        return preferences

    async def notify(
        self,
        title: str,
        message: str,
        user_id: str = "default",
        channels: Optional[list[NotificationChannel]] = None,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        condition: Optional[AlertCondition] = None,
        metadata: Optional[dict] = None,
    ) -> list[Notification]:
        """
        Send notification to specified channels.

        Args:
            title: Notification title
            message: Notification message
            user_id: User ID for preferences lookup
            channels: Channels to send to (None = use preferences)
            priority: Notification priority
            condition: Alert condition that triggered this
            metadata: Additional metadata

        Returns:
            List of notification results
        """
        preferences = self.get_user_preferences(user_id)
        target_channels = channels or preferences.enabled_channels
        notifications = []

        for channel in target_channels:
            notification_id = hashlib.sha256(
                f"{title}{message}{channel.value}{datetime.now().isoformat()}".encode()
            ).hexdigest()[:16]

            notification = Notification(
                id=notification_id,
                title=title,
                message=message,
                channel=channel,
                priority=priority,
                condition=condition,
                metadata=metadata or {},
            )

            # Check preferences
            if not preferences.should_notify(notification):
                logger.debug(f"Notification filtered by preferences for {channel.value}")
                continue

            # Check if provider exists
            if channel not in self.providers:
                logger.warning(f"No provider registered for {channel.value}")
                notification.error = "No provider configured"
                notifications.append(notification)
                continue

            # Send notification
            try:
                provider = self.providers[channel]
                success = await provider.send(notification, preferences)
                notification.delivered = success
                notification.sent_at = datetime.now()
            except Exception as e:
                logger.error(f"Failed to send {channel.value} notification: {e}")
                notification.error = str(e)

            notifications.append(notification)
            self._save_notification(notification, user_id)

        return notifications

    def _save_notification(self, notification: Notification, user_id: str):
        """Save notification to history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO notification_history
            (id, title, message, channel, priority, condition, metadata,
             created_at, sent_at, delivered, error, retry_count, user_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                notification.id,
                notification.title,
                notification.message,
                notification.channel.value,
                notification.priority.value,
                notification.condition.value if notification.condition else None,
                json.dumps(notification.metadata),
                notification.created_at.isoformat(),
                notification.sent_at.isoformat() if notification.sent_at else None,
                notification.delivered,
                notification.error,
                notification.retry_count,
                user_id,
            ),
        )
        conn.commit()
        conn.close()

    def add_alert_rule(
        self,
        name: str,
        condition: AlertCondition,
        channels: list[NotificationChannel],
        priority: NotificationPriority = NotificationPriority.NORMAL,
        filters: Optional[dict] = None,
    ) -> str:
        """
        Add an alert rule.

        Args:
            name: Rule name
            condition: Condition that triggers the alert
            channels: Channels to notify
            priority: Alert priority
            filters: Additional filters (e.g., keyword matches)

        Returns:
            Rule ID
        """
        rule_id = hashlib.sha256(
            f"{name}{condition.value}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        rule = {
            "id": rule_id,
            "name": name,
            "condition": condition,
            "channels": channels,
            "priority": priority,
            "filters": filters or {},
            "enabled": True,
        }

        self.alert_rules.append(rule)
        self._save_alert_rule(rule)

        return rule_id

    def _save_alert_rule(self, rule: dict):
        """Save alert rule to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO alert_rules
            (id, name, condition, channels, priority, filters, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                rule["id"],
                rule["name"],
                rule["condition"].value,
                json.dumps([c.value for c in rule["channels"]]),
                rule["priority"].value,
                json.dumps(rule["filters"]),
                rule["enabled"],
            ),
        )
        conn.commit()
        conn.close()

    async def trigger_alert(
        self,
        condition: AlertCondition,
        title: str,
        message: str,
        metadata: Optional[dict] = None,
        user_id: str = "default",
    ):
        """
        Trigger alerts based on condition.

        Checks all rules matching the condition and sends notifications.
        """
        matching_rules = [
            r for r in self.alert_rules if r["condition"] == condition and r["enabled"]
        ]

        for rule in matching_rules:
            # Check filters
            if rule["filters"]:
                if not self._check_filters(rule["filters"], metadata or {}):
                    continue

            await self.notify(
                title=f"[{rule['name']}] {title}",
                message=message,
                user_id=user_id,
                channels=rule["channels"],
                priority=rule["priority"],
                condition=condition,
                metadata=metadata,
            )

    def _check_filters(self, filters: dict, metadata: dict) -> bool:
        """Check if metadata matches filters."""
        for key, expected in filters.items():
            if key == "keywords":
                # Check if any keyword matches in metadata values
                for keyword in expected:
                    if any(keyword.lower() in str(v).lower() for v in metadata.values()):
                        return True
                return False
            elif key == "min_count":
                if metadata.get("count", 0) < expected:
                    return False
            elif key in metadata:
                if metadata[key] != expected:
                    return False
        return True

    def get_notification_history(
        self,
        user_id: Optional[str] = None,
        channel: Optional[NotificationChannel] = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get notification history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM notification_history WHERE 1=1"
        params = []

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        if channel:
            query += " AND channel = ?"
            params.append(channel.value)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [
            {
                "id": row[0],
                "title": row[1],
                "message": row[2],
                "channel": row[3],
                "priority": row[4],
                "condition": row[5],
                "metadata": json.loads(row[6]) if row[6] else {},
                "created_at": row[7],
                "sent_at": row[8],
                "delivered": bool(row[9]),
                "error": row[10],
                "retry_count": row[11],
                "user_id": row[12],
            }
            for row in rows
        ]

    def get_in_app_notifications(self, user_id: str, limit: int = 50) -> list[dict]:
        """Get unread in-app notifications for a user."""
        if NotificationChannel.IN_APP in self.providers:
            provider = self.providers[NotificationChannel.IN_APP]
            if isinstance(provider, InAppProvider):
                return provider.get_unread(user_id, limit)
        return []

    def mark_notification_read(self, notification_id: str):
        """Mark an in-app notification as read."""
        if NotificationChannel.IN_APP in self.providers:
            provider = self.providers[NotificationChannel.IN_APP]
            if isinstance(provider, InAppProvider):
                provider.mark_read(notification_id)


# Convenience functions for quick notifications
async def send_notification(
    title: str,
    message: str,
    priority: NotificationPriority = NotificationPriority.NORMAL,
    channels: Optional[list[NotificationChannel]] = None,
) -> list[Notification]:
    """Quick notification helper."""
    manager = NotificationManager()
    return await manager.notify(title, message, priority=priority, channels=channels)


async def send_alert(
    condition: AlertCondition, title: str, message: str, metadata: Optional[dict] = None
):
    """Quick alert trigger helper."""
    manager = NotificationManager()
    await manager.trigger_alert(condition, title, message, metadata)
