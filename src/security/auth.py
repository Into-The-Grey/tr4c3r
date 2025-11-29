"""JWT authentication and user management for TR4C3R.

Provides secure authentication using JWT tokens, user management,
role-based access control (RBAC), password hashing, session management,
API keys, two-factor authentication (TOTP), and comprehensive audit logging.
"""

import asyncio
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
import struct
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from pathlib import Path
from threading import Lock
from typing import (
    Dict,
    List,
    Optional,
    Any,
    Annotated,
    Callable,
    Set,
    Tuple,
    TypeVar,
    Union,
)

import jwt
from pydantic import BaseModel, Field, ConfigDict, EmailStr, field_validator

logger = logging.getLogger(__name__)

# Type variables for decorators
F = TypeVar("F", bound=Callable[..., Any])


class UserRole(Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    API_USER = "api_user"
    GUEST = "guest"


class Permission(Enum):
    """Available permissions."""

    # Search permissions
    SEARCH_USERNAME = "search:username"
    SEARCH_EMAIL = "search:email"
    SEARCH_PHONE = "search:phone"
    SEARCH_NAME = "search:name"
    SEARCH_SOCIAL = "search:social"
    SEARCH_ALL = "search:all"
    SEARCH_DARK_WEB = "search:dark_web"
    SEARCH_BATCH = "search:batch"

    # Export permissions
    EXPORT_JSON = "export:json"
    EXPORT_CSV = "export:csv"
    EXPORT_GRAPH = "export:graph"
    EXPORT_PDF = "export:pdf"
    EXPORT_HTML = "export:html"

    # Admin permissions
    MANAGE_USERS = "admin:manage_users"
    MANAGE_API_KEYS = "admin:manage_api_keys"
    VIEW_AUDIT_LOGS = "admin:view_audit_logs"
    MANAGE_SETTINGS = "admin:manage_settings"
    MANAGE_PLUGINS = "admin:manage_plugins"
    VIEW_ANALYTICS = "admin:view_analytics"

    # Dashboard permissions
    DASHBOARD_VIEW = "dashboard:view"
    DASHBOARD_CONFIGURE = "dashboard:configure"
    DASHBOARD_SHARE = "dashboard:share"

    # Mobile permissions
    MOBILE_ACCESS = "mobile:access"
    MOBILE_THREAT_FEED = "mobile:threat_feed"
    MOBILE_PUSH = "mobile:push"

    # Scheduler permissions
    SCHEDULER_CREATE = "scheduler:create"
    SCHEDULER_MANAGE = "scheduler:manage"

    # Notes and tagging
    TAGS_CREATE = "tags:create"
    TAGS_MANAGE = "tags:manage"
    NOTES_CREATE = "notes:create"
    NOTES_VIEW_ALL = "notes:view_all"

    # Notifications
    NOTIFICATIONS_CONFIGURE = "notifications:configure"
    NOTIFICATIONS_VIEW = "notifications:view"


class SessionStatus(Enum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    LOCKED = "locked"


class AuditAction(Enum):
    """Types of auditable actions."""

    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    TOKEN_REFRESH = "token_refresh"
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET_REQUEST = "password_reset_request"
    PASSWORD_RESET_COMPLETE = "password_reset_complete"
    USER_CREATE = "user_create"
    USER_UPDATE = "user_update"
    USER_DELETE = "user_delete"
    USER_DEACTIVATE = "user_deactivate"
    ROLE_CHANGE = "role_change"
    API_KEY_CREATE = "api_key_create"
    API_KEY_REVOKE = "api_key_revoke"
    TWO_FACTOR_ENABLE = "two_factor_enable"
    TWO_FACTOR_DISABLE = "two_factor_disable"
    SESSION_REVOKE = "session_revoke"
    PERMISSION_DENIED = "permission_denied"
    SEARCH_PERFORMED = "search_performed"
    EXPORT_PERFORMED = "export_performed"


# Role-Permission mapping
ROLE_PERMISSIONS: Dict[UserRole, List[Permission]] = {
    UserRole.ADMIN: list(Permission),  # Admins get ALL permissions
    UserRole.ANALYST: [
        # Most search and export permissions
        Permission.SEARCH_USERNAME,
        Permission.SEARCH_EMAIL,
        Permission.SEARCH_PHONE,
        Permission.SEARCH_NAME,
        Permission.SEARCH_SOCIAL,
        Permission.SEARCH_ALL,
        Permission.SEARCH_DARK_WEB,
        Permission.SEARCH_BATCH,
        Permission.EXPORT_JSON,
        Permission.EXPORT_CSV,
        Permission.EXPORT_GRAPH,
        Permission.EXPORT_PDF,
        Permission.EXPORT_HTML,
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_CONFIGURE,
        Permission.MOBILE_ACCESS,
        Permission.MOBILE_THREAT_FEED,
        Permission.SCHEDULER_CREATE,
        Permission.TAGS_CREATE,
        Permission.TAGS_MANAGE,
        Permission.NOTES_CREATE,
        Permission.NOTES_VIEW_ALL,
        Permission.NOTIFICATIONS_CONFIGURE,
        Permission.NOTIFICATIONS_VIEW,
    ],
    UserRole.VIEWER: [
        # Read-only permissions
        Permission.SEARCH_USERNAME,
        Permission.SEARCH_EMAIL,
        Permission.SEARCH_PHONE,
        Permission.SEARCH_NAME,
        Permission.SEARCH_SOCIAL,
        Permission.EXPORT_JSON,
        Permission.DASHBOARD_VIEW,
        Permission.TAGS_CREATE,
        Permission.NOTES_CREATE,
        Permission.NOTIFICATIONS_VIEW,
    ],
    UserRole.API_USER: [
        # API-specific permissions
        Permission.SEARCH_ALL,
        Permission.SEARCH_BATCH,
        Permission.EXPORT_JSON,
        Permission.MOBILE_ACCESS,
        Permission.TAGS_CREATE,
        Permission.NOTES_CREATE,
    ],
    UserRole.GUEST: [
        # Very limited permissions
        Permission.SEARCH_USERNAME,
        Permission.DASHBOARD_VIEW,
    ],
}


class User(BaseModel):
    """User model."""

    model_config = ConfigDict(use_enum_values=True)

    user_id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Username for login")
    email: EmailStr = Field(..., description="User email address")
    password_hash: str = Field(..., description="Hashed password")
    role: UserRole = Field(default=UserRole.VIEWER, description="User role")
    is_active: bool = Field(default=True, description="Whether user is active")
    is_verified: bool = Field(default=False, description="Whether email is verified")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")
    failed_login_attempts: int = Field(default=0, description="Failed login count")
    locked_until: Optional[datetime] = Field(default=None, description="Account lock expiry")
    two_factor_enabled: bool = Field(default=False, description="2FA enabled")
    two_factor_secret: Optional[str] = Field(default=None, description="TOTP secret")
    password_changed_at: Optional[datetime] = Field(
        default=None, description="Last password change"
    )
    require_password_change: bool = Field(default=False, description="Force password change")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional user metadata")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r"^[a-zA-Z0-9_-]{3,32}$", v):
            raise ValueError(
                "Username must be 3-32 alphanumeric characters, dashes, or underscores"
            )
        return v.lower()


class Session(BaseModel):
    """User session model."""

    model_config = ConfigDict(use_enum_values=True)

    session_id: str = Field(..., description="Unique session identifier")
    user_id: str = Field(..., description="User who owns this session")
    token_hash: str = Field(..., description="Hash of the JWT token")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(..., description="Session expiration time")
    last_activity: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: Optional[str] = Field(default=None, description="IP address of session")
    user_agent: Optional[str] = Field(default=None, description="Browser/client user agent")
    device_info: Dict[str, Any] = Field(default_factory=dict, description="Device information")
    status: SessionStatus = Field(default=SessionStatus.ACTIVE, description="Session status")


class APIKey(BaseModel):
    """API key model."""

    model_config = ConfigDict(use_enum_values=True)

    key_id: str = Field(..., description="Unique key identifier")
    user_id: str = Field(..., description="User who owns this key")
    name: str = Field(..., description="Friendly name for the key")
    key_hash: str = Field(..., description="Hash of the API key")
    key_prefix: str = Field(..., description="First few chars of key for identification")
    permissions: List[str] = Field(default_factory=list, description="Granted permissions")
    rate_limit: int = Field(default=1000, description="Requests per hour")
    is_active: bool = Field(default=True, description="Whether key is active")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = Field(default=None, description="Key expiration")
    last_used: Optional[datetime] = Field(default=None, description="Last usage time")
    usage_count: int = Field(default=0, description="Total API calls made")
    allowed_ips: List[str] = Field(default_factory=list, description="IP whitelist")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class AuditLogEntry(BaseModel):
    """Audit log entry."""

    model_config = ConfigDict(use_enum_values=True)

    log_id: str = Field(..., description="Unique log entry ID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = Field(default=None, description="User who performed action")
    username: Optional[str] = Field(default=None, description="Username for display")
    action: AuditAction = Field(..., description="Type of action")
    resource: Optional[str] = Field(default=None, description="Resource affected")
    ip_address: Optional[str] = Field(default=None, description="Client IP address")
    user_agent: Optional[str] = Field(default=None, description="Client user agent")
    success: bool = Field(default=True, description="Whether action succeeded")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")
    risk_level: str = Field(default="low", description="Risk level: low, medium, high, critical")


class PasswordResetToken(BaseModel):
    """Password reset token."""

    token_id: str = Field(..., description="Unique token ID")
    user_id: str = Field(..., description="User requesting reset")
    token_hash: str = Field(..., description="Hash of the reset token")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(..., description="Token expiration")
    used: bool = Field(default=False, description="Whether token was used")


class TokenData(BaseModel):
    """JWT token payload data."""

    user_id: str
    username: str
    role: str
    permissions: List[str]
    session_id: Optional[str] = None
    exp: datetime
    iat: Optional[datetime] = None
    token_type: str = "access"


class AuthenticationError(Exception):
    """Raised when authentication fails."""

    pass


class AuthorizationError(Exception):
    """Raised when user lacks required permissions."""

    pass


class AccountLockedError(Exception):
    """Raised when account is locked due to failed attempts."""

    def __init__(self, message: str, locked_until: Optional[datetime] = None):
        super().__init__(message)
        self.locked_until = locked_until


class TwoFactorRequiredError(Exception):
    """Raised when 2FA verification is required."""

    def __init__(self, message: str, user_id: str):
        super().__init__(message)
        self.user_id = user_id


class PasswordExpiredError(Exception):
    """Raised when password change is required."""

    pass


class RateLimitError(Exception):
    """Raised when rate limit is exceeded."""

    def __init__(self, message: str, retry_after: int):
        super().__init__(message)
        self.retry_after = retry_after


# =============================================================================
# TOTP (Time-based One-Time Password) Implementation
# =============================================================================


class TOTPGenerator:
    """TOTP generator for two-factor authentication."""

    def __init__(self, secret: Optional[str] = None, digits: int = 6, interval: int = 30):
        """Initialize TOTP generator.

        Args:
            secret: Base32-encoded secret (generated if None)
            digits: Number of digits in OTP (default: 6)
            interval: Time interval in seconds (default: 30)
        """
        self.secret = secret or self.generate_secret()
        self.digits = digits
        self.interval = interval

    @staticmethod
    def generate_secret(length: int = 32) -> str:
        """Generate a random base32-encoded secret.

        Args:
            length: Length of secret in bytes

        Returns:
            Base32-encoded secret
        """
        random_bytes = secrets.token_bytes(length)
        return base64.b32encode(random_bytes).decode("utf-8").rstrip("=")

    def _get_counter(self, timestamp: Optional[float] = None) -> int:
        """Get the TOTP counter for a given timestamp.

        Args:
            timestamp: Unix timestamp (current time if None)

        Returns:
            Counter value
        """
        if timestamp is None:
            timestamp = time.time()
        return int(timestamp // self.interval)

    def _hotp(self, counter: int) -> str:
        """Generate HOTP value.

        Args:
            counter: Counter value

        Returns:
            OTP string
        """
        # Decode secret
        secret_bytes = base64.b32decode(
            self.secret.upper() + "=" * ((8 - len(self.secret) % 8) % 8)
        )

        # Pack counter as big-endian 64-bit integer
        counter_bytes = struct.pack(">Q", counter)

        # Generate HMAC-SHA1
        hmac_hash = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()

        # Dynamic truncation
        offset = hmac_hash[-1] & 0x0F
        code = struct.unpack(">I", hmac_hash[offset : offset + 4])[0]
        code &= 0x7FFFFFFF
        code %= 10**self.digits

        return str(code).zfill(self.digits)

    def generate(self, timestamp: Optional[float] = None) -> str:
        """Generate current TOTP.

        Args:
            timestamp: Unix timestamp (current time if None)

        Returns:
            OTP string
        """
        counter = self._get_counter(timestamp)
        return self._hotp(counter)

    def verify(self, otp: str, timestamp: Optional[float] = None, window: int = 1) -> bool:
        """Verify a TOTP.

        Args:
            otp: OTP to verify
            timestamp: Unix timestamp (current time if None)
            window: Number of intervals to check before/after

        Returns:
            True if OTP is valid
        """
        if timestamp is None:
            timestamp = time.time()

        counter = self._get_counter(timestamp)

        # Check current and nearby intervals
        for i in range(-window, window + 1):
            if secrets.compare_digest(self._hotp(counter + i), otp):
                return True
        return False

    def get_provisioning_uri(self, username: str, issuer: str = "TR4C3R") -> str:
        """Generate provisioning URI for QR code.

        Args:
            username: User's account name
            issuer: Service name

        Returns:
            otpauth:// URI
        """
        import urllib.parse

        params = {
            "secret": self.secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": str(self.digits),
            "period": str(self.interval),
        }

        query = urllib.parse.urlencode(params)
        label = urllib.parse.quote(f"{issuer}:{username}")

        return f"otpauth://totp/{label}?{query}"


# =============================================================================
# Auth Rate Limiter
# =============================================================================


class AuthRateLimiter:
    """Rate limiter for authentication endpoints."""

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
    ):
        """Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed
            window_seconds: Time window in seconds
            lockout_seconds: Lockout duration after max attempts
        """
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._attempts: Dict[str, List[float]] = {}
        self._lockouts: Dict[str, float] = {}
        self._lock = Lock()

    def _cleanup_old_attempts(self, key: str):
        """Remove expired attempts."""
        cutoff = time.time() - self.window_seconds
        self._attempts[key] = [t for t in self._attempts.get(key, []) if t > cutoff]

    def check_rate_limit(self, identifier: str) -> Tuple[bool, Optional[int]]:
        """Check if identifier is rate limited.

        Args:
            identifier: IP address or username to check

        Returns:
            Tuple of (is_allowed, retry_after_seconds)
        """
        with self._lock:
            now = time.time()

            # Check if locked out
            if identifier in self._lockouts:
                lockout_end = self._lockouts[identifier]
                if now < lockout_end:
                    return False, int(lockout_end - now)
                else:
                    del self._lockouts[identifier]

            self._cleanup_old_attempts(identifier)

            if len(self._attempts.get(identifier, [])) >= self.max_attempts:
                # Lock out
                self._lockouts[identifier] = now + self.lockout_seconds
                return False, self.lockout_seconds

            return True, None

    def record_attempt(self, identifier: str, success: bool = False):
        """Record an authentication attempt.

        Args:
            identifier: IP address or username
            success: Whether attempt was successful
        """
        with self._lock:
            if success:
                # Clear attempts on success
                self._attempts.pop(identifier, None)
                self._lockouts.pop(identifier, None)
            else:
                if identifier not in self._attempts:
                    self._attempts[identifier] = []
                self._attempts[identifier].append(time.time())

    def reset(self, identifier: str):
        """Reset rate limit for identifier."""
        with self._lock:
            self._attempts.pop(identifier, None)
            self._lockouts.pop(identifier, None)


# =============================================================================
# Database Persistence Layer
# =============================================================================


class AuthDatabase:
    """SQLite database for authentication persistence."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize database.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path or Path("data/tr4c3r_auth.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_database()

    @contextmanager
    def _get_connection(self):
        """Get database connection with automatic cleanup."""
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_database(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    is_verified INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_login TEXT,
                    failed_login_attempts INTEGER DEFAULT 0,
                    locked_until TEXT,
                    two_factor_enabled INTEGER DEFAULT 0,
                    two_factor_secret TEXT,
                    password_changed_at TEXT,
                    require_password_change INTEGER DEFAULT 0,
                    metadata TEXT DEFAULT '{}'
                )
            """
            )

            # Sessions table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_activity TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    device_info TEXT DEFAULT '{}',
                    status TEXT NOT NULL DEFAULT 'active',
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """
            )

            # API Keys table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS api_keys (
                    key_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL,
                    key_prefix TEXT NOT NULL,
                    permissions TEXT NOT NULL DEFAULT '[]',
                    rate_limit INTEGER DEFAULT 1000,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_used TEXT,
                    usage_count INTEGER DEFAULT 0,
                    allowed_ips TEXT DEFAULT '[]',
                    metadata TEXT DEFAULT '{}',
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """
            )

            # Password reset tokens
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS password_reset_tokens (
                    token_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    used INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """
            )

            # Audit log table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    log_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    user_id TEXT,
                    username TEXT,
                    action TEXT NOT NULL,
                    resource TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    success INTEGER NOT NULL DEFAULT 1,
                    details TEXT DEFAULT '{}',
                    risk_level TEXT DEFAULT 'low'
                )
            """
            )

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")

    def save_user(self, user: User, salt: str):
        """Save or update a user."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO users (
                    user_id, username, email, password_hash, password_salt,
                    role, is_active, is_verified, created_at, updated_at,
                    last_login, failed_login_attempts, locked_until,
                    two_factor_enabled, two_factor_secret, password_changed_at,
                    require_password_change, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    user.user_id,
                    user.username,
                    user.email,
                    user.password_hash,
                    salt,
                    user.role.value if isinstance(user.role, UserRole) else user.role,
                    int(user.is_active),
                    int(user.is_verified),
                    user.created_at.isoformat(),
                    user.updated_at.isoformat(),
                    user.last_login.isoformat() if user.last_login else None,
                    user.failed_login_attempts,
                    user.locked_until.isoformat() if user.locked_until else None,
                    int(user.two_factor_enabled),
                    user.two_factor_secret,
                    user.password_changed_at.isoformat() if user.password_changed_at else None,
                    int(user.require_password_change),
                    json.dumps(user.metadata),
                ),
            )

    def get_user_by_id(self, user_id: str) -> Optional[Tuple[User, str]]:
        """Get user by ID with salt."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_user(row), row["password_salt"]
        return None

    def get_user_by_username(self, username: str) -> Optional[Tuple[User, str]]:
        """Get user by username with salt."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username.lower(),))
            row = cursor.fetchone()
            if row:
                return self._row_to_user(row), row["password_salt"]
        return None

    def get_user_by_email(self, email: str) -> Optional[Tuple[User, str]]:
        """Get user by email with salt."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
            row = cursor.fetchone()
            if row:
                return self._row_to_user(row), row["password_salt"]
        return None

    def _row_to_user(self, row: sqlite3.Row) -> User:
        """Convert database row to User model."""
        import json

        return User(
            user_id=row["user_id"],
            username=row["username"],
            email=row["email"],
            password_hash=row["password_hash"],
            role=UserRole(row["role"]),
            is_active=bool(row["is_active"]),
            is_verified=bool(row["is_verified"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
            failed_login_attempts=row["failed_login_attempts"] or 0,
            locked_until=(
                datetime.fromisoformat(row["locked_until"]) if row["locked_until"] else None
            ),
            two_factor_enabled=bool(row["two_factor_enabled"]),
            two_factor_secret=row["two_factor_secret"],
            password_changed_at=(
                datetime.fromisoformat(row["password_changed_at"])
                if row["password_changed_at"]
                else None
            ),
            require_password_change=bool(row["require_password_change"]),
            metadata=json.loads(row["metadata"] or "{}"),
        )

    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """List all users."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
            )
            return [self._row_to_user(row) for row in cursor.fetchall()]

    def delete_user(self, user_id: str):
        """Delete a user."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM api_keys WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
            cursor.execute("DELETE FROM users WHERE user_id = ?", (user_id,))

    def save_session(self, session: Session):
        """Save a session."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO sessions (
                    session_id, user_id, token_hash, created_at, expires_at,
                    last_activity, ip_address, user_agent, device_info, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    session.session_id,
                    session.user_id,
                    session.token_hash,
                    session.created_at.isoformat(),
                    session.expires_at.isoformat(),
                    session.last_activity.isoformat(),
                    session.ip_address,
                    session.user_agent,
                    json.dumps(session.device_info),
                    (
                        session.status.value
                        if isinstance(session.status, SessionStatus)
                        else session.status
                    ),
                ),
            )

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
            row = cursor.fetchone()
            if row:
                return Session(
                    session_id=row["session_id"],
                    user_id=row["user_id"],
                    token_hash=row["token_hash"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]),
                    last_activity=datetime.fromisoformat(row["last_activity"]),
                    ip_address=row["ip_address"],
                    user_agent=row["user_agent"],
                    device_info=json.loads(row["device_info"] or "{}"),
                    status=SessionStatus(row["status"]),
                )
        return None

    def get_user_sessions(self, user_id: str, active_only: bool = True) -> List[Session]:
        """Get all sessions for a user."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            if active_only:
                cursor.execute(
                    "SELECT * FROM sessions WHERE user_id = ? AND status = 'active' ORDER BY last_activity DESC",
                    (user_id,),
                )
            else:
                cursor.execute(
                    "SELECT * FROM sessions WHERE user_id = ? ORDER BY last_activity DESC",
                    (user_id,),
                )

            sessions = []
            for row in cursor.fetchall():
                sessions.append(
                    Session(
                        session_id=row["session_id"],
                        user_id=row["user_id"],
                        token_hash=row["token_hash"],
                        created_at=datetime.fromisoformat(row["created_at"]),
                        expires_at=datetime.fromisoformat(row["expires_at"]),
                        last_activity=datetime.fromisoformat(row["last_activity"]),
                        ip_address=row["ip_address"],
                        user_agent=row["user_agent"],
                        device_info=json.loads(row["device_info"] or "{}"),
                        status=SessionStatus(row["status"]),
                    )
                )
            return sessions

    def revoke_session(self, session_id: str):
        """Revoke a session."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET status = 'revoked' WHERE session_id = ?", (session_id,)
            )

    def revoke_all_user_sessions(self, user_id: str, except_session: Optional[str] = None):
        """Revoke all sessions for a user."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if except_session:
                cursor.execute(
                    "UPDATE sessions SET status = 'revoked' WHERE user_id = ? AND session_id != ?",
                    (user_id, except_session),
                )
            else:
                cursor.execute(
                    "UPDATE sessions SET status = 'revoked' WHERE user_id = ?", (user_id,)
                )

    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            now = datetime.now(timezone.utc).isoformat()
            cursor.execute(
                "UPDATE sessions SET status = 'expired' WHERE expires_at < ? AND status = 'active'",
                (now,),
            )

    def save_api_key(self, api_key: APIKey):
        """Save an API key."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO api_keys (
                    key_id, user_id, name, key_hash, key_prefix,
                    permissions, rate_limit, is_active, created_at,
                    expires_at, last_used, usage_count, allowed_ips, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    api_key.key_id,
                    api_key.user_id,
                    api_key.name,
                    api_key.key_hash,
                    api_key.key_prefix,
                    json.dumps(api_key.permissions),
                    api_key.rate_limit,
                    int(api_key.is_active),
                    api_key.created_at.isoformat(),
                    api_key.expires_at.isoformat() if api_key.expires_at else None,
                    api_key.last_used.isoformat() if api_key.last_used else None,
                    api_key.usage_count,
                    json.dumps(api_key.allowed_ips),
                    json.dumps(api_key.metadata),
                ),
            )

    def get_api_key_by_prefix(self, prefix: str) -> Optional[APIKey]:
        """Get API key by prefix."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM api_keys WHERE key_prefix = ? AND is_active = 1", (prefix,)
            )
            row = cursor.fetchone()
            if row:
                return self._row_to_api_key(row)
        return None

    def get_user_api_keys(self, user_id: str) -> List[APIKey]:
        """Get all API keys for a user."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC", (user_id,)
            )
            return [self._row_to_api_key(row) for row in cursor.fetchall()]

    def _row_to_api_key(self, row: sqlite3.Row) -> APIKey:
        """Convert database row to APIKey model."""
        import json

        return APIKey(
            key_id=row["key_id"],
            user_id=row["user_id"],
            name=row["name"],
            key_hash=row["key_hash"],
            key_prefix=row["key_prefix"],
            permissions=json.loads(row["permissions"] or "[]"),
            rate_limit=row["rate_limit"],
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            last_used=datetime.fromisoformat(row["last_used"]) if row["last_used"] else None,
            usage_count=row["usage_count"],
            allowed_ips=json.loads(row["allowed_ips"] or "[]"),
            metadata=json.loads(row["metadata"] or "{}"),
        )

    def update_api_key_usage(self, key_id: str):
        """Update API key last used time and increment counter."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE api_keys 
                SET last_used = ?, usage_count = usage_count + 1
                WHERE key_id = ?
            """,
                (datetime.now(timezone.utc).isoformat(), key_id),
            )

    def revoke_api_key(self, key_id: str):
        """Revoke an API key."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE api_keys SET is_active = 0 WHERE key_id = ?", (key_id,))

    def save_password_reset_token(self, token: PasswordResetToken):
        """Save a password reset token."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO password_reset_tokens (
                    token_id, user_id, token_hash, created_at, expires_at, used
                ) VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    token.token_id,
                    token.user_id,
                    token.token_hash,
                    token.created_at.isoformat(),
                    token.expires_at.isoformat(),
                    int(token.used),
                ),
            )

    def get_password_reset_token(self, token_hash: str) -> Optional[PasswordResetToken]:
        """Get password reset token by hash."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used = 0",
                (token_hash,),
            )
            row = cursor.fetchone()
            if row:
                return PasswordResetToken(
                    token_id=row["token_id"],
                    user_id=row["user_id"],
                    token_hash=row["token_hash"],
                    created_at=datetime.fromisoformat(row["created_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]),
                    used=bool(row["used"]),
                )
        return None

    def mark_reset_token_used(self, token_id: str):
        """Mark a password reset token as used."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE token_id = ?", (token_id,)
            )

    def save_audit_log(self, entry: AuditLogEntry):
        """Save an audit log entry."""
        import json

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_log (
                    log_id, timestamp, user_id, username, action,
                    resource, ip_address, user_agent, success, details, risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    entry.log_id,
                    entry.timestamp.isoformat(),
                    entry.user_id,
                    entry.username,
                    entry.action.value if isinstance(entry.action, AuditAction) else entry.action,
                    entry.resource,
                    entry.ip_address,
                    entry.user_agent,
                    int(entry.success),
                    json.dumps(entry.details),
                    entry.risk_level,
                ),
            )

    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[AuditAction] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLogEntry]:
        """Query audit logs."""
        import json

        query = "SELECT * FROM audit_log WHERE 1=1"
        params: List[Any] = []

        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)

        if action:
            query += " AND action = ?"
            params.append(action.value)

        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date.isoformat())

        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)

            entries = []
            for row in cursor.fetchall():
                entries.append(
                    AuditLogEntry(
                        log_id=row["log_id"],
                        timestamp=datetime.fromisoformat(row["timestamp"]),
                        user_id=row["user_id"],
                        username=row["username"],
                        action=AuditAction(row["action"]),
                        resource=row["resource"],
                        ip_address=row["ip_address"],
                        user_agent=row["user_agent"],
                        success=bool(row["success"]),
                        details=json.loads(row["details"] or "{}"),
                        risk_level=row["risk_level"],
                    )
                )
            return entries


class JWTAuthenticator:
    """JWT-based authentication manager with session tracking."""

    def __init__(
        self,
        secret_key: Optional[str] = None,
        algorithm: str = "HS256",
        access_token_expiry_minutes: int = 30,
        refresh_token_expiry_days: int = 7,
        db: Optional[AuthDatabase] = None,
    ):
        """Initialize JWT authenticator.

        Args:
            secret_key: Secret key for JWT signing (auto-generated if None)
            algorithm: JWT algorithm (default: HS256)
            access_token_expiry_minutes: Access token expiration in minutes
            refresh_token_expiry_days: Refresh token expiration in days
            db: Database for session persistence
        """
        self.secret_key = secret_key or self._generate_secret_key()
        self.algorithm = algorithm
        self.access_token_expiry_minutes = access_token_expiry_minutes
        self.refresh_token_expiry_days = refresh_token_expiry_days
        self.db = db or AuthDatabase()
        self._refresh_secret = self._generate_secret_key()  # Separate secret for refresh tokens

    def _generate_secret_key(self) -> str:
        """Generate a secure random secret key.

        Returns:
            256-bit hex-encoded secret key
        """
        return secrets.token_hex(32)

    def hash_password(self, password: str, salt: Optional[str] = None) -> tuple[str, str]:
        """Hash a password with salt using PBKDF2-SHA256.

        Args:
            password: Plain text password
            salt: Salt for hashing (auto-generated if None)

        Returns:
            Tuple of (password_hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)

        # Use PBKDF2 with SHA256 - 100k iterations
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000
        ).hex()

        return password_hash, salt

    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password to verify
            password_hash: Stored password hash
            salt: Salt used in hashing

        Returns:
            True if password matches, False otherwise
        """
        computed_hash, _ = self.hash_password(password, salt)
        return secrets.compare_digest(computed_hash, password_hash)

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    def create_access_token(
        self,
        user: User,
        session_id: Optional[str] = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a JWT access token for a user.

        Args:
            user: User to create token for
            session_id: Session ID to include in token
            expires_delta: Custom expiration time

        Returns:
            Encoded JWT token
        """
        if expires_delta is None:
            expires_delta = timedelta(minutes=self.access_token_expiry_minutes)

        now = datetime.now(timezone.utc)
        expire = now + expires_delta

        # Get user permissions based on role
        role = user.role if isinstance(user.role, UserRole) else UserRole(user.role)
        permissions = [p.value for p in ROLE_PERMISSIONS.get(role, [])]

        payload = {
            "user_id": user.user_id,
            "username": user.username,
            "role": user.role.value if isinstance(user.role, UserRole) else str(user.role),
            "permissions": permissions,
            "session_id": session_id,
            "token_type": "access",
            "exp": expire,
            "iat": now,
            "nbf": now,  # Not valid before
        }

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token

    def create_refresh_token(
        self,
        user: User,
        session_id: str,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create a refresh token for a user.

        Args:
            user: User to create token for
            session_id: Session ID
            expires_delta: Custom expiration time

        Returns:
            Encoded refresh token
        """
        if expires_delta is None:
            expires_delta = timedelta(days=self.refresh_token_expiry_days)

        now = datetime.now(timezone.utc)
        expire = now + expires_delta

        payload = {
            "user_id": user.user_id,
            "session_id": session_id,
            "token_type": "refresh",
            "exp": expire,
            "iat": now,
        }

        return jwt.encode(payload, self._refresh_secret, algorithm=self.algorithm)

    def create_session(
        self,
        user: User,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        device_info: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, str, Session]:
        """Create a new session with access and refresh tokens.

        Args:
            user: User to create session for
            ip_address: Client IP address
            user_agent: Client user agent
            device_info: Additional device information

        Returns:
            Tuple of (access_token, refresh_token, session)
        """
        session_id = f"sess_{secrets.token_hex(16)}"

        access_token = self.create_access_token(user, session_id)
        refresh_token = self.create_refresh_token(user, session_id)

        session = Session(
            session_id=session_id,
            user_id=user.user_id,
            token_hash=self._hash_token(access_token),
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(days=self.refresh_token_expiry_days),
            last_activity=datetime.now(timezone.utc),
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info or {},
            status=SessionStatus.ACTIVE,
        )

        self.db.save_session(session)

        return access_token, refresh_token, session

    def verify_token(self, token: str, token_type: str = "access") -> TokenData:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify
            token_type: Expected token type ("access" or "refresh")

        Returns:
            Decoded token data

        Raises:
            AuthenticationError: If token is invalid or expired
        """
        try:
            secret = self.secret_key if token_type == "access" else self._refresh_secret
            payload = jwt.decode(token, secret, algorithms=[self.algorithm])

            if payload.get("token_type") != token_type:
                raise AuthenticationError(f"Invalid token type: expected {token_type}")

            # Check session status if session_id present
            session_id = payload.get("session_id")
            if session_id:
                session = self.db.get_session(session_id)
                if session:  # Only check if session exists in DB
                    if session.status != SessionStatus.ACTIVE:
                        raise AuthenticationError("Session has been revoked")

            return TokenData(
                user_id=payload["user_id"],
                username=payload.get("username", ""),
                role=payload.get("role", "viewer"),
                permissions=payload.get("permissions", []),
                session_id=session_id,
                exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
                iat=(
                    datetime.fromtimestamp(payload.get("iat", 0), tz=timezone.utc)
                    if payload.get("iat")
                    else None
                ),
                token_type=payload.get("token_type", "access"),
            )

        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")

    def refresh_access_token(self, refresh_token: str, user: User) -> str:
        """Refresh an access token using a refresh token.

        Args:
            refresh_token: Refresh token
            user: User to create new access token for

        Returns:
            New access token

        Raises:
            AuthenticationError: If refresh token is invalid
        """
        token_data = self.verify_token(refresh_token, token_type="refresh")

        # Update session activity
        if token_data.session_id:
            session = self.db.get_session(token_data.session_id)
            if session:
                session.last_activity = datetime.now(timezone.utc)
                self.db.save_session(session)

        return self.create_access_token(user, token_data.session_id)

    def revoke_session(self, session_id: str):
        """Revoke a session.

        Args:
            session_id: Session ID to revoke
        """
        self.db.revoke_session(session_id)
        logger.info(f"Revoked session: {session_id}")

    def revoke_all_user_sessions(self, user_id: str, except_session: Optional[str] = None):
        """Revoke all sessions for a user.

        Args:
            user_id: User ID
            except_session: Session ID to keep active
        """
        self.db.revoke_all_user_sessions(user_id, except_session)
        logger.info(f"Revoked all sessions for user: {user_id}")


class APIKeyManager:
    """Manager for API key authentication."""

    def __init__(self, db: AuthDatabase, rate_limiter: Optional[AuthRateLimiter] = None):
        """Initialize API key manager.

        Args:
            db: Database for persistence
            rate_limiter: Rate limiter for API key usage
        """
        self.db = db
        self.rate_limiter = rate_limiter or AuthRateLimiter(
            max_attempts=100,
            window_seconds=3600,
            lockout_seconds=3600,
        )

    def generate_api_key(
        self,
        user_id: str,
        name: str,
        permissions: Optional[List[Permission]] = None,
        rate_limit: int = 1000,
        expires_in_days: Optional[int] = None,
        allowed_ips: Optional[List[str]] = None,
    ) -> Tuple[str, APIKey]:
        """Generate a new API key.

        Args:
            user_id: User who owns the key
            name: Friendly name for the key
            permissions: Specific permissions (or inherit from user role)
            rate_limit: Requests per hour
            expires_in_days: Days until expiration
            allowed_ips: IP whitelist

        Returns:
            Tuple of (raw_key, api_key_object)
        """
        # Generate key: tr4c3r_<prefix>_<secret>
        prefix = secrets.token_hex(4)
        secret_part = secrets.token_hex(24)
        raw_key = f"tr4c3r_{prefix}_{secret_part}"

        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        api_key = APIKey(
            key_id=f"key_{secrets.token_hex(8)}",
            user_id=user_id,
            name=name,
            key_hash=key_hash,
            key_prefix=prefix,
            permissions=[p.value for p in (permissions or [])],
            rate_limit=rate_limit,
            is_active=True,
            created_at=datetime.now(timezone.utc),
            expires_at=(
                datetime.now(timezone.utc) + timedelta(days=expires_in_days)
                if expires_in_days
                else None
            ),
            allowed_ips=allowed_ips or [],
        )

        self.db.save_api_key(api_key)
        logger.info(f"Generated API key: {name} for user {user_id}")

        return raw_key, api_key

    def verify_api_key(
        self,
        raw_key: str,
        ip_address: Optional[str] = None,
    ) -> Tuple[APIKey, User]:
        """Verify an API key and return the associated user.

        Args:
            raw_key: Raw API key string
            ip_address: Client IP address for whitelist check

        Returns:
            Tuple of (api_key, user)

        Raises:
            AuthenticationError: If key is invalid
            RateLimitError: If rate limit exceeded
        """
        # Parse key
        parts = raw_key.split("_")
        if len(parts) != 3 or parts[0] != "tr4c3r":
            raise AuthenticationError("Invalid API key format")

        prefix = parts[1]

        # Look up by prefix
        api_key = self.db.get_api_key_by_prefix(prefix)
        if not api_key:
            raise AuthenticationError("Invalid API key")

        # Verify hash
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        if not secrets.compare_digest(key_hash, api_key.key_hash):
            raise AuthenticationError("Invalid API key")

        # Check if active
        if not api_key.is_active:
            raise AuthenticationError("API key has been revoked")

        # Check expiration
        if api_key.expires_at and datetime.now(timezone.utc) > api_key.expires_at:
            raise AuthenticationError("API key has expired")

        # Check IP whitelist
        if api_key.allowed_ips and ip_address:
            if ip_address not in api_key.allowed_ips:
                raise AuthenticationError(f"IP {ip_address} not allowed for this API key")

        # Check rate limit
        is_allowed, retry_after = self.rate_limiter.check_rate_limit(api_key.key_id)
        if not is_allowed:
            raise RateLimitError("API key rate limit exceeded", retry_after or 3600)

        # Update usage
        self.db.update_api_key_usage(api_key.key_id)

        # Get user
        result = self.db.get_user_by_id(api_key.user_id)
        if not result:
            raise AuthenticationError("User not found")

        user, _ = result
        return api_key, user

    def revoke_api_key(self, key_id: str, user_id: str):
        """Revoke an API key.

        Args:
            key_id: Key ID to revoke
            user_id: User who owns the key (for authorization)
        """
        self.db.revoke_api_key(key_id)
        logger.info(f"Revoked API key: {key_id}")

    def list_user_keys(self, user_id: str) -> List[APIKey]:
        """List all API keys for a user.

        Args:
            user_id: User ID

        Returns:
            List of API keys (without the actual key value)
        """
        return self.db.get_user_api_keys(user_id)


class UserManager:
    """Comprehensive user management with database persistence."""

    def __init__(
        self,
        authenticator: JWTAuthenticator,
        rate_limiter: Optional[AuthRateLimiter] = None,
        db: Optional[AuthDatabase] = None,
    ):
        """Initialize user manager.

        Args:
            authenticator: JWT authenticator instance
            rate_limiter: Rate limiter for login attempts
            db: Database for persistence
        """
        self.authenticator = authenticator
        self.rate_limiter = rate_limiter or AuthRateLimiter()
        self.db = db or authenticator.db
        self.api_key_manager = APIKeyManager(self.db, self.rate_limiter)

        # Password policy
        self.min_password_length = 8
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_digit = True
        self.require_special = True
        self.password_history_count = 5
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 30

        # Create default admin user if no users exist
        self._ensure_default_admin()

    def _ensure_default_admin(self):
        """Create default admin user if no users exist."""
        users = self.db.list_users(limit=1)
        if not users:
            try:
                # Create admin with bypassed password validation
                user_id = "admin_default"
                password_hash, salt = self.authenticator.hash_password("admin")
                now = datetime.now(timezone.utc)

                admin_user = User(
                    user_id=user_id,
                    username="admin",
                    email="admin@localhost.localdomain",
                    password_hash=password_hash,
                    role=UserRole.ADMIN,
                    is_active=True,
                    is_verified=True,
                    created_at=now,
                    updated_at=now,
                    require_password_change=True,  # Force password change on first login
                )

                self.db.save_user(admin_user, salt)
                logger.info("Created default admin user (password: 'admin' - MUST be changed)")
            except Exception as e:
                logger.error(f"Failed to create default admin: {e}")

    def validate_password(
        self, password: str, skip_pattern_check: bool = False
    ) -> Tuple[bool, List[str]]:
        """Validate password against policy.

        Args:
            password: Password to validate
            skip_pattern_check: Skip common pattern check (for internal use)

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if len(password) < self.min_password_length:
            errors.append(f"Password must be at least {self.min_password_length} characters")

        if self.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")

        if self.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")

        if self.require_digit and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")

        if self.require_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")

        # Check for common patterns (can be skipped for internal use)
        if not skip_pattern_check:
            common_patterns = ["password", "123456", "qwerty", "letmein"]
            if any(pattern in password.lower() for pattern in common_patterns):
                errors.append("Password contains common patterns")

        return len(errors) == 0, errors

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: UserRole = UserRole.VIEWER,
        require_password_change: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> User:
        """Create a new user.

        Args:
            username: Username for login
            email: User email address
            password: Plain text password
            role: User role
            require_password_change: Force password change on first login
            metadata: Additional user metadata

        Returns:
            Created user

        Raises:
            ValueError: If username/email exists or password invalid
        """
        # Check username availability
        if self.db.get_user_by_username(username):
            raise ValueError(f"Username '{username}' already exists")

        # Check email availability
        if self.db.get_user_by_email(email):
            raise ValueError(f"Email '{email}' already registered")

        # Validate password
        is_valid, errors = self.validate_password(password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {'; '.join(errors)}")

        # Generate user ID
        user_id = f"user_{secrets.token_hex(8)}"

        # Hash password
        password_hash, salt = self.authenticator.hash_password(password)

        now = datetime.now(timezone.utc)

        # Create user
        user = User(
            user_id=user_id,
            username=username.lower(),
            email=email.lower(),
            password_hash=password_hash,
            role=role,
            is_active=True,
            is_verified=False,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
            require_password_change=require_password_change,
            metadata=metadata or {},
        )

        self.db.save_user(user, salt)

        # Log user creation
        self._audit_log(
            action=AuditAction.USER_CREATE,
            user_id=user_id,
            username=username,
            details={"role": role.value, "email": email},
        )

        logger.info(f"Created user: {username} ({user_id})")
        return user

    def _audit_log(
        self,
        action: AuditAction,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        resource: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
        risk_level: str = "low",
    ):
        """Create an audit log entry."""
        entry = AuditLogEntry(
            log_id=f"log_{secrets.token_hex(8)}",
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details or {},
            risk_level=risk_level,
        )
        self.db.save_audit_log(entry)

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID.

        Args:
            user_id: User identifier

        Returns:
            User if found, None otherwise
        """
        result = self.db.get_user_by_id(user_id)
        return result[0] if result else None

    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username.

        Args:
            username: Username to look up

        Returns:
            User if found, None otherwise
        """
        result = self.db.get_user_by_username(username)
        return result[0] if result else None

    def authenticate(
        self,
        username: str,
        password: str,
        totp_code: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[User, str, str]:
        """Authenticate a user and return tokens.

        Args:
            username: Username for login
            password: Plain text password
            totp_code: Two-factor authentication code (if enabled)
            ip_address: Client IP address
            user_agent: Client user agent

        Returns:
            Tuple of (user, access_token, refresh_token)

        Raises:
            AuthenticationError: If authentication fails
            AccountLockedError: If account is locked
            TwoFactorRequiredError: If 2FA verification needed
        """
        # Check rate limit
        rate_key = f"login:{ip_address or 'unknown'}:{username}"
        is_allowed, retry_after = self.rate_limiter.check_rate_limit(rate_key)
        if not is_allowed:
            self._audit_log(
                action=AuditAction.LOGIN_FAILED,
                username=username,
                ip_address=ip_address,
                success=False,
                details={"reason": "rate_limited"},
                risk_level="high",
            )
            raise RateLimitError("Too many login attempts", retry_after or 900)

        # Get user
        result = self.db.get_user_by_username(username)
        if not result:
            self.rate_limiter.record_attempt(rate_key, success=False)
            self._audit_log(
                action=AuditAction.LOGIN_FAILED,
                username=username,
                ip_address=ip_address,
                success=False,
                details={"reason": "user_not_found"},
            )
            raise AuthenticationError("Invalid username or password")

        user, salt = result

        # Check if account is locked
        if user.locked_until and datetime.now(timezone.utc) < user.locked_until:
            self._audit_log(
                action=AuditAction.LOGIN_FAILED,
                user_id=user.user_id,
                username=username,
                ip_address=ip_address,
                success=False,
                details={"reason": "account_locked"},
                risk_level="medium",
            )
            raise AccountLockedError(
                "Account is locked due to too many failed attempts", user.locked_until
            )

        # Check if active
        if not user.is_active:
            self._audit_log(
                action=AuditAction.LOGIN_FAILED,
                user_id=user.user_id,
                username=username,
                ip_address=ip_address,
                success=False,
                details={"reason": "account_disabled"},
            )
            raise AuthenticationError("User account is disabled")

        # Verify password
        if not self.authenticator.verify_password(password, user.password_hash, salt):
            # Record failed attempt
            user.failed_login_attempts += 1

            if user.failed_login_attempts >= self.max_failed_attempts:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=self.lockout_duration_minutes
                )
                self._audit_log(
                    action=AuditAction.LOGIN_FAILED,
                    user_id=user.user_id,
                    username=username,
                    ip_address=ip_address,
                    success=False,
                    details={"reason": "account_locked", "attempts": user.failed_login_attempts},
                    risk_level="high",
                )

            user.updated_at = datetime.now(timezone.utc)
            self.db.save_user(user, salt)

            self.rate_limiter.record_attempt(rate_key, success=False)
            raise AuthenticationError("Invalid username or password")

        # Check 2FA if enabled
        if user.two_factor_enabled:
            if not totp_code:
                raise TwoFactorRequiredError("Two-factor authentication required", user.user_id)

            if not user.two_factor_secret:
                raise AuthenticationError("2FA is enabled but secret is missing")

            totp = TOTPGenerator(secret=user.two_factor_secret)
            if not totp.verify(totp_code):
                self._audit_log(
                    action=AuditAction.LOGIN_FAILED,
                    user_id=user.user_id,
                    username=username,
                    ip_address=ip_address,
                    success=False,
                    details={"reason": "invalid_totp"},
                    risk_level="medium",
                )
                raise AuthenticationError("Invalid two-factor code")

        # Successful login - reset failed attempts
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        user.updated_at = datetime.now(timezone.utc)
        self.db.save_user(user, salt)

        self.rate_limiter.record_attempt(rate_key, success=True)

        # Create session
        access_token, refresh_token, session = self.authenticator.create_session(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        self._audit_log(
            action=AuditAction.LOGIN,
            user_id=user.user_id,
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            details={"session_id": session.session_id},
        )

        logger.info(f"User authenticated: {username}")
        return user, access_token, refresh_token

    def logout(
        self,
        session_id: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
    ):
        """Logout a session.

        Args:
            session_id: Session to revoke
            user_id: User performing logout
            ip_address: Client IP
        """
        self.authenticator.revoke_session(session_id)

        self._audit_log(
            action=AuditAction.LOGOUT,
            user_id=user_id,
            details={"session_id": session_id},
            ip_address=ip_address,
        )

    def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Change a user's password.

        Args:
            user_id: User ID
            current_password: Current password
            new_password: New password
            ip_address: Client IP

        Returns:
            True if successful

        Raises:
            AuthenticationError: If current password is wrong
            ValueError: If new password is invalid
        """
        result = self.db.get_user_by_id(user_id)
        if not result:
            raise ValueError("User not found")

        user, salt = result

        # Verify current password
        if not self.authenticator.verify_password(current_password, user.password_hash, salt):
            self._audit_log(
                action=AuditAction.PASSWORD_CHANGE,
                user_id=user_id,
                username=user.username,
                ip_address=ip_address,
                success=False,
                details={"reason": "wrong_current_password"},
                risk_level="medium",
            )
            raise AuthenticationError("Current password is incorrect")

        # Validate new password
        is_valid, errors = self.validate_password(new_password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {'; '.join(errors)}")

        # Hash new password
        new_hash, new_salt = self.authenticator.hash_password(new_password)

        user.password_hash = new_hash
        user.password_changed_at = datetime.now(timezone.utc)
        user.require_password_change = False
        user.updated_at = datetime.now(timezone.utc)

        self.db.save_user(user, new_salt)

        # Revoke all other sessions for security
        self.authenticator.revoke_all_user_sessions(user_id)

        self._audit_log(
            action=AuditAction.PASSWORD_CHANGE,
            user_id=user_id,
            username=user.username,
            ip_address=ip_address,
            risk_level="medium",
        )

        logger.info(f"Password changed for user: {user.username}")
        return True

    def request_password_reset(self, email: str) -> Optional[str]:
        """Request a password reset token.

        Args:
            email: User's email address

        Returns:
            Reset token if user found, None otherwise
        """
        result = self.db.get_user_by_email(email)
        if not result:
            # Don't reveal whether email exists
            return None

        user, _ = result

        # Generate reset token
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        reset_token = PasswordResetToken(
            token_id=f"reset_{secrets.token_hex(8)}",
            user_id=user.user_id,
            token_hash=token_hash,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        self.db.save_password_reset_token(reset_token)

        self._audit_log(
            action=AuditAction.PASSWORD_RESET_REQUEST,
            user_id=user.user_id,
            username=user.username,
            details={"token_id": reset_token.token_id},
        )

        return raw_token

    def complete_password_reset(
        self,
        token: str,
        new_password: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Complete a password reset using the token.

        Args:
            token: Reset token
            new_password: New password
            ip_address: Client IP

        Returns:
            True if successful

        Raises:
            AuthenticationError: If token is invalid/expired
            ValueError: If password is invalid
        """
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        reset_token = self.db.get_password_reset_token(token_hash)

        if not reset_token:
            raise AuthenticationError("Invalid or expired reset token")

        if datetime.now(timezone.utc) > reset_token.expires_at:
            raise AuthenticationError("Reset token has expired")

        # Validate new password
        is_valid, errors = self.validate_password(new_password)
        if not is_valid:
            raise ValueError(f"Password validation failed: {'; '.join(errors)}")

        # Get user
        result = self.db.get_user_by_id(reset_token.user_id)
        if not result:
            raise AuthenticationError("User not found")

        user, _ = result

        # Hash new password
        new_hash, new_salt = self.authenticator.hash_password(new_password)

        user.password_hash = new_hash
        user.password_changed_at = datetime.now(timezone.utc)
        user.require_password_change = False
        user.updated_at = datetime.now(timezone.utc)
        user.failed_login_attempts = 0
        user.locked_until = None

        self.db.save_user(user, new_salt)
        self.db.mark_reset_token_used(reset_token.token_id)

        # Revoke all sessions
        self.authenticator.revoke_all_user_sessions(user.user_id)

        self._audit_log(
            action=AuditAction.PASSWORD_RESET_COMPLETE,
            user_id=user.user_id,
            username=user.username,
            ip_address=ip_address,
        )

        logger.info(f"Password reset completed for user: {user.username}")
        return True

    def enable_two_factor(self, user_id: str) -> Tuple[str, str]:
        """Enable two-factor authentication for a user.

        Args:
            user_id: User ID

        Returns:
            Tuple of (secret, provisioning_uri)
        """
        result = self.db.get_user_by_id(user_id)
        if not result:
            raise ValueError("User not found")

        user, salt = result

        # Generate TOTP secret
        totp = TOTPGenerator()

        user.two_factor_secret = totp.secret
        user.updated_at = datetime.now(timezone.utc)
        # Don't enable yet - wait for verification

        self.db.save_user(user, salt)

        provisioning_uri = totp.get_provisioning_uri(user.username)

        return totp.secret, provisioning_uri

    def verify_and_enable_two_factor(
        self,
        user_id: str,
        totp_code: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Verify TOTP code and enable 2FA.

        Args:
            user_id: User ID
            totp_code: TOTP code to verify
            ip_address: Client IP

        Returns:
            True if enabled successfully
        """
        result = self.db.get_user_by_id(user_id)
        if not result:
            raise ValueError("User not found")

        user, salt = result

        if not user.two_factor_secret:
            raise ValueError("Two-factor setup not initiated")

        totp = TOTPGenerator(secret=user.two_factor_secret)
        if not totp.verify(totp_code):
            raise AuthenticationError("Invalid verification code")

        user.two_factor_enabled = True
        user.updated_at = datetime.now(timezone.utc)
        self.db.save_user(user, salt)

        self._audit_log(
            action=AuditAction.TWO_FACTOR_ENABLE,
            user_id=user_id,
            username=user.username,
            ip_address=ip_address,
            risk_level="medium",
        )

        logger.info(f"2FA enabled for user: {user.username}")
        return True

    def disable_two_factor(
        self,
        user_id: str,
        password: str,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Disable two-factor authentication.

        Args:
            user_id: User ID
            password: User's password for verification
            ip_address: Client IP

        Returns:
            True if disabled successfully
        """
        result = self.db.get_user_by_id(user_id)
        if not result:
            raise ValueError("User not found")

        user, salt = result

        # Verify password
        if not self.authenticator.verify_password(password, user.password_hash, salt):
            raise AuthenticationError("Invalid password")

        user.two_factor_enabled = False
        user.two_factor_secret = None
        user.updated_at = datetime.now(timezone.utc)
        self.db.save_user(user, salt)

        self._audit_log(
            action=AuditAction.TWO_FACTOR_DISABLE,
            user_id=user_id,
            username=user.username,
            ip_address=ip_address,
            risk_level="high",
        )

        logger.info(f"2FA disabled for user: {user.username}")
        return True

    def update_user_role(
        self,
        user_id: str,
        new_role: UserRole,
        admin_user_id: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """Update user's role.

        Args:
            user_id: User identifier
            new_role: New role to assign
            admin_user_id: Admin performing the change
            ip_address: Client IP

        Returns:
            Updated user

        Raises:
            ValueError: If user not found
        """
        result = self.db.get_user_by_id(user_id)
        if not result:
            raise ValueError(f"User not found: {user_id}")

        user, salt = result
        old_role = user.role

        user.role = new_role
        user.updated_at = datetime.now(timezone.utc)
        self.db.save_user(user, salt)

        self._audit_log(
            action=AuditAction.ROLE_CHANGE,
            user_id=admin_user_id,
            resource=user_id,
            ip_address=ip_address,
            details={"old_role": old_role, "new_role": new_role.value},
            risk_level="high",
        )

        logger.info(f"Updated user role: {user.username} from {old_role} to {new_role}")
        return user

    def deactivate_user(
        self,
        user_id: str,
        admin_user_id: str,
        ip_address: Optional[str] = None,
    ) -> User:
        """Deactivate a user account.

        Args:
            user_id: User identifier
            admin_user_id: Admin performing the action
            ip_address: Client IP

        Returns:
            Updated user

        Raises:
            ValueError: If user not found
        """
        result = self.db.get_user_by_id(user_id)
        if not result:
            raise ValueError(f"User not found: {user_id}")

        user, salt = result
        user.is_active = False
        user.updated_at = datetime.now(timezone.utc)
        self.db.save_user(user, salt)

        # Revoke all sessions
        self.authenticator.revoke_all_user_sessions(user_id)

        self._audit_log(
            action=AuditAction.USER_DEACTIVATE,
            user_id=admin_user_id,
            resource=user_id,
            ip_address=ip_address,
            details={"username": user.username},
            risk_level="high",
        )

        logger.info(f"Deactivated user: {user.username}")
        return user

    def list_users(self, limit: int = 100, offset: int = 0) -> List[User]:
        """List all users.

        Args:
            limit: Maximum users to return
            offset: Offset for pagination

        Returns:
            List of users
        """
        return self.db.list_users(limit, offset)

    def get_user_sessions(self, user_id: str) -> List[Session]:
        """Get all active sessions for a user.

        Args:
            user_id: User ID

        Returns:
            List of sessions
        """
        return self.db.get_user_sessions(user_id)

    def revoke_session(
        self,
        session_id: str,
        user_id: str,
        ip_address: Optional[str] = None,
    ):
        """Revoke a specific session.

        Args:
            session_id: Session to revoke
            user_id: User performing the action
            ip_address: Client IP
        """
        self.authenticator.revoke_session(session_id)

        self._audit_log(
            action=AuditAction.SESSION_REVOKE,
            user_id=user_id,
            details={"session_id": session_id},
            ip_address=ip_address,
        )

    def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has a specific permission.

        Args:
            user: User to check
            permission: Permission to check for

        Returns:
            True if user has permission, False otherwise
        """
        role = user.role if isinstance(user.role, UserRole) else UserRole(user.role)
        user_permissions = ROLE_PERMISSIONS.get(role, [])
        return permission in user_permissions

    def require_permission(
        self,
        user: User,
        permission: Permission,
        ip_address: Optional[str] = None,
    ):
        """Require user to have a specific permission.

        Args:
            user: User to check
            permission: Required permission
            ip_address: Client IP

        Raises:
            AuthorizationError: If user lacks permission
        """
        if not self.check_permission(user, permission):
            self._audit_log(
                action=AuditAction.PERMISSION_DENIED,
                user_id=user.user_id,
                username=user.username,
                ip_address=ip_address,
                success=False,
                details={"permission": permission.value},
                risk_level="medium",
            )
            raise AuthorizationError(f"User '{user.username}' lacks permission: {permission.value}")

    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        action: Optional[AuditAction] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLogEntry]:
        """Get audit log entries.

        Args:
            user_id: Filter by user
            action: Filter by action type
            start_date: Filter by start date
            end_date: Filter by end date
            limit: Maximum entries
            offset: Pagination offset

        Returns:
            List of audit log entries
        """
        return self.db.get_audit_logs(
            user_id=user_id,
            action=action,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )


# =============================================================================
# FastAPI Integration Helpers
# =============================================================================


def auth_required(permission: Optional[Permission] = None):
    """Decorator for requiring authentication and optional permission.

    Args:
        permission: Optional permission to require

    Returns:
        Decorator function
    """

    def decorator(func: F) -> F:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # This would be used with FastAPI dependency injection
            # The actual token verification happens in the dependency
            return await func(*args, **kwargs)

        return wrapper  # type: ignore

    return decorator


def create_fastapi_auth_dependency(user_manager: "UserManager"):
    """Create a FastAPI dependency for authentication.

    Args:
        user_manager: UserManager instance

    Returns:
        Dependency function
    """

    async def get_current_user(
        authorization: str = None,  # Header: Authorization
        x_api_key: str = None,  # Header: X-API-Key
    ) -> User:
        """FastAPI dependency to get current authenticated user."""
        if x_api_key:
            # API key authentication
            try:
                _, user = user_manager.api_key_manager.verify_api_key(x_api_key)
                return user
            except (AuthenticationError, RateLimitError):
                raise

        if not authorization:
            raise AuthenticationError("No authentication provided")

        # Bearer token authentication
        if not authorization.startswith("Bearer "):
            raise AuthenticationError("Invalid authorization header")

        token = authorization[7:]  # Remove "Bearer " prefix

        try:
            token_data = user_manager.authenticator.verify_token(token)
            user = user_manager.get_user_by_id(token_data.user_id)
            if not user:
                raise AuthenticationError("User not found")
            return user
        except AuthenticationError:
            raise

    return get_current_user


# =============================================================================
# Global Instances
# =============================================================================

_db: Optional[AuthDatabase] = None
_authenticator: Optional[JWTAuthenticator] = None
_user_manager: Optional[UserManager] = None
_rate_limiter: Optional[AuthRateLimiter] = None


def initialize_auth(
    secret_key: Optional[str] = None,
    db_path: Optional[Path] = None,
    access_token_expiry_minutes: int = 30,
    refresh_token_expiry_days: int = 7,
) -> Tuple[JWTAuthenticator, UserManager]:
    """Initialize authentication system.

    Args:
        secret_key: JWT secret key (auto-generated if None)
        db_path: Path to SQLite database
        access_token_expiry_minutes: Access token expiration
        refresh_token_expiry_days: Refresh token expiration

    Returns:
        Tuple of (authenticator, user_manager)
    """
    global _db, _authenticator, _user_manager, _rate_limiter

    _db = AuthDatabase(db_path)
    _rate_limiter = AuthRateLimiter()
    _authenticator = JWTAuthenticator(
        secret_key=secret_key,
        access_token_expiry_minutes=access_token_expiry_minutes,
        refresh_token_expiry_days=refresh_token_expiry_days,
        db=_db,
    )
    _user_manager = UserManager(
        _authenticator,
        rate_limiter=_rate_limiter,
        db=_db,
    )

    logger.info("Authentication system initialized")
    return _authenticator, _user_manager


def get_authenticator() -> JWTAuthenticator:
    """Get global authenticator instance.

    Returns:
        JWT authenticator

    Raises:
        RuntimeError: If not initialized
    """
    if _authenticator is None:
        raise RuntimeError("Authentication not initialized. Call initialize_auth() first.")
    return _authenticator


def get_user_manager() -> UserManager:
    """Get global user manager instance.

    Returns:
        User manager

    Raises:
        RuntimeError: If not initialized
    """
    if _user_manager is None:
        raise RuntimeError("Authentication not initialized. Call initialize_auth() first.")
    return _user_manager


def get_auth_database() -> AuthDatabase:
    """Get global auth database instance.

    Returns:
        Auth database

    Raises:
        RuntimeError: If not initialized
    """
    if _db is None:
        raise RuntimeError("Authentication not initialized. Call initialize_auth() first.")
    return _db


# =============================================================================
# Convenience Functions
# =============================================================================


def hash_password(password: str) -> Tuple[str, str]:
    """Hash a password (convenience function).

    Args:
        password: Plain text password

    Returns:
        Tuple of (hash, salt)
    """
    return get_authenticator().hash_password(password)


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify a password (convenience function).

    Args:
        password: Plain text password
        password_hash: Stored hash
        salt: Salt used in hashing

    Returns:
        True if password matches
    """
    return get_authenticator().verify_password(password, password_hash, salt)


def create_token(user: User) -> str:
    """Create an access token (convenience function).

    Args:
        user: User to create token for

    Returns:
        JWT token
    """
    return get_authenticator().create_access_token(user)


def verify_token(token: str) -> TokenData:
    """Verify a token (convenience function).

    Args:
        token: JWT token

    Returns:
        Token data
    """
    return get_authenticator().verify_token(token)
