"""Tests for JWT authentication and user management."""

import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from src.security.auth import (
    AuthDatabase,
    AuthenticationError,
    AuthorizationError,
    AuthRateLimiter,
    JWTAuthenticator,
    Permission,
    Session,
    TOTPGenerator,
    User,
    UserManager,
    UserRole,
    initialize_auth,
)


class TestJWTAuthenticator:
    """Tests for JWT authenticator."""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            yield AuthDatabase(db_path)

    def test_generate_secret_key(self, temp_db):
        """Test secret key generation."""
        auth = JWTAuthenticator(db=temp_db)
        assert len(auth.secret_key) == 64  # 32 bytes = 64 hex chars

        # Should be different each time
        auth2 = JWTAuthenticator(db=temp_db)
        assert auth.secret_key != auth2.secret_key

    def test_hash_password(self, temp_db):
        """Test password hashing."""
        auth = JWTAuthenticator(db=temp_db)
        password = "test_password_123"

        password_hash, salt = auth.hash_password(password)

        assert len(password_hash) == 64  # SHA256 hex = 64 chars
        assert len(salt) == 32  # 16 bytes = 32 hex chars

        # Same password with same salt should produce same hash
        hash2, _ = auth.hash_password(password, salt)
        assert password_hash == hash2

        # Different password should produce different hash
        hash3, _ = auth.hash_password("different_password", salt)
        assert password_hash != hash3

    def test_verify_password(self, temp_db):
        """Test password verification."""
        auth = JWTAuthenticator(db=temp_db)
        password = "test_password_123"

        password_hash, salt = auth.hash_password(password)

        # Correct password should verify
        assert auth.verify_password(password, password_hash, salt)

        # Wrong password should not verify
        assert not auth.verify_password("wrong_password", password_hash, salt)

    def test_create_access_token(self, temp_db):
        """Test JWT token creation."""
        auth = JWTAuthenticator(db=temp_db)

        user = User(
            user_id="test_001",
            username="testuser",
            email="test@example.com",
            password_hash="dummy_hash",
            role=UserRole.ANALYST,
        )

        token = auth.create_access_token(user)

        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_token(self, temp_db):
        """Test JWT token verification."""
        auth = JWTAuthenticator(db=temp_db)

        user = User(
            user_id="test_001",
            username="testuser",
            email="test@example.com",
            password_hash="dummy_hash",
            role=UserRole.ANALYST,
        )

        token = auth.create_access_token(user)
        token_data = auth.verify_token(token)

        assert token_data.user_id == user.user_id
        assert token_data.username == user.username
        assert token_data.role == (
            user.role.value if isinstance(user.role, UserRole) else user.role
        )
        assert len(token_data.permissions) > 0
        assert token_data.exp > datetime.now(timezone.utc)

    def test_verify_token_expired(self, temp_db):
        """Test verification of expired token."""
        auth = JWTAuthenticator(db=temp_db, access_token_expiry_minutes=0)

        user = User(
            user_id="test_001",
            username="testuser",
            email="test@example.com",
            password_hash="dummy_hash",
            role=UserRole.VIEWER,
        )

        # Create token with negative expiry
        token = auth.create_access_token(user, expires_delta=timedelta(seconds=-1))

        # Should raise AuthenticationError
        with pytest.raises(AuthenticationError, match="expired"):
            auth.verify_token(token)

    def test_verify_token_invalid(self, temp_db):
        """Test verification of invalid token."""
        auth = JWTAuthenticator(db=temp_db)

        with pytest.raises(AuthenticationError, match="Invalid token"):
            auth.verify_token("invalid_token")

    def test_refresh_access_token(self, temp_db):
        """Test token refresh."""
        auth = JWTAuthenticator(db=temp_db)

        user = User(
            user_id="test_001",
            username="testuser",
            email="test@example.com",
            password_hash="dummy_hash",
            role=UserRole.ANALYST,
        )

        # Create session with access and refresh tokens
        access_token, refresh_token, session = auth.create_session(user)
        time.sleep(0.1)  # Ensure different iat

        # Refresh access token using refresh token
        refreshed_token = auth.refresh_access_token(refresh_token, user)

        # Should be different tokens
        assert refreshed_token != access_token

        # But same user data
        original_data = auth.verify_token(access_token)
        refreshed_data = auth.verify_token(refreshed_token)

        assert refreshed_data.user_id == original_data.user_id
        assert refreshed_data.username == original_data.username
        assert refreshed_data.role == original_data.role


class TestUserManager:
    """Tests for user manager."""

    @pytest.fixture
    def auth_system(self):
        """Create fresh auth system for each test."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            db = AuthDatabase(db_path)
            auth = JWTAuthenticator(secret_key="test_secret_key", db=db)
            rate_limiter = AuthRateLimiter()
            user_mgr = UserManager(auth, rate_limiter=rate_limiter, db=db)
            yield auth, user_mgr

    def test_default_admin_created(self, auth_system):
        """Test default admin user is created."""
        _, user_mgr = auth_system

        admin = user_mgr.get_user_by_username("admin")
        assert admin is not None
        assert admin.role == UserRole.ADMIN.value  # Compare string value
        assert admin.is_active

    def test_create_user(self, auth_system):
        """Test creating a new user."""
        _, user_mgr = auth_system

        user = user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",  # Strong password
            role=UserRole.ANALYST,
        )

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == UserRole.ANALYST.value  # Compare string value
        assert user.is_active
        assert user.user_id.startswith("user_")

    def test_create_duplicate_user(self, auth_system):
        """Test creating user with duplicate username."""
        _, user_mgr = auth_system

        user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
        )

        # Should raise ValueError
        with pytest.raises(ValueError, match="already exists"):
            user_mgr.create_user(
                username="testuser",
                email="test2@example.com",
                password="TestPass456!",
            )

    def test_get_user_by_id(self, auth_system):
        """Test getting user by ID."""
        _, user_mgr = auth_system

        created_user = user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
        )

        retrieved_user = user_mgr.get_user_by_id(created_user.user_id)

        assert retrieved_user is not None
        assert retrieved_user.user_id == created_user.user_id
        assert retrieved_user.username == created_user.username

    def test_get_user_by_username(self, auth_system):
        """Test getting user by username."""
        _, user_mgr = auth_system

        user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
        )

        retrieved_user = user_mgr.get_user_by_username("testuser")

        assert retrieved_user is not None
        assert retrieved_user.username == "testuser"

    def test_authenticate_success(self, auth_system):
        """Test successful authentication."""
        _, user_mgr = auth_system

        user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.ANALYST,
        )

        user, access_token, refresh_token = user_mgr.authenticate("testuser", "TestPass123!")

        assert user.username == "testuser"
        assert isinstance(access_token, str)
        assert isinstance(refresh_token, str)
        assert len(access_token) > 0
        assert user.last_login is not None

    def test_authenticate_wrong_password(self, auth_system):
        """Test authentication with wrong password."""
        _, user_mgr = auth_system

        user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
        )

        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            user_mgr.authenticate("testuser", "WrongPass123!")

    def test_authenticate_nonexistent_user(self, auth_system):
        """Test authentication with nonexistent user."""
        _, user_mgr = auth_system

        with pytest.raises(AuthenticationError, match="Invalid username or password"):
            user_mgr.authenticate("nonexistent", "TestPass123!")

    def test_authenticate_inactive_user(self, auth_system):
        """Test authentication with inactive user."""
        _, user_mgr = auth_system

        user = user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
        )

        user_mgr.deactivate_user(user.user_id, admin_user_id="admin")

        with pytest.raises(AuthenticationError, match="disabled"):
            user_mgr.authenticate("testuser", "TestPass123!")

    def test_update_user_role(self, auth_system):
        """Test updating user role."""
        _, user_mgr = auth_system

        user = user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
            role=UserRole.VIEWER,
        )

        updated_user = user_mgr.update_user_role(
            user.user_id, UserRole.ANALYST, admin_user_id="admin"
        )

        # Role could be enum or string depending on Pydantic behavior
        assert updated_user.role in (UserRole.ANALYST, UserRole.ANALYST.value)

    def test_deactivate_user(self, auth_system):
        """Test deactivating user."""
        _, user_mgr = auth_system

        user = user_mgr.create_user(
            username="testuser",
            email="test@example.com",
            password="TestPass123!",
        )

        assert user.is_active

        deactivated_user = user_mgr.deactivate_user(user.user_id, admin_user_id="admin")

        assert not deactivated_user.is_active

    def test_list_users(self, auth_system):
        """Test listing all users."""
        _, user_mgr = auth_system

        # Should have default admin
        users = user_mgr.list_users()
        assert len(users) == 1
        assert users[0].username == "admin"

        # Create more users
        user_mgr.create_user(
            username="user1",
            email="user1@example.com",
            password="TestPass123!",
        )
        user_mgr.create_user(
            username="user2",
            email="user2@example.com",
            password="TestPass456!",
        )

        users = user_mgr.list_users()
        assert len(users) == 3
        usernames = {u.username for u in users}
        assert usernames == {"admin", "user1", "user2"}

    def test_check_permission(self, auth_system):
        """Test checking user permissions."""
        _, user_mgr = auth_system

        # Admin should have all permissions
        admin = user_mgr.get_user_by_username("admin")
        assert user_mgr.check_permission(admin, Permission.SEARCH_EMAIL)
        assert user_mgr.check_permission(admin, Permission.MANAGE_USERS)

        # Analyst should have search but not admin permissions
        analyst = user_mgr.create_user(
            username="analyst",
            email="analyst@example.com",
            password="TestPass123!",
            role=UserRole.ANALYST,
        )
        assert user_mgr.check_permission(analyst, Permission.SEARCH_EMAIL)
        assert not user_mgr.check_permission(analyst, Permission.MANAGE_USERS)

        # Viewer should have limited permissions
        viewer = user_mgr.create_user(
            username="viewer",
            email="viewer@example.com",
            password="TestPass456!",
            role=UserRole.VIEWER,
        )
        assert user_mgr.check_permission(viewer, Permission.SEARCH_EMAIL)
        assert user_mgr.check_permission(viewer, Permission.EXPORT_JSON)  # Viewers can export JSON

    def test_require_permission_success(self, auth_system):
        """Test requiring permission when user has it."""
        _, user_mgr = auth_system

        admin = user_mgr.get_user_by_username("admin")

        # Should not raise
        user_mgr.require_permission(admin, Permission.SEARCH_EMAIL)
        user_mgr.require_permission(admin, Permission.MANAGE_USERS)

    def test_require_permission_failure(self, auth_system):
        """Test requiring permission when user lacks it."""
        _, user_mgr = auth_system

        viewer = user_mgr.create_user(
            username="viewer",
            email="viewer@example.com",
            password="TestPass789!",
            role=UserRole.VIEWER,
        )

        with pytest.raises(AuthorizationError, match="lacks permission"):
            user_mgr.require_permission(viewer, Permission.MANAGE_USERS)


class TestRolePermissions:
    """Tests for role-permission mappings."""

    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions."""
        from src.security.auth import ROLE_PERMISSIONS

        admin_perms = ROLE_PERMISSIONS[UserRole.ADMIN]

        # Admin should have all defined permissions
        assert Permission.SEARCH_ALL in admin_perms
        assert Permission.EXPORT_GRAPH in admin_perms
        assert Permission.MANAGE_USERS in admin_perms
        assert Permission.MOBILE_ACCESS in admin_perms

    def test_analyst_permissions(self):
        """Test analyst role permissions."""
        from src.security.auth import ROLE_PERMISSIONS

        analyst_perms = ROLE_PERMISSIONS[UserRole.ANALYST]

        # Should have search and export
        assert Permission.SEARCH_ALL in analyst_perms
        assert Permission.EXPORT_JSON in analyst_perms

        # Should not have admin permissions
        assert Permission.MANAGE_USERS not in analyst_perms
        assert Permission.VIEW_AUDIT_LOGS not in analyst_perms

    def test_viewer_permissions(self):
        """Test viewer role permissions."""
        from src.security.auth import ROLE_PERMISSIONS

        viewer_perms = ROLE_PERMISSIONS[UserRole.VIEWER]

        # Should have search only
        assert Permission.SEARCH_EMAIL in viewer_perms
        assert Permission.SEARCH_USERNAME in viewer_perms

        # Should have basic export
        assert Permission.EXPORT_JSON in viewer_perms

        # Should not have admin
        assert Permission.MANAGE_USERS not in viewer_perms

    def test_api_user_permissions(self):
        """Test API user role permissions."""
        from src.security.auth import ROLE_PERMISSIONS

        api_perms = ROLE_PERMISSIONS[UserRole.API_USER]

        # Should have API-specific permissions
        assert Permission.SEARCH_ALL in api_perms
        assert Permission.EXPORT_JSON in api_perms
        assert Permission.MOBILE_ACCESS in api_perms

        # Should not have admin permissions
        assert Permission.MANAGE_USERS not in api_perms


class TestTOTP:
    """Tests for TOTP two-factor authentication."""

    def test_generate_secret(self):
        """Test TOTP secret generation."""
        totp = TOTPGenerator()
        assert len(totp.secret) > 0

        # Should be base32 encoded
        import base64

        base64.b32decode(totp.secret.upper() + "=" * ((8 - len(totp.secret) % 8) % 8))

    def test_generate_and_verify(self):
        """Test TOTP generation and verification."""
        totp = TOTPGenerator()

        code = totp.generate()
        assert len(code) == 6
        assert code.isdigit()

        # Should verify immediately
        assert totp.verify(code)

    def test_verify_wrong_code(self):
        """Test TOTP verification with wrong code."""
        totp = TOTPGenerator()

        assert not totp.verify("000000")
        assert not totp.verify("999999")

    def test_provisioning_uri(self):
        """Test TOTP provisioning URI generation."""
        totp = TOTPGenerator(secret="TESTSECRET123456")

        uri = totp.get_provisioning_uri("testuser", "TR4C3R")

        assert uri.startswith("otpauth://totp/")
        assert "testuser" in uri
        assert "TR4C3R" in uri
        assert "secret=TESTSECRET123456" in uri


class TestAuthRateLimiter:
    """Tests for authentication rate limiter."""

    def test_allows_initial_attempts(self):
        """Test that initial attempts are allowed."""
        limiter = AuthRateLimiter(max_attempts=3)

        allowed, retry = limiter.check_rate_limit("test_user")
        assert allowed
        assert retry is None

    def test_blocks_after_max_attempts(self):
        """Test blocking after max attempts."""
        limiter = AuthRateLimiter(max_attempts=3, lockout_seconds=60)

        # Record 3 failed attempts
        for _ in range(3):
            limiter.record_attempt("test_user", success=False)

        # Should be blocked
        allowed, retry = limiter.check_rate_limit("test_user")
        assert not allowed
        assert retry is not None
        assert retry <= 60

    def test_resets_on_success(self):
        """Test counter reset on successful attempt."""
        limiter = AuthRateLimiter(max_attempts=3)

        # Record 2 failed attempts
        limiter.record_attempt("test_user", success=False)
        limiter.record_attempt("test_user", success=False)

        # Successful login
        limiter.record_attempt("test_user", success=True)

        # Should be allowed
        allowed, retry = limiter.check_rate_limit("test_user")
        assert allowed


class TestInitialization:
    """Tests for global initialization."""

    def test_initialize_auth(self):
        """Test authentication system initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            auth, user_mgr = initialize_auth(secret_key="test_key", db_path=db_path)

            assert auth is not None
            assert user_mgr is not None
            assert auth.secret_key == "test_key"

    def test_initialize_auth_auto_key(self):
        """Test initialization with auto-generated key."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            auth, user_mgr = initialize_auth(db_path=db_path)

            assert auth is not None
            assert user_mgr is not None
            assert len(auth.secret_key) == 64


class TestIntegrationScenarios:
    """Integration tests for complete auth workflows."""

    def test_full_auth_workflow(self):
        """Test complete authentication workflow."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            auth, user_mgr = initialize_auth(db_path=db_path)

            # Create user
            user = user_mgr.create_user(
                username="testuser",
                email="test@example.com",
                password="SecurePass123!",
                role=UserRole.ANALYST,
            )

            # Authenticate
            authenticated_user, access_token, refresh_token = user_mgr.authenticate(
                "testuser", "SecurePass123!"
            )
            assert authenticated_user.user_id == user.user_id

            # Verify token
            token_data = auth.verify_token(access_token)
            assert token_data.user_id == user.user_id
            assert token_data.username == "testuser"
            assert token_data.role == UserRole.ANALYST.value

            # Check permissions
            assert user_mgr.check_permission(user, Permission.SEARCH_EMAIL)
            assert user_mgr.check_permission(user, Permission.EXPORT_JSON)

            # Refresh token
            new_token = auth.refresh_access_token(refresh_token, user)
            new_token_data = auth.verify_token(new_token)
            assert new_token_data.user_id == user.user_id

    def test_role_change_workflow(self):
        """Test changing user role and permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            auth, user_mgr = initialize_auth(db_path=db_path)

            # Create viewer
            user = user_mgr.create_user(
                username="testuser",
                email="test@example.com",
                password="SecurePass123!",
                role=UserRole.VIEWER,
            )

            # Viewer can search and has limited export
            assert user_mgr.check_permission(user, Permission.SEARCH_EMAIL)
            assert user_mgr.check_permission(user, Permission.EXPORT_JSON)
            assert not user_mgr.check_permission(user, Permission.EXPORT_PDF)

            # Promote to analyst
            user_mgr.update_user_role(user.user_id, UserRole.ANALYST, admin_user_id="admin")

            # Now can export more
            updated_user = user_mgr.get_user_by_id(user.user_id)
            assert user_mgr.check_permission(updated_user, Permission.EXPORT_PDF)

    def test_user_deactivation_workflow(self):
        """Test user deactivation prevents login."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_auth.db"
            auth, user_mgr = initialize_auth(db_path=db_path)

            # Create and authenticate user
            user = user_mgr.create_user(
                username="testuser",
                email="test@example.com",
                password="SecurePass123!",
            )

            _, access_token, refresh_token = user_mgr.authenticate("testuser", "SecurePass123!")
            assert access_token is not None

            # Deactivate user
            user_mgr.deactivate_user(user.user_id, admin_user_id="admin")

            # Can no longer authenticate
            with pytest.raises(AuthenticationError, match="disabled"):
                user_mgr.authenticate("testuser", "SecurePass123!")
