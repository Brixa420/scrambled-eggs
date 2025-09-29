"""
Security Policy

Defines security policies and configurations for the application.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PasswordPolicy:
    """Password policy configuration."""

    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    max_age_days: int = 90  # Password expiration
    history_size: int = 5  # Number of previous passwords to remember
    max_attempts: int = 5  # Maximum failed login attempts before lockout
    lockout_minutes: int = 15  # Lockout duration in minutes


@dataclass
class EncryptionPolicy:
    """Encryption policy configuration."""

    min_key_size: int = 256  # Minimum key size in bits
    key_rotation_days: int = 30
    encryption_algorithm: str = "AES-256-CBC"
    key_derivation_algorithm: str = "PBKDF2-HMAC-SHA256"
    key_derivation_iterations: int = 100000
    require_encryption: bool = True

    def validate_key_size(self, key_size: int) -> bool:
        """Validate if the key size meets the policy."""
        return key_size * 8 >= self.min_key_size  # Convert bytes to bits


@dataclass
class SessionPolicy:
    """Session management policy."""

    session_timeout_minutes: int = 30
    max_concurrent_sessions: int = 5
    require_reauthentication: bool = True
    reauthentication_timeout_minutes: int = 15

    def get_session_expiry(self) -> datetime:
        """Get the session expiry datetime based on the policy."""
        return datetime.utcnow() + timedelta(minutes=self.session_timeout_minutes)


@dataclass
class NetworkSecurityPolicy:
    """Network security policy configuration."""

    require_tls: bool = True
    min_tls_version: str = "TLSv1.2"
    allowed_ciphers: List[str] = field(
        default_factory=lambda: [
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_128_GCM_SHA256",
        ]
    )
    rate_limit_requests: int = 100  # Max requests per minute
    rate_limit_window: int = 60  # Time window in seconds
    enable_cors: bool = True
    allowed_origins: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class AuditPolicy:
    """Audit logging policy."""

    enabled: bool = True
    log_successful_logins: bool = True
    log_failed_logins: bool = True
    log_sensitive_operations: bool = True
    log_user_actions: bool = True
    retention_days: int = 365

    def should_log_event(self, event_type: str) -> bool:
        """Check if an event type should be logged based on the policy."""
        if not self.enabled:
            return False

        event_handlers = {
            "login_success": self.log_successful_logins,
            "login_failure": self.log_failed_logins,
            "sensitive_operation": self.log_sensitive_operations,
            "user_action": self.log_user_actions,
        }

        return event_handlers.get(event_type, False)


class SecurityPolicy:
    """
    Centralized security policy management for the application.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the security policy with optional configuration.

        Args:
            config: Dictionary containing policy overrides
        """
        self.config = config or {}

        # Initialize policy components
        self.password_policy = PasswordPolicy(**self.config.get("password_policy", {}))
        self.encryption_policy = EncryptionPolicy(**self.config.get("encryption_policy", {}))
        self.session_policy = SessionPolicy(**self.config.get("session_policy", {}))
        self.network_policy = NetworkSecurityPolicy(**self.config.get("network_policy", {}))
        self.audit_policy = AuditPolicy(**self.config.get("audit_policy", {}))

        # Initialize any additional security measures
        self._init_security_measures()

    def _init_security_measures(self) -> None:
        """Initialize additional security measures based on the policy."""
        # Apply secure defaults to Python
        self._apply_python_security()

        # Log security policy initialization
        logger.info("Security policy initialized")

    def _apply_python_security(self) -> None:
        """Apply Python-specific security settings."""
        try:
            # Disable Python's hash randomization for consistent behavior
            # Note: This is a trade-off between security and predictability
            # In production, you might want to keep this enabled
            import os

            os.environ["PYTHONHASHSEED"] = "0"

            # Disable Python's bytecode generation
            sys.dont_write_bytecode = True

            # Apply secure SSL settings
            self._configure_ssl()

        except Exception as e:
            logger.warning(f"Failed to apply Python security settings: {e}")

    def _configure_ssl(self) -> None:
        """Configure SSL/TLS settings."""
        try:
            import ssl

            # Disable SSLv2 and SSLv3
            ssl.PROTOCOL_SSLv23 = ssl.PROTOCOL_TLS

            # Set default SSL context
            ssl_context = ssl.create_default_context()
            ssl_context.minimum_version = getattr(
                ssl.TLSVersion,
                f"{self.network_policy.min_tls_version.replace('.', '_')}",
                ssl.TLSVersion.TLSv1_2,
            )

            # Set allowed ciphers if specified
            if self.network_policy.allowed_ciphers:
                ssl_context.set_ciphers(":".join(self.network_policy.allowed_ciphers))

            # Apply the context
            ssl._create_default_https_context = lambda: ssl_context

        except Exception as e:
            logger.error(f"Failed to configure SSL: {e}")

    def validate_password(self, password: str) -> tuple[bool, str]:
        """
        Validate a password against the password policy.

        Args:
            password: The password to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < self.password_policy.min_length:
            return (
                False,
                f"Password must be at least {self.password_policy.min_length} characters long",
            )

        if self.password_policy.require_uppercase and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        if self.password_policy.require_lowercase and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        if self.password_policy.require_digits and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        if self.password_policy.require_special and not any(not c.isalnum() for c in password):
            return False, "Password must contain at least one special character"

        return True, ""

    def get_key_rotation_interval(self) -> timedelta:
        """
        Get the key rotation interval based on the encryption policy.

        Returns:
            Time delta representing the rotation interval
        """
        return timedelta(days=self.encryption_policy.key_rotation_days)

    def get_security_headers(self) -> Dict[str, str]:
        """
        Get recommended security headers for HTTP responses.

        Returns:
            Dictionary of security headers
        """
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:;",
        }

        if self.network_policy.require_tls:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return headers
