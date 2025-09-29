"""
Security utilities for Scrambled Eggs.
Handles key management, security policies, and breach detection.
"""

import hmac
import logging
import os
from dataclasses import asdict, dataclass
from datetime import datetime

# Import ScrambledEggsCrypto only when needed to avoid circular imports
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.config import settings

if TYPE_CHECKING:
    from app.services.scrambled_eggs_crypto import ScrambledEggsCrypto

logger = logging.getLogger(__name__)


@dataclass
class SecurityPolicy:
    """Defines security policies for the application."""

    max_failed_attempts: int = 5
    lockout_duration: int = 300  # seconds
    min_password_length: int = 12
    key_rotation_days: int = 30
    session_timeout: int = 3600  # 1 hour

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityPolicy":
        """Create policy from dictionary."""
        return cls(**data)


class SecurityManager:
    """Manages security operations and policies."""

    def __init__(self, policy: Optional[SecurityPolicy] = None):
        self.policy = policy or SecurityPolicy()
        self.failed_attempts = {}
        self.locked_accounts = {}
        self.security_events = []

    def hash_password(
        self, password: str, salt: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, dict]:
        """
        Hash a password using Scrypt for key derivation.

        Args:
            password: The password to hash
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (hashed_password, salt, params) where params contains the KDF parameters
        """
        if salt is None:
            salt = os.urandom(16)

        # Use Scrypt for password hashing (more secure than PBKDF2)
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**20,  # CPU/memory cost parameter
            r=8,  # Block size parameter
            p=1,  # Parallelization parameter
        )

        hashed = kdf.derive(password.encode("utf-8"))

        # Include KDF parameters for verification
        params = {"kdf": "scrypt", "n": 2**20, "r": 8, "p": 1, "salt": salt.hex(), "key_length": 32}

        return hashed, salt, params

    def verify_password(
        self,
        password: str,
        hashed_password: bytes,
        salt: bytes,
        kdf_params: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Verify a password against a stored hash using the specified KDF parameters.

        Args:
            password: The password to verify
            hashed_password: The stored hashed password
            salt: The salt used in the original hash
            kdf_params: Optional parameters for the KDF (defaults to Scrypt with standard params)

        Returns:
            bool: True if the password matches, False otherwise
        """
        try:
            if kdf_params and kdf_params.get("kdf") == "scrypt":
                # Use provided Scrypt parameters
                kdf = Scrypt(
                    salt=salt,
                    length=kdf_params.get("key_length", 32),
                    n=kdf_params.get("n", 2**20),
                    r=kdf_params.get("r", 8),
                    p=kdf_params.get("p", 1),
                )
            else:
                # Fallback to default Scrypt parameters
                kdf = Scrypt(salt=salt, length=32, n=2**20, r=8, p=1)

            # Verify the password by deriving the same key and comparing
            new_hash = kdf.derive(password.encode("utf-8"))

            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(new_hash, hashed_password)

        except Exception as e:
            logger.error(f"Password verification failed: {e}", exc_info=True)
            return False

    def check_password_strength(self, password: str) -> Tuple[bool, str]:
        """Check if a password meets strength requirements."""
        if len(password) < self.policy.min_password_length:
            return False, f"Password must be at least {self.policy.min_password_length} characters"

        # Check for common patterns
        common_patterns = ["123", "password", "qwerty", "admin", "welcome"]
        if any(pattern in password.lower() for pattern in common_patterns):
            return False, "Password contains common patterns"

        # Check for character diversity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        if not (has_upper and has_lower and has_digit and has_special):
            return (
                False,
                "Password must include uppercase, lowercase, numbers, and special characters",
            )

        return True, "Password is strong"

    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log a security event."""
        event = {"timestamp": datetime.utcnow().isoformat(), "type": event_type, "details": details}
        self.security_events.append(event)
        logger.info(f"Security event: {event_type} - {details}")

    def detect_breach(self, message_hash: str) -> bool:
        """Detect if a message hash has been involved in a breach."""
        # In a real implementation, this would check against a breach database
        # For now, just log the check
        self.log_security_event("breach_check", {"hash": message_hash, "result": "clean"})
        return False

    def rotate_encryption_keys(self, crypto_service=None) -> str:
        """
        Rotate encryption keys and return the new key ID.

        Args:
            crypto_service: Optional ScrambledEggsCrypto instance

        Returns:
            str: The ID of the new encryption key
        """
        from app.services.scrambled_eggs_crypto import ScrambledEggsCrypto

        self.log_security_event("key_rotation", {"status": "started"})

        try:
            if crypto_service is None:
                crypto_service = ScrambledEggsCrypto(self)

            new_key_id = crypto_service.rotate_key()

            self.log_security_event(
                "key_rotation",
                {
                    "status": "completed",
                    "new_key_id": new_key_id,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            return new_key_id

        except Exception as e:
            self.log_security_event(
                "key_rotation_error", {"error": str(e), "timestamp": datetime.utcnow().isoformat()}
            )
            raise

    def get_security_status(self, include_events: bool = False) -> Dict[str, Any]:
        """
        Get current security status.

        Args:
            include_events: Whether to include recent security events

        Returns:
            Dict containing security status information
        """
        status = {
            "policy": self.policy.to_dict(),
            "failed_attempts": len(self.failed_attempts),
            "locked_accounts": len(self.locked_accounts),
            "total_security_events": len(self.security_events),
            "last_breach_check": next(
                (e for e in reversed(self.security_events) if e["type"] == "breach_check"), None
            ),
            "key_status": {},
            "encryption": {
                "default_algorithm": getattr(settings, "ENCRYPTION_ALGORITHM", "aes-256-gcm"),
                "key_rotation_enabled": True,
                "key_rotation_days": getattr(settings, "KEY_ROTATION_DAYS", 90),
            },
        }

        # Try to get key status if crypto service is available
        try:
            crypto = ScrambledEggsCrypto(self)
            status["key_status"] = crypto.get_key_status()
        except Exception as e:
            logger.warning(f"Could not get key status: {e}")
            status["key_status"] = {"error": "Key status unavailable"}

        # Include recent security events if requested
        if include_events and self.security_events:
            status["recent_events"] = self.security_events[-10:]  # Last 10 events

        return status
