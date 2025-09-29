"""
Scrambled Eggs Core Encryption Service

This module provides the core encryption functionality using the Scrambled Eggs algorithm.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

# Import SecurityManager only when needed to avoid circular imports
from typing import TYPE_CHECKING, Any, Dict, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from app.core.config import get_config

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class EncryptionMode(str, Enum):
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    XCHACHA20_POLY1305 = "xchacha20-poly1305"


@dataclass
class EncryptionResult:
    """Result of an encryption operation."""

    ciphertext: bytes
    key_id: Optional[str] = None
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            "ciphertext": self.ciphertext.hex(),
            "key_id": self.key_id,
            "iv": self.iv.hex() if self.iv else None,
            "tag": self.tag.hex() if self.tag else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptionResult":
        """Create from a dictionary."""
        return cls(
            ciphertext=bytes.fromhex(data["ciphertext"]),
            key_id=data.get("key_id"),
            iv=bytes.fromhex(data["iv"]) if data.get("iv") else None,
            tag=bytes.fromhex(data["tag"]) if data.get("tag") else None,
            metadata=data.get("metadata", {}),
        )


class ScrambledEggsCrypto:
    """Core encryption service using Scrambled Eggs algorithm."""

    def __init__(self, security_manager=None):
        """Initialize the crypto service.

        Args:
            security_manager: Optional SecurityManager instance. If not provided, will be imported when needed.
        """
        if security_manager is None:
            from app.core.security import SecurityManager

            self.security_manager = SecurityManager()
        else:
            self.security_manager = security_manager
        config = get_config()
        self.algorithm = config.get("encryption.algorithm", "aes-256-gcm")
        self.key_size = 32  # 256 bits
        self.iv_size = 12  # 96 bits for GCM
        self.tag_size = 16  # 128 bits for GCM

        # Initialize key store
        self.key_store = {}
        self.current_key_id = self._generate_key_id()

        # Generate initial key
        self._generate_new_key(self.current_key_id)

    def _generate_key_id(self) -> str:
        """Generate a unique key ID."""
        return f"key_{int(datetime.utcnow().timestamp() * 1000)}"

    def _generate_nonce(self) -> bytes:
        """Generate a secure random nonce/IV."""
        return os.urandom(self.iv_size)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a secure key from a password and salt."""
        kdf = Scrypt(
            salt=salt,
            length=self.key_size,
            n=2**20,  # CPU/memory cost parameter
            r=8,  # Block size parameter
            p=1,  # Parallelization parameter
        )
        return kdf.derive(password.encode())

    def _generate_new_key(self, key_id: str) -> None:
        """Generate a new encryption key and store it."""
        key = os.urandom(self.key_size)
        self.key_store[key_id] = {
            "key": key,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(days=90),  # Rotate every 90 days
        }

    def encrypt(
        self, plaintext: Union[str, bytes], associated_data: Optional[bytes] = None
    ) -> EncryptionResult:
        """
        Encrypt data using Scrambled Eggs encryption.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional associated data to authenticate

        Returns:
            EncryptionResult containing ciphertext and metadata
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        # Get the current key
        key_data = self.key_store[self.current_key_id]
        key = key_data["key"]

        # Generate a random nonce/IV
        nonce = self._generate_nonce()

        # Encrypt the data
        if self.algorithm == "aes-256-gcm":
            cipher = AESGCM(key)
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
            # Split into ciphertext and tag
            tag = ciphertext[-self.tag_size :]
            ciphertext = ciphertext[: -self.tag_size]
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")

        # Log the encryption operation
        self.security_manager.log_security_event(
            "encryption",
            {
                "key_id": self.current_key_id,
                "algorithm": self.algorithm,
                "data_length": len(plaintext),
            },
        )

        return EncryptionResult(
            ciphertext=ciphertext,
            key_id=self.current_key_id,
            iv=nonce,
            tag=tag,
            metadata={"algorithm": self.algorithm, "created_at": datetime.utcnow().isoformat()},
        )

    def decrypt(
        self,
        result: Union[EncryptionResult, Dict[str, Any]],
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt data using Scrambled Eggs encryption.

        Args:
            result: EncryptionResult or dict containing ciphertext and metadata
            associated_data: Optional associated data to authenticate

        Returns:
            Decrypted plaintext as bytes

        Raises:
            ValueError: If decryption fails or authentication fails
        """
        if isinstance(result, dict):
            result = EncryptionResult.from_dict(result)

        # Get the key
        if result.key_id not in self.key_store:
            raise ValueError(f"Key ID not found: {result.key_id}")

        key = self.key_store[result.key_id]["key"]

        # Decrypt the data
        try:
            if self.algorithm == "aes-256-gcm":
                if not result.iv or not result.tag:
                    raise ValueError("IV and tag are required for AES-GCM decryption")

                cipher = AESGCM(key)
                ciphertext = result.ciphertext + result.tag  # Combine for decryption
                plaintext = cipher.decrypt(result.iv, ciphertext, associated_data)
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")

            # Log successful decryption
            self.security_manager.log_security_event(
                "decryption",
                {
                    "key_id": result.key_id,
                    "algorithm": self.algorithm,
                    "data_length": len(plaintext),
                },
            )

            return plaintext

        except InvalidTag as e:
            # Log failed decryption attempt
            self.security_manager.log_security_event(
                "decryption_failed",
                {
                    "key_id": result.key_id,
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
            raise ValueError("Decryption failed: Invalid authentication tag") from e

    def rotate_key(self) -> str:
        """
        Rotate to a new encryption key.

        Returns:
            The ID of the new key
        """
        new_key_id = self._generate_key_id()
        self._generate_new_key(new_key_id)

        # Update the current key ID
        old_key_id = self.current_key_id
        self.current_key_id = new_key_id

        # Log the key rotation
        self.security_manager.log_security_event(
            "key_rotation",
            {
                "old_key_id": old_key_id,
                "new_key_id": new_key_id,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

        return new_key_id

    def get_key_status(self) -> Dict[str, Any]:
        """Get the status of all keys."""
        return {
            "current_key_id": self.current_key_id,
            "key_count": len(self.key_store),
            "keys": [
                {
                    "key_id": key_id,
                    "created_at": data["created_at"].isoformat(),
                    "expires_at": data["expires_at"].isoformat(),
                    "is_current": key_id == self.current_key_id,
                }
                for key_id, data in self.key_store.items()
            ],
        }
