"""
Key Management Service for Scrambled Eggs encryption.

Handles key generation, rotation, and secure storage.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple

from app.config.encryption import config
from app.crypto import generate_key  # Keep this for backward compatibility
from app.services.encryption import ScrambledEggsCrypto

logger = logging.getLogger(__name__)


class KeyService:
    """Service for managing encryption keys."""

    def __init__(self, storage_path: Optional[str] = None):
        """Initialize the key service."""
        self.storage_path = Path(storage_path or config.KEY_STORAGE_PATH)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.crypto = ScrambledEggsCrypto()
        self.keys_metadata: Dict[str, dict] = {}
        self._load_keys_metadata()

    def _get_metadata_path(self) -> Path:
        """Get the path to the keys metadata file."""
        return self.storage_path / "keys_metadata.json"

    def _load_keys_metadata(self) -> None:
        """Load keys metadata from disk."""
        metadata_path = self._get_metadata_path()
        try:
            if metadata_path.exists():
                with open(metadata_path, "r") as f:
                    self.keys_metadata = json.load(f)
            else:
                self.keys_metadata = {"current_key_id": None, "key_versions": {}, "key_history": []}
        except Exception as e:
            logger.error(f"Failed to load keys metadata: {e}")
            self.keys_metadata = {"current_key_id": None, "key_versions": {}, "key_history": []}

    def _save_keys_metadata(self) -> None:
        """Save keys metadata to disk."""
        metadata_path = self._get_metadata_path()
        try:
            with open(metadata_path, "w") as f:
                json.dump(self.keys_metadata, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save keys metadata: {e}")
            raise

    def _generate_key_id(self, key: bytes) -> str:
        """Generate a unique ID for a key."""
        return hashlib.sha256(key).hexdigest()

    def _get_key_path(self, key_id: str) -> Path:
        """Get the path to a key file."""
        return self.storage_path / f"key_{key_id}.enc"

    def _encrypt_key(self, key: bytes, master_key: bytes) -> bytes:
        """Encrypt a key with the master key."""
        return self.crypto.encrypt(key, master_key).ciphertext

    def _decrypt_key(self, encrypted_key: bytes, master_key: bytes) -> bytes:
        """Decrypt a key with the master key."""
        from app.crypto import EncryptionResult

        # Create a dummy EncryptionResult with just the ciphertext
        result = EncryptionResult(
            ciphertext=encrypted_key,
            key=master_key,
            salt=b"",  # Will be replaced during decryption
            iv=b"",  # Will be replaced during decryption
        )

        return self.crypto.decrypt(result, master_key)

    def create_key(self, master_key: bytes, key_data: Optional[bytes] = None) -> Tuple[bytes, str]:
        """
        Create a new encryption key.

        Args:
            master_key: The master key used to encrypt the new key
            key_data: Optional key material (if None, a new key will be generated)

        Returns:
            A tuple of (encrypted_key, key_id)
        """
        # Generate a new key if none provided
        if key_data is None:
            key_data = generate_key()

        # Generate a key ID
        key_id = self._generate_key_id(key_data)

        # Encrypt the key with the master key
        encrypted_key = self._encrypt_key(key_data, master_key)

        # Save the encrypted key
        key_path = self._get_key_path(key_id)
        with open(key_path, "wb") as f:
            f.write(encrypted_key)

        # Update metadata
        now = datetime.utcnow().isoformat()
        self.keys_metadata["key_versions"][key_id] = {
            "created_at": now,
            "last_used": now,
            "is_active": True,
            "metadata": {},
        }

        # Add to history
        self.keys_metadata["key_history"].append(
            {"key_id": key_id, "action": "created", "timestamp": now}
        )

        # If this is the first key, set it as current
        if self.keys_metadata["current_key_id"] is None:
            self.keys_metadata["current_key_id"] = key_id

        self._save_keys_metadata()

        return encrypted_key, key_id

    def get_current_key(self, master_key: bytes) -> Tuple[bytes, str]:
        """
        Get the current encryption key.

        Args:
            master_key: The master key used to decrypt the current key

        Returns:
            A tuple of (decrypted_key, key_id)
        """
        if not self.keys_metadata["current_key_id"]:
            raise ValueError("No current key set")

        key_id = self.keys_metadata["current_key_id"]
        return self.get_key(key_id, master_key), key_id

    def get_key(self, key_id: str, master_key: bytes) -> bytes:
        """
        Get a key by ID.

        Args:
            key_id: The ID of the key to retrieve
            master_key: The master key used to decrypt the key

        Returns:
            The decrypted key
        """
        if key_id not in self.keys_metadata["key_versions"]:
            raise ValueError(f"Key {key_id} not found")

        # Update last used timestamp
        self.keys_metadata["key_versions"][key_id]["last_used"] = datetime.utcnow().isoformat()
        self._save_keys_metadata()

        # Read and decrypt the key
        key_path = self._get_key_path(key_id)
        with open(key_path, "rb") as f:
            encrypted_key = f.read()

        return self._decrypt_key(encrypted_key, master_key)

    def rotate_key(self, master_key: bytes) -> Tuple[bytes, str]:
        """
        Rotate to a new encryption key.

        Args:
            master_key: The master key used to encrypt the new key

        Returns:
            A tuple of (new_encrypted_key, new_key_id)
        """
        # Generate a new key
        new_key = generate_key()
        encrypted_key, key_id = self.create_key(master_key, new_key)

        # Update current key
        old_key_id = self.keys_metadata["current_key_id"]
        self.keys_metadata["current_key_id"] = key_id

        # Update metadata
        now = datetime.utcnow().isoformat()
        self.keys_metadata["key_versions"][key_id]["is_active"] = True

        # If there was a previous key, mark it as inactive
        if old_key_id and old_key_id in self.keys_metadata["key_versions"]:
            self.keys_metadata["key_versions"][old_key_id]["is_active"] = False

        # Add to history
        self.keys_metadata["key_history"].append(
            {"key_id": key_id, "previous_key_id": old_key_id, "action": "rotated", "timestamp": now}
        )

        # Enforce key history size limit
        self._enforce_key_history_limit()

        self._save_keys_metadata()

        return encrypted_key, key_id

    def _enforce_key_history_limit(self) -> None:
        """Remove old keys beyond the configured history limit."""
        if not self.keys_metadata["key_history"]:
            return

        # Get active and recently used keys
        active_keys = set()
        for key_id, key_data in self.keys_metadata["key_versions"].items():
            if key_data["is_active"] or datetime.fromisoformat(
                key_data["last_used"]
            ) > datetime.utcnow() - timedelta(days=30):
                active_keys.add(key_id)

        # Remove keys not in active set
        keys_to_remove = set(self.keys_metadata["key_versions"].keys()) - active_keys

        for key_id in keys_to_remove:
            # Delete the key file
            key_path = self._get_key_path(key_id)
            if key_path.exists():
                try:
                    key_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete key file {key_path}: {e}")

            # Remove from metadata
            if key_id in self.keys_metadata["key_versions"]:
                del self.keys_metadata["key_versions"][key_id]

            # Update history
            self.keys_metadata["key_history"] = [
                entry
                for entry in self.keys_metadata["key_history"]
                if entry.get("key_id") != key_id and entry.get("previous_key_id") != key_id
            ]

    def get_key_rotation_schedule(self) -> dict:
        """Get the current key rotation schedule."""
        return {
            "schedule": config.KEY_ROTATION_SCHEDULE,
            "next_rotation": self._calculate_next_rotation_date().isoformat(),
            "current_key_id": self.keys_metadata["current_key_id"],
            "key_count": len(self.keys_metadata["key_versions"]),
            "active_keys": sum(
                1 for k in self.keys_metadata["key_versions"].values() if k["is_active"]
            ),
        }

    def _calculate_next_rotation_date(self) -> datetime:
        """Calculate the next key rotation date based on the schedule."""
        now = datetime.utcnow()

        if config.KEY_ROTATION_SCHEDULE == "monthly":
            return (now.replace(day=1) + timedelta(days=32)).replace(day=1)
        elif config.KEY_ROTATION_SCHEDULE == "quarterly":
            month = ((now.month - 1) // 3 + 1) * 3 + 1
            year = now.year + (month > 12)
            month = month % 12 or 12
            return datetime(year, month, 1)
        elif config.KEY_ROTATION_SCHEDULE == "biannually":
            month = 1 if now.month <= 6 else 7
            return datetime(now.year + (1 if month == 1 and now.month > 6 else 0), month, 1)
        else:  # annually
            return datetime(now.year + 1, 1, 1)


# Create a singleton instance
key_service = KeyService()
