"""
Key Management Service for Scrambled Eggs encryption.

This module provides secure key generation, storage, rotation, and retrieval
for the Scrambled Eggs encryption system.
"""

import json
import logging
import os
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.config.encryption import config
from app.core.exceptions import KeyManagementError

logger = logging.getLogger(__name__)


class KeyManager:
    """
    Manages encryption keys for the Scrambled Eggs encryption system.

    Handles key generation, storage, rotation, and retrieval with secure practices.
    """

    def __init__(
        self,
        key_storage_path: Optional[str] = None,
        max_key_age: int = 30,
        key_rotation_interval: int = 7,
    ):
        """Initialize the KeyManager.

        Args:
            key_storage_path: Path to store encryption keys (default: 'data/keys')
            max_key_age: Maximum key age in days (default: 30)
            key_rotation_interval: Key rotation interval in days (default: 7)
        """
        # Use provided path or default to 'data/keys' to avoid circular imports
        self.key_storage_path = Path(key_storage_path) if key_storage_path else Path("data/keys")
        self.key_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.active_key_id: Optional[str] = None
        self.key_cache: Dict[str, bytes] = {}
        self.key_metadata: Dict[str, dict] = {}
        self._load_key_metadata()

        # Initialize metrics
        self.metrics = {
            "key_generations": 0,
            "key_rotations": 0,
            "key_retrievals": 0,
            "key_errors": 0,
            "last_key_rotation": None,
            "key_versions": {},
        }

    def generate_key(self, key_id: Optional[str] = None, key_size: int = 32) -> str:
        """Generate a new encryption key.

        Args:
            key_id: Optional custom key ID. If not provided, a UUID will be generated.
            key_size: Size of the key in bytes.

        Returns:
            str: The generated key ID.

        Raises:
            KeyManagementError: If key generation fails.
        """
        try:
            if not key_id:
                key_id = f"key_{secrets.token_hex(8)}"

            # Generate secure random key
            key = secrets.token_bytes(key_size)

            # Store the key securely
            self._store_key(key_id, key)

            # Update metadata
            self.key_metadata[key_id] = {
                "created_at": datetime.utcnow().isoformat(),
                "key_size": key_size,
                "is_active": True,
                "version": 1,
                "algorithm": "AES-256-GCM",
                "rotation_policy": config.KEY_ROTATION_SCHEDULE.value,
                "tags": ["system_generated"],
            }

            self._save_key_metadata()
            self.active_key_id = key_id
            self.metrics["key_generations"] += 1
            self.metrics["key_versions"][key_id] = 1

            logger.info(f"Generated new encryption key: {key_id}")
            return key_id

        except Exception as e:
            error_msg = f"Failed to generate key: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.metrics["key_errors"] += 1
            raise KeyManagementError(error_msg) from e

    def rotate_key(self, key_id: str) -> str:
        """Rotate an existing key.

        Args:
            key_id: ID of the key to rotate.

        Returns:
            str: The new key ID.

        Raises:
            KeyManagementError: If key rotation fails.
        """
        try:
            if key_id not in self.key_metadata:
                raise KeyError(f"Key {key_id} not found")

            # Mark old key as inactive but keep it for decryption
            self.key_metadata[key_id]["is_active"] = False
            self.key_metadata[key_id]["deactivated_at"] = datetime.utcnow().isoformat()

            # Generate new key
            new_key_id = self.generate_key()
            self.key_metadata[new_key_id]["version"] = self.key_metadata[key_id]["version"] + 1
            self.key_metadata[new_key_id]["previous_key_id"] = key_id

            self.metrics["key_rotations"] += 1
            self.metrics["last_key_rotation"] = datetime.utcnow().isoformat()

            logger.info(f"Rotated key {key_id} to {new_key_id}")
            return new_key_id

        except Exception as e:
            error_msg = f"Failed to rotate key {key_id}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.metrics["key_errors"] += 1
            raise KeyManagementError(error_msg) from e

    def get_key(self, key_id: str) -> bytes:
        """Retrieve an encryption key.

        Args:
            key_id: ID of the key to retrieve.

        Returns:
            bytes: The encryption key.

        Raises:
            KeyError: If the key is not found.
            KeyManagementError: If key retrieval fails.
        """
        try:
            # Check cache first
            if key_id in self.key_cache:
                self.metrics["key_retrievals"] += 1
                return self.key_cache[key_id]

            # Load from secure storage
            key_path = self.key_storage_path / f"{key_id}.key"
            if not key_path.exists():
                raise KeyError(f"Key {key_id} not found")

            with open(key_path, "rb") as f:
                key = f.read()

            # Cache the key
            self.key_cache[key_id] = key
            self.metrics["key_retrievals"] += 1

            return key

        except Exception as e:
            error_msg = f"Failed to retrieve key {key_id}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.metrics["key_errors"] += 1
            if isinstance(e, KeyError):
                raise
            raise KeyManagementError(error_msg) from e

    def get_active_key(self) -> Tuple[str, bytes]:
        """Get the currently active encryption key.

        Returns:
            Tuple[str, bytes]: A tuple of (key_id, key_bytes).

        Raises:
            KeyManagementError: If no active key is found.
        """
        if not self.active_key_id:
            # Try to find an active key
            for key_id, meta in self.key_metadata.items():
                if meta.get("is_active", False):
                    self.active_key_id = key_id
                    break

            if not self.active_key_id and self.key_metadata:
                # No active key but we have keys, use the most recent one
                self.active_key_id = max(
                    self.key_metadata.items(), key=lambda x: x[1].get("created_at", "")
                )[0]

            if not self.active_key_id:
                raise KeyManagementError("No encryption keys available")

        try:
            return self.active_key_id, self.get_key(self.active_key_id)
        except Exception as e:
            raise KeyManagementError(f"Failed to get active key: {str(e)}") from e

    def _store_key(self, key_id: str, key: bytes) -> None:
        """Securely store an encryption key.

        Args:
            key_id: The key ID.
            key: The key bytes to store.

        Raises:
            KeyManagementError: If key storage fails.
        """
        try:
            key_path = self.key_storage_path / f"{key_id}.key"
            temp_path = f"{key_path}.tmp"

            # Write to temporary file first
            with open(temp_path, "wb") as f:
                f.write(key)

            # Set secure permissions
            os.chmod(temp_path, 0o600)

            # Atomic rename
            if key_path.exists():
                os.replace(temp_path, key_path)
            else:
                os.rename(temp_path, key_path)

        except Exception as e:
            error_msg = f"Failed to store key {key_id}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
            raise KeyManagementError(error_msg) from e

    def _load_key_metadata(self) -> None:
        """Load key metadata from disk."""
        metadata_path = self.key_storage_path / "metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, "r") as f:
                    self.key_metadata = json.load(f)

                # Find active key
                for key_id, meta in self.key_metadata.items():
                    if meta.get("is_active", False):
                        self.active_key_id = key_id
                        break

            except Exception as e:
                logger.error(f"Failed to load key metadata: {str(e)}", exc_info=True)
                self.key_metadata = {}

    def _save_key_metadata(self) -> None:
        """Save key metadata to disk."""
        metadata_path = self.key_storage_path / "metadata.json"
        temp_path = f"{metadata_path}.tmp"

        try:
            with open(temp_path, "w") as f:
                json.dump(self.key_metadata, f, indent=2)

            # Set secure permissions
            os.chmod(temp_path, 0o600)

            # Atomic write
            if metadata_path.exists():
                os.replace(temp_path, metadata_path)
            else:
                os.rename(temp_path, metadata_path)

        except Exception as e:
            logger.error(f"Failed to save key metadata: {str(e)}", exc_info=True)
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except:
                    pass
            raise

    def get_metrics(self) -> Dict[str, Any]:
        """Get key management metrics.

        Returns:
            Dict containing key management metrics.
        """
        return {
            **self.metrics,
            "total_keys": len(self.key_metadata),
            "active_keys": sum(
                1 for meta in self.key_metadata.values() if meta.get("is_active", False)
            ),
            "key_ids": list(self.key_metadata.keys()),
        }

    def cleanup_old_keys(self, max_age_days: int = 90) -> List[str]:
        """Remove keys older than the specified number of days.

        Args:
            max_age_days: Maximum age in days before a key is considered old.

        Returns:
            List of key IDs that were removed.
        """
        removed = []
        cutoff = datetime.utcnow() - timedelta(days=max_age_days)

        for key_id, meta in list(self.key_metadata.items()):
            if "created_at" in meta:
                created_at = datetime.fromisoformat(meta["created_at"])
                if created_at < cutoff and not meta.get("is_active", False):
                    try:
                        self._delete_key(key_id)
                        removed.append(key_id)
                    except Exception as e:
                        logger.error(f"Failed to delete old key {key_id}: {str(e)}", exc_info=True)

        return removed

    def _delete_key(self, key_id: str) -> None:
        """Delete a key and its metadata.

        Args:
            key_id: ID of the key to delete.

        Raises:
            KeyError: If the key is active or not found.
        """
        if key_id not in self.key_metadata:
            raise KeyError(f"Key {key_id} not found")

        if self.key_metadata[key_id].get("is_active", False):
            raise KeyError(f"Cannot delete active key {key_id}")

        # Remove key file
        key_path = self.key_storage_path / f"{key_id}.key"
        if key_path.exists():
            os.unlink(key_path)

        # Remove from metadata
        del self.key_metadata[key_id]
        self._save_key_metadata()

        # Remove from cache
        self.key_cache.pop(key_id, None)

        logger.info(f"Deleted key: {key_id}")


# Singleton instance
key_manager = KeyManager()
