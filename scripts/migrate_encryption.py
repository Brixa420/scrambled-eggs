"""
Migration script to update existing encrypted data to use Scrambled Eggs encryption.

This script handles the migration of encrypted data from the old encryption scheme
to the new Scrambled Eggs encryption.
"""

import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Set up logging before importing other modules
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(project_root / "migration.log")],
)
logger = logging.getLogger(__name__)

# Now import the application modules
try:
    from app.config.encryption import config as encryption_config
    from app.core.crypto import CryptoEngine
    from app.core.crypto import EncryptionResult as OldEncryptionResult
    from app.crypto.scrambled_eggs import EncryptionResult, ScrambledEggsCrypto
    from app.db.database import get_db
    from app.models.encryption_key import EncryptionKey
except ImportError as e:
    logger.error(f"Failed to import required modules: {e}")
    logger.error(f"Python path: {sys.path}")
    raise

# Logging is already configured at the top


class EncryptionMigrator:
    """Handles migration of encrypted data between encryption schemes."""

    def __init__(self):
        """Initialize the migrator with old and new crypto engines."""
        self.old_crypto = CryptoEngine()
        self.new_crypto = ScrambledEggsCrypto()
        self.metrics = {
            "total_processed": 0,
            "successful_migrations": 0,
            "failed_migrations": 0,
            "migration_errors": [],
            "start_time": datetime.utcnow(),
            "end_time": None,
            "duration_seconds": None,
        }

    def migrate_encryption_key(self, key_data: Dict[str, Any]) -> Optional[EncryptionKey]:
        """Migrate a single encryption key to the new format."""
        try:
            # Check if this key is already in the new format
            if key_data.get("key_type") == "scrambled_eggs":
                logger.info(f"Key {key_data.get('key_id')} is already in the new format")
                return None

            # Decrypt the key material using the old crypto engine
            encrypted_key = OldEncryptionResult.from_dict(key_data["encrypted_key"])
            decrypted_key = self.old_crypto.decrypt(encrypted_key)

            # Generate a new key using the new crypto engine
            new_key = self.new_crypto.generate_key()

            # Create a new encryption key record
            new_key_record = EncryptionKey(
                key_id=key_data["key_id"],
                key_type="scrambled_eggs",
                key_data=new_key,
                created_at=key_data.get("created_at", datetime.utcnow()),
                expires_at=key_data.get("expires_at"),
                metadata={
                    "migrated_from": key_data.get("key_type", "legacy"),
                    "migration_timestamp": datetime.utcnow().isoformat(),
                    **key_data.get("metadata", {}),
                },
            )

            logger.info(f"Successfully migrated key {key_data['key_id']}")
            return new_key_record

        except Exception as e:
            error_msg = f"Error migrating key {key_data.get('key_id')}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.metrics["migration_errors"].append(error_msg)
            self.metrics["failed_migrations"] += 1
            return None

    def migrate_encrypted_data(self, encrypted_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Migrate a single encrypted data record to use the new encryption."""
        try:
            # Check if this data is already in the new format
            if encrypted_data.get("encryption_scheme") == "scrambled_eggs":
                logger.info(f"Data {encrypted_data.get('id')} is already in the new format")
                return None

            # Get the encryption key
            key_id = encrypted_data.get("key_id")
            key_record = self._get_key_record(key_id)
            if not key_record:
                raise ValueError(f"Key not found: {key_id}")

            # Decrypt the data using the old crypto engine
            old_result = OldEncryptionResult(
                ciphertext=bytes.fromhex(encrypted_data["ciphertext"]),
                key_id=key_id,
                iv=bytes.fromhex(encrypted_data["iv"]),
                tag=bytes.fromhex(encrypted_data["tag"]),
                scheme_id=encrypted_data.get("encryption_scheme", "legacy"),
                metadata=encrypted_data.get("metadata", {}),
            )

            decrypted_data = self.old_crypto.decrypt(old_result)

            # Re-encrypt with the new crypto engine
            new_key = self._get_key_material(key_id)
            if not new_key:
                raise ValueError(f"New key not found for key_id: {key_id}")

            new_result = self.new_crypto.encrypt(decrypted_data, new_key)

            # Update the data record
            migrated_data = {
                **encrypted_data,
                "ciphertext": new_result.ciphertext.hex(),
                "iv": new_result.iv.hex(),
                "tag": new_result.auth_tag.hex() if hasattr(new_result, "auth_tag") else None,
                "encryption_scheme": "scrambled_eggs",
                "metadata": {
                    **encrypted_data.get("metadata", {}),
                    "migrated_from": old_result.scheme_id,
                    "migration_timestamp": datetime.utcnow().isoformat(),
                },
            }

            logger.info(f"Successfully migrated data record {encrypted_data.get('id')}")
            return migrated_data

        except Exception as e:
            error_msg = f"Error migrating data {encrypted_data.get('id')}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            self.metrics["migration_errors"].append(error_msg)
            self.metrics["failed_migrations"] += 1
            return None

    def _get_key_record(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get a key record from the database."""
        with get_db() as db:
            return db.query(EncryptionKey).filter(EncryptionKey.key_id == key_id).first()

    def _get_key_material(self, key_id: str) -> Optional[bytes]:
        """Get the key material for a key ID."""
        key_record = self._get_key_record(key_id)
        if not key_record:
            return None
        return key_record.key_data

    def finalize_migration(self):
        """Finalize the migration and log the results."""
        self.metrics["end_time"] = datetime.utcnow()
        self.metrics["duration_seconds"] = (
            self.metrics["end_time"] - self.metrics["start_time"]
        ).total_seconds()

        logger.info("\n" + "=" * 50)
        logger.info("MIGRATION SUMMARY")
        logger.info("=" * 50)
        logger.info(f"Total processed: {self.metrics['total_processed']}")
        logger.info(f"Successful migrations: {self.metrics['successful_migrations']}")
        logger.info(f"Failed migrations: {self.metrics['failed_migrations']}")
        logger.info(f"Duration: {self.metrics['duration_seconds']:.2f} seconds")

        if self.metrics["migration_errors"]:
            logger.warning("\nEncountered the following errors:")
            for error in self.metrics["migration_errors"]:
                logger.warning(f"- {error}")


def get_all_encrypted_data() -> List[Dict[str, Any]]:
    """Retrieve all encrypted data records that need migration."""
    # This is a placeholder implementation. Replace with actual database queries
    # to retrieve encrypted data that needs migration.
    logger.warning("get_all_encrypted_data() is not implemented. No data records will be migrated.")
    return []


def main():
    """Run the migration."""
    logger.info("Starting encryption migration...")
    logger.info(f"Project root: {project_root}")
    logger.info(f"Python path: {sys.path}")

    try:
        migrator = EncryptionMigrator()

        # Migrate encryption keys
        try:
            with get_db() as db:
                keys = db.query(EncryptionKey).all()
                logger.info(f"Found {len(keys)} encryption keys to migrate")

                for key in keys:
                    try:
                        migrator.migrate_encryption_key(key.to_dict())
                        migrator.metrics["total_processed"] += 1
                        migrator.metrics["successful_migrations"] += 1
                    except Exception as e:
                        migrator.metrics["failed_migrations"] += 1
                        migrator.metrics["migration_errors"].append(
                            f"Failed to migrate key {getattr(key, 'id', 'unknown')}: {str(e)}"
                        )
                        logger.error(f"Error migrating key: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error accessing database: {e}", exc_info=True)
            return 1

        # Migrate encrypted data
        try:
            encrypted_data = get_all_encrypted_data()
            logger.info(f"Found {len(encrypted_data)} encrypted data records to migrate")

            for data in encrypted_data:
                try:
                    migrator.migrate_encrypted_data(data)
                    migrator.metrics["total_processed"] += 1
                    migrator.metrics["successful_migrations"] += 1
                except Exception as e:
                    migrator.metrics["failed_migrations"] += 1
                    migrator.metrics["migration_errors"].append(
                        f"Failed to migrate data {data.get('id', 'unknown')}: {str(e)}"
                    )
                    logger.error(f"Error migrating data: {e}", exc_info=True)
        except Exception as e:
            logger.error(f"Error processing encrypted data: {e}", exc_info=True)
            return 1

        return 0

    except Exception as e:
        logger.error(f"Unexpected error during migration: {e}", exc_info=True)
        return 1
    finally:
        try:
            migrator.finalize_migration()
        except Exception as e:
            logger.error(f"Error finalizing migration: {e}", exc_info=True)


if __name__ == "__main__":
    sys.exit(main())
