"""
Setup encryption for Scrambled Eggs application.

This script initializes the encryption system with the necessary keys and configuration.
"""

import json
import logging
import os
import sys
from getpass import getpass
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(project_root / "encryption_setup.log")],
)
logger = logging.getLogger(__name__)


def setup_encryption():
    """Set up the encryption system with a new master key."""
    try:
        # Create necessary directories
        data_dir = project_root / "data"
        keys_dir = data_dir / "keys"

        for directory in [data_dir, keys_dir]:
            directory.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")

        # Get master key from user
        print("\n=== Scrambled Eggs Encryption Setup ===\n")
        print("Please enter a strong master encryption key (at least 32 characters).")
        print("This key will be used to protect your encryption keys.")
        print(
            "IMPORTANT: Keep this key safe! If you lose it, you won't be able to decrypt your data!\n"
        )

        while True:
            master_key = getpass("Enter master key (hidden input): ").strip()
            confirm_key = getpass("Confirm master key (hidden input): ").strip()

            if master_key != confirm_key:
                print("\nError: Keys do not match. Please try again.\n")
                continue

            if len(master_key) < 32:
                print(
                    f"\nError: Master key must be at least 32 characters (got {len(master_key)}).\n"
                )
                continue

            break

        # Initialize the key service
        from app.services.key_service import key_service

        # Generate a new encryption key
        encrypted_key, key_id = key_service.create_key(master_key.encode())
        logger.info(f"Generated new encryption key: {key_id}")

        # Save the configuration
        config = {
            "version": 1,
            "key_id": key_id,
            "key_storage": str(keys_dir.absolute()),
            "encryption_type": "scrambled_eggs",
            "key_rotation": "quarterly",
            "key_history_size": 3,
        }

        config_path = data_dir / "encryption_config.json"
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        logger.info(f"Encryption configuration saved to {config_path}")

        # Create a backup of the master key (in a real app, this would be more secure)
        backup_path = data_dir / "master_key_backup.txt"
        with open(backup_path, "w") as f:
            f.write("=== MASTER KEY BACKUP ===\n")
            f.write("WARNING: Keep this file in a secure location!\n\n")
            f.write(f"Key ID: {key_id}\n")
            f.write(f"Master Key: {master_key}\n")

        logger.warning(f"Master key backup saved to {backup_path}")

        return True

    except Exception as e:
        logger.error(f"Failed to set up encryption: {e}", exc_info=True)
        return False


if __name__ == "__main__":
    try:
        if setup_encryption():
            print("\n✅ Encryption system set up successfully!")
            print("\nNext steps:")
            print("1. Securely store your master key backup")
            print("2. Restart your application to use the new encryption settings")
            print(
                "\n⚠️  WARNING: Keep your master key safe! If you lose it, you won't be able to decrypt your data!"
            )
        else:
            print("\n❌ Failed to set up encryption. Check the logs for details.")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
