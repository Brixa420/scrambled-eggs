"""
HSM Command Line Interface

This module provides a command-line interface for HSM operations.
"""

import argparse
import asyncio
import logging
from typing import Any, Dict, Optional

from . import (
    CloudHSMClient,
    HSMFactory,
    HSMKey,
    HSMType,
    KeyType,
    KeyUsage,
    PKCS11Interface,
    SmartCardManager,
    TPMInterface,
)

logger = logging.getLogger(__name__)


class HSMCli:
    """Command-line interface for HSM operations."""

    def __init__(self):
        """Initialize the HSM CLI."""
        self.hsm = None
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or environment variables."""
        # TODO: Implement configuration loading
        return {"hsm_type": "cloud", "cloud": {"provider": "aws_kms", "region": "us-west-2"}}

    async def initialize_hsm(self, hsm_type: Optional[HSMType] = None) -> None:
        """Initialize the HSM connection."""
        hsm_type = hsm_type or HSMType[self.config["hsm_type"].upper()]

        logger.info(f"Initializing {hsm_type.name} HSM...")

        try:
            self.hsm = HSMFactory.create_hsm(hsm_type, self.config.get(hsm_type.name.lower(), {}))
            await self.hsm.initialize()
            logger.info(f"Successfully connected to {hsm_type.name} HSM")
        except Exception as e:
            logger.error(f"Failed to initialize HSM: {str(e)}")
            raise

    async def create_key(self, key_type: str, key_size: int, **kwargs) -> HSMKey:
        """Create a new cryptographic key."""
        if not self.hsm:
            await self.initialize_hsm()

        try:
            key = await self.hsm.create_key(
                key_type=KeyType[key_type.upper()], key_size=key_size, **kwargs
            )
            logger.info(f"Created key: {key.key_id}")
            return key
        except Exception as e:
            logger.error(f"Failed to create key: {str(e)}")
            raise

    async def list_keys(self) -> None:
        """List all available keys."""
        if not self.hsm:
            await self.initialize_hsm()

        try:
            keys = await self.hsm.list_keys()
            if not keys:
                print("No keys found")
                return

            print("\nAvailable Keys:")
            print("-" * 80)
            for key in keys:
                print(f"ID: {key.key_id}")
                print(f"Type: {key.key_type.name}")
                print(f"Size: {key.key_size} bits")
                if hasattr(key, "label") and key.label:
                    print(f"Label: {key.label}")
                print("-" * 80)

        except Exception as e:
            logger.error(f"Failed to list keys: {str(e)}")
            raise

    async def close(self) -> None:
        """Close the HSM connection."""
        if self.hsm:
            await self.hsm.disconnect()
            self.hsm = None


async def main():
    """Main entry point for the HSM CLI."""
    parser = argparse.ArgumentParser(description="HSM Command Line Interface")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create key command
    create_parser = subparsers.add_parser("create-key", help="Create a new key")
    create_parser.add_argument(
        "--type",
        type=str,
        required=True,
        choices=[t.name.lower() for t in KeyType],
        help="Key type",
    )
    create_parser.add_argument("--size", type=int, required=True, help="Key size in bits")
    create_parser.add_argument("--label", type=str, help="Key label")

    # List keys command
    list_parser = subparsers.add_parser("list-keys", help="List all keys")

    # Test command
    test_parser = subparsers.add_parser("test", help="Run HSM tests")

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    cli = HSMCli()

    try:
        if args.command == "create-key":
            await cli.initialize_hsm()
            key = await cli.create_key(key_type=args.type, key_size=args.size, label=args.label)
            print(f"Successfully created key: {key.key_id}")

        elif args.command == "list-keys":
            await cli.list_keys()

        elif args.command == "test":
            print("Running HSM tests...")
            import sys

            import pytest

            sys.exit(pytest.main(["-xvs", "tests/test_hsm_integration.py"]))

        else:
            parser.print_help()

    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1
    finally:
        await cli.close()

    return 0


if __name__ == "__main__":
    asyncio.run(main())
