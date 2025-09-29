"""
Run script for Scrambled Eggs application with proper password handling.
"""

import configparser
import getpass
import importlib.util
import logging
import os
import sys
from pathlib import Path

# Set up basic logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("scrambled_eggs_debug.log")],
)
logger = logging.getLogger(__name__)

# Load configuration
config = configparser.ConfigParser()
config_path = Path(__file__).parent / "config.ini"
if config_path.exists():
    config.read(config_path)
    logger.info(f"Loaded configuration from {config_path}")
else:
    logger.warning(f"Configuration file not found: {config_path}")


def apply_patches():
    """Apply all necessary patches to handle missing methods and functionality."""
    # Apply memory protection patch
    try:
        from scrambled_eggs.security import memory_protection as mp

        class MemoryProtection:
            """Mock implementation of MemoryProtection to handle missing methods."""

            @staticmethod
            def secure_erase(data):
                """Mock secure erase method."""
                logger.debug("Secure erase called (mock implementation)")
                if isinstance(data, (bytearray, bytes)):
                    data[:] = b"\x00" * len(data)
                elif hasattr(data, "clear"):
                    data.clear()
                return True

            @staticmethod
            def protect_memory():
                """Mock protect memory method."""
                logger.debug("Memory protection enabled (mock implementation)")
                return True

        mp.MemoryProtector = MemoryProtection()
        logger.info("Applied memory protection patch")
    except Exception as e:
        logger.error(f"Failed to apply memory protection patch: {e}")
        return False

    # Apply KeyDerivation patch
    try:
        from scrambled_eggs.security.key_derivation import KeyDerivation

        # Add the missing derive_key class method
        @classmethod
        def derive_key(cls, password, salt=None, key_length=32, **kwargs):
            """Derive a key from a password.

            Args:
                password: The password to derive the key from
                salt: Optional salt (randomly generated if not provided)
                key_length: Desired key length in bytes
                **kwargs: Additional arguments to pass to KeyDerivation

            Returns:
                Tuple of (derived_key, salt_used)
            """
            kdf = cls(salt=salt, **kwargs)
            derived_key = kdf.derive(password, key_length)
            return derived_key, kdf.salt

        # Apply the patch
        KeyDerivation.derive_key = derive_key
        logger.info("Applied KeyDerivation patch")
        return True

    except Exception as e:
        logger.error(f"Failed to apply KeyDerivation patch: {e}")
        return False


def main():
    try:
        # Apply all necessary patches
        if not apply_patches():
            logger.warning(
                "One or more patches failed to apply, continuing with limited functionality"
            )

        # Set environment variables from config
        if config.getboolean("security", "enable_memory_protection", fallback=False):
            os.environ["SCRAMBLED_EGGS_ENABLE_MEMORY_PROTECTION"] = "1"
        else:
            os.environ["SCRAMBLED_EGGS_ENABLE_MEMORY_PROTECTION"] = "0"

        # Set preferred KDF
        os.environ["SCRAMBLED_EGGS_PREFERRED_KDF"] = config.get(
            "security", "preferred_kdf", fallback="pbkdf2"
        )

        # Import after setting environment variables and applying patches
        from scrambled_eggs.controller import ScrambledEggsController
        from scrambled_eggs.core import ScrambledEggs

        # Get password securely
        print("Starting Scrambled Eggs...")
        password = getpass.getpass("Please enter your password: ")

        if not password:
            logger.error("Error: Password cannot be empty")
            return 1

        logger.info("Initializing encryption engine...")
        try:
            engine = ScrambledEggs(password=password)
            logger.info("Encryption engine initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize encryption engine: {e}", exc_info=True)
            logger.error("This might be due to missing dependencies or configuration issues.")
            return 1

        # Initialize the controller with the engine
        logger.info("Initializing controller...")
        controller = ScrambledEggsController(engine)

        # Start the application
        logger.info("Starting application...")
        controller.start()

        logger.info("Application started successfully")
        return 0

    except KeyboardInterrupt:
        logger.info("\nApplication terminated by user")
        return 0
    except Exception as e:
        logger.exception("An unexpected error occurred:")
        return 1


if __name__ == "__main__":
    sys.exit(main())
