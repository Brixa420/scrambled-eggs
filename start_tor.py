"""
Script to start the Tor manager with the correct Tor binary path.
"""

import logging
import os
import sys

from app.network.tor_manager import TorManager

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    """Start the Tor manager with the correct configuration."""
    # Set the path to the Tor binary
    tor_binary = r"C:\Users\Admin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe"

    # Ensure the Tor binary exists
    if not os.path.exists(tor_binary):
        logger.error(f"Tor binary not found at: {tor_binary}")
        logger.error("Please check the path and try again.")
        return 1

    # Initialize the Tor manager
    try:
        tor_manager = TorManager(
            control_port=9051,
            socks_port=9050,
            tor_data_dir=os.path.expanduser("~/.tor/scrambled-eggs"),
            tor_binary=tor_binary,
        )

        logger.info("Starting Tor manager...")
        if tor_manager.start():
            logger.info("✅ Tor started successfully!")
            logger.info(f"Control port: {tor_manager.control_port}")
            logger.info(f"SOCKS port: {tor_manager.socks_port}")

            # Keep the script running until interrupted
            try:
                import time

                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("\nShutting down Tor...")
                tor_manager.stop()
                logger.info("Tor has been stopped.")
        else:
            logger.error("❌ Failed to start Tor.")
            return 1

    except Exception as e:
        logger.exception("An error occurred while starting Tor:")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
