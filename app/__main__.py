#!/usr/bin/env python3
"""
Scrambled Eggs - Secure P2P Messaging

Main entry point for the application.
"""
import argparse
import asyncio
import logging
import sys
from pathlib import Path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("scrambled_eggs.log")],
)

logger = logging.getLogger(__name__)


async def run_gui():
    """Run the graphical user interface."""
    try:
        from app.network.p2p_manager import P2PManager
        from app.security.gate_system import GateSystem
        from app.security.security_manager import SecurityManager
        from app.ui.app import create_app

        logger.info("Starting Scrambled Eggs GUI...")

        # Initialize components
        security_manager = SecurityManager()
        gate_system = GateSystem()
        p2p_manager = P2PManager(security_manager, gate_system)

        # Create and start the application
        app = create_app(p2p_manager, security_manager, gate_system)
        await app.start()

        # Keep the application running
        while True:
            await asyncio.sleep(1)

    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.exception("An error occurred:")
    finally:
        # Clean up
        if "app" in locals():
            await app.stop()
        logger.info("Application stopped")


def run_cli():
    """Run the command line interface."""
    from app.cli import main as cli_main

    return cli_main()


def main():
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(description="Scrambled Eggs - Secure P2P Messaging")
    parser.add_argument("--gui", action="store_true", help="Launch the graphical user interface")
    parser.add_argument("--cli", action="store_true", help="Launch the command line interface")

    args = parser.parse_args()

    # Default to GUI if no interface is specified
    if not args.cli or args.gui:
        asyncio.run(run_gui())
    else:
        sys.exit(run_cli())


if __name__ == "__main__":
    main()
