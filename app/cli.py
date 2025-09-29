"""
Command-line interface for Scrambled Eggs.
"""

import argparse
import logging
import sys
from typing import List, Optional

from PySide6.QtWidgets import QApplication

from app.managers.app_manager import AppManager
from app.ui.main_window import MainWindow


def setup_logging(verbose: bool = False):
    """Configure logging for the application."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("scrambled_eggs.log")],
    )


def parse_args(args: List[str]) -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Scrambled Eggs - Secure P2P Messaging",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Global arguments
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # GUI command
    gui_parser = subparsers.add_parser("gui", help="Start the graphical user interface")
    gui_parser.add_argument("--fullscreen", action="store_true", help="Start in fullscreen mode")
    gui_parser.add_argument("--maximized", action="store_true", help="Start maximized")

    # Account commands
    account_parser = subparsers.add_parser("account", help="Account management commands")
    account_subparsers = account_parser.add_subparsers(dest="account_command")

    # Create account
    create_parser = account_subparsers.add_parser("create", help="Create a new account")
    create_parser.add_argument("username", help="Username for the new account")

    # List accounts
    account_subparsers.add_parser("list", help="List all accounts")

    # Version command
    subparsers.add_parser("version", help="Show version information")

    return parser.parse_args(args)


def run_gui(args: argparse.Namespace) -> int:
    """Run the GUI application."""
    app = QApplication(sys.argv)

    # Initialize application manager
    app_manager = AppManager()

    # Create and show main window
    main_window = MainWindow(app_manager)

    if args.fullscreen:
        main_window.showFullScreen()
    elif args.maximized:
        main_window.showMaximized()
    else:
        main_window.show()

    return app.exec()


def handle_account_command(args: argparse.Namespace) -> int:
    """Handle account management commands."""
    if args.account_command == "create":
        print(f"Creating account: {args.username}")
        # TODO: Implement account creation
        return 0
    elif args.account_command == "list":
        print("Listing accounts...")
        # TODO: Implement account listing
        return 0
    else:
        print("Unknown account command")
        return 1


def main(args: Optional[List[str]] = None) -> int:
    """Main entry point for the CLI."""
    if args is None:
        args = sys.argv[1:]

    # Parse command line arguments
    parsed_args = parse_args(args)

    # Set up logging
    setup_logging(parsed_args.verbose)

    # Execute the appropriate command
    if parsed_args.command == "gui":
        return run_gui(parsed_args)
    elif parsed_args.command == "account":
        return handle_account_command(parsed_args)
    elif parsed_args.command == "version":
        from app import __version__

        print(f"Scrambled Eggs v{__version__}")
        return 0
    else:
        # No command provided, show help
        parse_args(["--help"])
        return 1


if __name__ == "__main__":
    sys.exit(main())
