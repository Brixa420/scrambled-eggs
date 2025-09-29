"""
Command-line interface for Scrambled Eggs P2P Messaging.
"""

import argparse
import asyncio
import json
import os
import sys
from getpass import getpass
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
import uvicorn
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .p2p.webrtc_manager import WebRTCManager
from .signaling.server import app as signaling_app

# Initialize console for rich output
console = Console()


class CLIError(Exception):
    """Custom exception for CLI errors."""

    pass


def print_banner():
    """Print the application banner."""
    banner = """
   _____                                  _           _____                      
  / ____|                                | |         |  __ \                    
 | (___   ___ _ __ __ _ _ __   ___ _ __ | |_ _   _  | |__) |___  ___ ___  _ __  
  \___ \ / __| '__/ _` | '_ \ / _ \ '_ \| __| | | | |  _  // _ \/ __/ _ \| '_ \ 
  ____) | (__| | | (_| | |_) |  __/ | | | |_| |_| | | | \ \  __/ (_| (_) | | | |
 |_____/ \___|_|  \__,_| .__/ \___|_| |_|\__|\__, | |_|  \_\___|\___\___/|_| |_|
                       | |                     __/ |                             
                       |_|                    |___/                              
    """
    console.print(
        Panel.fit(
            f"[bold cyan]{banner}[/bold cyan]\n"
            "[bold green]Scrambled Eggs - Secure P2P Messaging[/bold green]\n"
            "[italic]Version 1.1.0 - End-to-End Encrypted Communication[/italic]",
            border_style="blue",
        )
    )


def get_password(confirm: bool = False) -> str:
    """Securely get password from user with rich console."""
    while True:
        password = console.input("[bold]Enter password: [/bold]", password=True)
        if not password:
            console.print("[red]Error:[/red] Password cannot be empty")
            continue

        if confirm:
            confirm_pw = console.input("[bold]Confirm password: [/bold]", password=True)
            if password != confirm_pw:
                console.print("[red]Error:[/red] Passwords do not match")
                continue

        return password


async def start_server(args):
    """Start the signaling server."""
    host = args.host or "0.0.0.0"
    port = args.port or 8000

    console.print(f"[bold]Starting signaling server on {host}:{port}[/bold]")
    console.print("Press Ctrl+C to stop the server\n")

    config = uvicorn.Config(
        signaling_app, host=host, port=port, log_level="info", reload=args.reload
    )
    server = uvicorn.Server(config)

    try:
        await server.serve()
    except KeyboardInterrupt:
        console.print("\n[bold]Stopping server...[/bold]")
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        return 1

    return 0


async def start_client(args):
    """Start the P2P messaging client."""
    from PySide6.QtWidgets import QApplication

    from .gui.chat_window import ChatWindow

    console.print("[bold]Starting Scrambled Eggs P2P Client[/bold]")
    console.print("Press Ctrl+C to exit\n")

    # Initialize WebRTC manager
    webrtc_manager = WebRTCManger({"signaling_url": args.server or "ws://localhost:8000/ws/"})

    # Start the Qt application
    app = QApplication(sys.argv)

    # Initialize and show the chat window
    chat_window = ChatWindow(webrtc_manager)
    chat_window.show()

    # Run the application
    return app.exec()


async def list_contacts(args):
    """List all contacts."""
    config_path = Path.home() / ".scrambled-eggs" / "config.json"
    if not config_path.exists():
        console.print("[yellow]No contacts found.[/yellow]")
        return 0

    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        contacts = config.get("contacts", {})
        if not contacts:
            console.print("[yellow]No contacts found.[/yellow]")
            return 0

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Public Key")
        table.add_column("Last Seen")
        table.add_column("Status")

        for contact_id, contact in contacts.items():
            status = (
                "[green]Online[/green]" if contact.get("online", False) else "[red]Offline[/red]"
            )
            table.add_row(
                contact_id[:8] + "...",
                contact.get("name", "Unknown"),
                contact.get("public_key", "")[:16] + "...",
                contact.get("last_seen", "Never"),
                status,
            )

        console.print(table)
        return 0

    except Exception as e:
        console.print(f"[red]Error loading contacts:[/red] {str(e)}")
        return 1


async def add_contact(args):
    """Add a new contact."""
    contact_id = args.contact_id
    name = args.name or input("Contact name: ")
    public_key = args.public_key or input("Contact's public key: ")

    if not all([contact_id, name, public_key]):
        console.print("[red]Error:[/red] Contact ID, name, and public key are required")
        return 1

    config_path = Path.home() / ".scrambled-eggs" / "config.json"
    config = {"contacts": {}}

    if config_path.exists():
        try:
            with open(config_path, "r") as f:
                config = json.load(f)
        except Exception as e:
            console.print(f"[yellow]Warning:[/yellow] Could not load existing config: {str(e)}")

    # Add or update contact
    config.setdefault("contacts", {})[contact_id] = {
        "name": name,
        "public_key": public_key,
        "added_at": str(datetime.now().isoformat()),
    }

    try:
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)

        console.print(f"[green]✓[/green] Contact [bold]{name}[/bold] added successfully!")
        return 0
    except Exception as e:
        console.print(f"[red]Error saving contact:[/red] {str(e)}")
        return 1


def get_webrtc_manager(args) -> WebRTCManager:
    """Initialize and return a WebRTC manager with the given configuration."""
    config = {
        "signaling_url": args.server or "ws://localhost:8000/ws/",
        "stun_servers": [
            "stun:stun.l.google.com:19302",
            "stun:stun1.l.google.com:19302",
            "stun:stun2.l.google.com:19302",
        ],
    }

    return WebRTCManager(config)

    if os.path.exists(args.output) and not args.force:
        print(f"Error: Output file '{args.output}' already exists. Use --force to overwrite.")
        return 1

    try:
        password = get_password(confirm=True)
        print(f"Encrypting {args.input}...")
        metadata = encrypt_file(args.input, args.output, password, layers=args.layers)

        print(f"\n✅ Successfully encrypted to {args.output}")
        print(f"Layers used: {metadata.get('layers_used', 'N/A')}")
        print(f"Breach count: {metadata.get('breach_count', 0)}")
        return 0

    except EncryptionError as e:
        print(f"\n❌ Encryption failed: {str(e)}")
        return 1
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {str(e)}")
        return 1


def decrypt_command(args):
    """Handle the decrypt command."""
    if not os.path.exists(args.input):
        print(f"Error: Input file '{args.input}' not found")
        return 1

    if os.path.exists(args.output) and not args.force:
        print(f"Error: Output file '{args.output}' already exists. Use --force to overwrite.")
        return 1

    try:
        password = get_password()
        print(f"Decrypting {args.input}...")
        metadata = decrypt_file(args.input, args.output, password)

        print(f"\n✅ Successfully decrypted to {args.output}")
        print(f"Layers used: {metadata.get('layers_used', 'N/A')}")
        print(f"Breach count: {metadata.get('breach_count', 0)}")
        return 0

    except DecryptionError as e:
        print(f"\n❌ Decryption failed: {str(e)}")
        return 1
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {str(e)}")
        return 1


def main(args: Optional[list] = None) -> int:
    """Main entry point for the CLI."""
    # Print banner
    print_banner()

    # Create the main parser
    parser = argparse.ArgumentParser(description="Scrambled Eggs - Secure P2P Messaging")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Command to execute")

    # Server command
    server_parser = subparsers.add_parser("server", help="Start the signaling server")
    server_parser.add_argument("--host", help="Host to bind the server to")
    server_parser.add_argument("--port", type=int, help="Port to bind the server to")
    server_parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    server_parser.set_defaults(func=start_server)

    # Client command
    client_parser = subparsers.add_parser("client", help="Start the P2P messaging client")
    client_parser.add_argument("--server", help="Signaling server URL")
    client_parser.set_defaults(func=start_client)

    # Contacts commands
    contacts_parser = subparsers.add_parser("contacts", help="Manage contacts")
    contacts_subparsers = contacts_parser.add_subparsers(dest="contacts_command", required=True)

    # List contacts
    list_parser = contacts_subparsers.add_parser("list", help="List all contacts")
    list_parser.set_defaults(func=list_contacts)

    # Add contact
    add_parser = contacts_subparsers.add_parser("add", help="Add a new contact")
    add_parser.add_argument("contact_id", help="Contact ID")
    add_parser.add_argument("--name", help="Contact name")
    add_parser.add_argument("--public-key", help="Contact's public key")
    add_parser.set_defaults(func=add_contact)

    # Version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=lambda _: console.print("Scrambled Eggs P2P v1.1.0"))

    # Parse arguments
    parsed_args = parser.parse_args(args)

    # Run the appropriate function
    try:
        if asyncio.iscoroutinefunction(parsed_args.func):
            return asyncio.run(parsed_args.func(parsed_args))
        else:
            return parsed_args.func(parsed_args)
    except KeyboardInterrupt:
        console.print("\n[bold]Operation cancelled by user[/bold]")
        return 0
    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        if parsed_args.verbose:
            import traceback

            console.print(traceback.format_exc())
        return 1

    # Encrypt command
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt_parser.add_argument("input", help="Input file to encrypt")
    encrypt_parser.add_argument("output", help="Output file for encrypted data")
    encrypt_parser.add_argument(
        "-l", "--layers", type=int, default=100, help="Number of hashing layers (default: 100)"
    )
    encrypt_parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it exists"
    )
    encrypt_parser.set_defaults(func=encrypt_command)

    # Decrypt command
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    decrypt_parser.add_argument("input", help="Input file to decrypt")
    decrypt_parser.add_argument("output", help="Output file for decrypted data")
    decrypt_parser.add_argument(
        "-f", "--force", action="store_true", help="Overwrite output file if it exists"
    )
    decrypt_parser.set_defaults(func=decrypt_command)

    # Parse arguments
    if args is None:
        args = sys.argv[1:]

    # If no arguments, show help
    if not args:
        print_banner()
        parser.print_help()
        return 0

    try:
        parsed_args = parser.parse_args(args)
        return parsed_args.func(parsed_args)
    except ScrambledEggsError as e:
        print(f"Error: {str(e)}")
        return 1
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
