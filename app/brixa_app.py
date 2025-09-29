"""
Brixa - Secure P2P Communication Application
Main application class that ties all components together.
"""

import asyncio
import logging
import signal
import sys
from typing import Any, Dict, Optional

from app.config.brixa_config import BrixaConfig, get_config
from app.file_transfer.secure_file_sharing import SecureFileSharing
from app.network.tor_integration import TorManager
from app.p2p.p2p_manager import P2PManager
from app.security.scrambled_eggs_crypto import ClippyAI, ScrambledEggsCrypto


class BrixaApp:
    """Main application class for Brixa."""

    def __init__(self, config: Optional[BrixaConfig] = None):
        """Initialize the Brixa application."""
        self.config = config or get_config()
        self.logger = logging.getLogger(__name__)
        self.running = False

        # Core components
        self.tor_manager: Optional[TorManager] = None
        self.crypto: Optional[ScrambledEggsCrypto] = None
        self.clippy: Optional[ClippyAI] = None
        self.p2p_manager: Optional[P2PManager] = None
        self.file_sharing: Optional[SecureFileSharing] = None

        # UI components will be initialized separately
        self.ui_components = {}

        # Set up signal handlers
        self._setup_signal_handlers()

    async def initialize(self):
        """Initialize all components."""
        self.logger.info("Initializing Brixa...")

        try:
            # Initialize Tor if enabled
            if self.config["tor"]["enabled"]:
                await self._initialize_tor()

            # Initialize core components
            self._initialize_core_components()

            # Initialize P2P networking
            await self._initialize_networking()

            # Initialize file sharing
            self._initialize_file_sharing()

            # Initialize UI components
            self._initialize_ui()

            self.logger.info("Brixa initialization complete")
            return True

        except Exception as e:
            self.logger.critical(f"Failed to initialize Brixa: {str(e)}", exc_info=True)
            await self.shutdown()
            return False

    async def _initialize_tor(self):
        """Initialize the Tor connection."""
        self.logger.info("Initializing Tor...")
        self.tor_manager = self.config.get_component("tor")

        if not self.tor_manager.is_running():
            await self.tor_manager.start_tor()

        # Wait for Tor to be ready
        if not await self.tor_manager.is_connected():
            self.logger.warning("Tor connection not available, some features may be limited")

    def _initialize_core_components(self):
        """Initialize core security components."""
        self.logger.info("Initializing core components...")

        # Initialize encryption
        self.crypto = self.config.get_component("crypto")
        self.clippy = self.config.get_component("clippy")

        # Start Clippy AI monitoring
        self.clippy.start_monitoring()

    async def _initialize_networking(self):
        """Initialize P2P networking."""
        self.logger.info("Initializing P2P networking...")

        self.p2p_manager = self.config.get_component("p2p")

        # Register message handlers
        self.p2p_manager.register_message_handler("chat", self._handle_chat_message)
        self.p2p_manager.register_message_handler("call", self._handle_call_request)

        # Start listening for incoming connections
        await self.p2p_manager.start_listening()

    def _initialize_file_sharing(self):
        """Initialize file sharing component."""
        self.logger.info("Initializing file sharing...")
        self.file_sharing = self.config.get_component("file_sharing")

        # Register file transfer callbacks
        self.file_sharing.on_transfer_progress = self._on_file_transfer_progress
        self.file_sharing.on_transfer_complete = self._on_file_transfer_complete

    def _initialize_ui(self):
        """Initialize UI components."""
        self.logger.info("Initializing UI...")

        # Import UI components here to avoid circular imports
        from app.ui.components.chat_window import ChatWindow
        from app.ui.components.contact_manager import ContactManager
        from app.ui.main_window import MainWindow

        # Initialize main window
        self.main_window = MainWindow(self)
        self.ui_components["main_window"] = self.main_window

        # Initialize other UI components
        self.contact_manager = ContactManager(self)
        self.chat_window = ChatWindow(self)

        # Connect signals
        self._connect_ui_signals()

        # Show main window
        self.main_window.show()

    def _connect_ui_signals(self):
        """Connect UI signals to handlers."""
        # Connect menu actions
        self.main_window.action_quit.triggered.connect(self.quit)
        self.main_window.action_settings.triggered.connect(self.show_settings)

        # Connect contact management
        self.contact_manager.contact_selected.connect(self.chat_window.set_active_contact)

    async def run(self):
        """Run the application's main event loop."""
        if not await self.initialize():
            return False

        self.running = True
        self.logger.info("Brixa is running")

        try:
            # Start the asyncio event loop
            while self.running:
                await asyncio.sleep(1)

                # Update UI and check for events
                self._process_events()

        except asyncio.CancelledError:
            self.logger.info("Shutting down...")
        except Exception as e:
            self.logger.critical(f"Fatal error: {str(e)}", exc_info=True)
        finally:
            await self.shutdown()

    async def shutdown(self):
        """Shut down the application cleanly."""
        if not self.running:
            return

        self.logger.info("Shutting down Brixa...")
        self.running = False

        # Shutdown components in reverse order of initialization
        try:
            # Close UI
            if hasattr(self, "main_window"):
                self.main_window.close()

            # Stop P2P connections
            if self.p2p_manager:
                await self.p2p_manager.shutdown()

            # Stop Tor
            if self.tor_manager and self.tor_manager.is_running():
                self.tor_manager.stop_tor()

            # Save configuration
            self.config.save_config()

        except Exception as e:
            self.logger.error(f"Error during shutdown: {str(e)}")

        self.logger.info("Brixa has been shut down")

    def quit(self):
        """Quit the application."""
        asyncio.create_task(self.shutdown())

    def _setup_signal_handlers(self):
        """Set up signal handlers for clean shutdown."""
        if sys.platform != "win32":
            # Unix-like systems
            for sig in (signal.SIGTERM, signal.SIGINT):
                signal.signal(sig, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(self.shutdown())

    # Event handlers

    async def _handle_chat_message(self, data: Dict[str, Any]):
        """Handle incoming chat message."""
        try:
            peer_id = data.get("peer_id")
            message = data.get("message")

            if not peer_id or not message:
                return

            # Decrypt message if needed
            if isinstance(message, dict) and "encrypted" in message:
                message = self.crypto.decrypt_message(message)

            # Update UI
            if hasattr(self, "chat_window"):
                self.chat_window.display_message(peer_id, message)

        except Exception as e:
            self.logger.error(f"Error handling chat message: {str(e)}")

    async def _handle_call_request(self, data: Dict[str, Any]):
        """Handle incoming call request."""
        try:
            call_type = data.get("type", "audio")
            peer_id = data.get("peer_id")

            if not peer_id:
                return

            # Show call UI
            if hasattr(self, "main_window"):
                self.main_window.show_call_ui(peer_id, call_type, incoming=True)

        except Exception as e:
            self.logger.error(f"Error handling call request: {str(e)}")

    def _on_file_transfer_progress(self, transfer_id: str, progress: float):
        """Update file transfer progress in the UI."""
        if hasattr(self, "file_transfer_dialog"):
            self.file_transfer_dialog.update_progress(transfer_id, progress)

    def _on_file_transfer_complete(self, transfer_id: str, success: bool, error: str = None):
        """Handle file transfer completion."""
        if hasattr(self, "file_transfer_dialog"):
            self.file_transfer_dialog.transfer_complete(transfer_id, success, error)

    def _process_events(self):
        """Process pending events and update the UI."""
        # Update status indicators
        if hasattr(self, "status_bar"):
            self.status_bar.update_connection_status(
                tor_connected=self.tor_manager.is_connected() if self.tor_manager else False,
                p2p_connected=len(self.p2p_manager.connections) > 0 if self.p2p_manager else False,
            )

        # Process UI events
        if hasattr(self, "main_window"):
            self.main_window.process_events()

    # Public API methods

    async def send_message(self, peer_id: str, message: str) -> bool:
        """Send a message to a peer."""
        if not self.p2p_manager:
            return False

        try:
            # Encrypt message
            encrypted = self.crypto.encrypt_message(message)

            # Send via P2P
            return await self.p2p_manager.send_message(
                peer_id, {"type": "chat", "message": encrypted, "timestamp": int(time.time())}
            )

        except Exception as e:
            self.logger.error(f"Failed to send message: {str(e)}")
            return False

    async def start_call(self, peer_id: str, call_type: str = "audio") -> bool:
        """Start a voice or video call with a peer."""
        if not self.p2p_manager:
            return False

        try:
            # Send call request
            await self.p2p_manager.send_message(
                peer_id, {"type": "call", "call_type": call_type, "timestamp": int(time.time())}
            )

            # Show call UI
            if hasattr(self, "main_window"):
                self.main_window.show_call_ui(peer_id, call_type, incoming=False)

            return True

        except Exception as e:
            self.logger.error(f"Failed to start call: {str(e)}")
            return False

    async def send_file(self, peer_id: str, file_path: str) -> str:
        """Send a file to a peer."""
        if not self.file_sharing:
            return None

        try:
            return await self.file_sharing.send_file(peer_id, file_path)
        except Exception as e:
            self.logger.error(f"Failed to send file: {str(e)}")
            return None

    def show_settings(self):
        """Show application settings dialog."""
        if hasattr(self, "settings_dialog"):
            self.settings_dialog.show()


def main():
    """Main entry point for the Brixa application."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("brixa.log")],
    )

    # Create and run the application
    app = BrixaApp()

    try:
        # Run the application
        asyncio.run(app.run())
    except KeyboardInterrupt:
        logging.info("Shutdown requested by user")
    except Exception as e:
        logging.critical(f"Fatal error: {str(e)}", exc_info=True)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
