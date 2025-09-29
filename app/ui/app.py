"""
Main Application UI for Scrambled Eggs P2P Messenger
"""

import logging

import ipywidgets as widgets
from IPython.display import display

from app.ui.components.contact_manager import create_contact_manager
from app.ui.components.file_transfer import create_file_transfer_manager

# Import UI components
from app.ui.components.security_dashboard import create_security_dashboard

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ScrambledEggsApp:
    """Main application class for Scrambled Eggs P2P Messenger."""

    def __init__(self, p2p_manager, security_manager, gate_system):
        """Initialize the application.

        Args:
            p2p_manager: Instance of P2PManager
            security_manager: Instance of SecurityManager
            gate_system: Instance of GateSystem
        """
        self.p2p_manager = p2p_manager
        self.security_manager = security_manager
        self.gate_system = gate_system

        # UI state
        self.current_chat = None  # ID of the current chat (contact_id or group_id)
        self.is_chat_encrypted = True

        # Initialize UI components
        self._init_ui()

        # Start background tasks
        self._start_background_tasks()

    def _init_ui(self):
        """Initialize the user interface."""
        # Create main tabs
        self.tabs = widgets.Tab()

        # Create the main layout
        self.main_layout = widgets.VBox([self._create_header(), self.tabs])

        # Initialize tabs
        self._init_chat_tab()
        self._init_contacts_tab()
        self._init_security_tab()
        self._init_settings_tab()

        # Set tab titles
        self.tabs.set_title(0, "Chats")
        self.tabs.set_title(1, "Contacts")
        self.tabs.set_title(2, "Security")
        self.tabs.set_title(3, "Settings")

    def _create_header(self):
        """Create the application header."""
        # App title
        title = widgets.HTML("<h1 style='margin: 0; padding: 10px;'>🔐 Scrambled Eggs</h1>")

        # Connection status
        self.connection_status = widgets.HTML(
            "<div style='text-align: right;'>Status: <span style='color: green;'>Connected</span></div>"
        )

        # Header layout
        header = widgets.HBox(
            [
                title,
                widgets.HBox(
                    [self.connection_status],
                    layout={"width": "100%", "justify_content": "flex-end"},
                ),
            ],
            layout={"border": "1px solid #e0e0e0", "padding": "5px"},
        )

        return header

    def _init_chat_tab(self):
        """Initialize the chat tab."""
        # Chat area
        self.chat_display = widgets.Output(
            layout={"height": "400px", "overflow_y": "auto", "border": "1px solid #e0e0e0"}
        )

        # Message input
        self.message_input = widgets.Textarea(
            placeholder="Type a message...", layout={"width": "100%", "height": "80px"}
        )

        # Send button
        self.send_button = widgets.Button(
            description="Send", button_style="primary", tooltip="Send message", icon="paper-plane"
        )
        self.send_button.on_click(self._on_send_message)

        # File button
        self.file_button = widgets.Button(
            icon="paperclip", tooltip="Attach file", layout={"width": "50px"}
        )
        self.file_button.on_click(self._on_attach_file)

        # Encryption toggle
        self.encryption_toggle = widgets.ToggleButton(
            value=True, icon="lock", tooltip="Toggle encryption", layout={"width": "50px"}
        )
        self.encryption_toggle.observe(self._on_toggle_encryption, "value")

        # Message input area
        input_area = widgets.HBox(
            [self.file_button, self.message_input, self.encryption_toggle, self.send_button]
        )

        # Chat tab layout
        self.chat_tab = widgets.VBox([self.chat_display, input_area])

        # Add to tabs
        if len(self.tabs.children) == 0:
            self.tabs.children = [self.chat_tab]
        else:
            self.tabs.children = (self.chat_tab,) + self.tabs.children[1:]

    def _init_contacts_tab(self):
        """Initialize the contacts tab."""
        # Create contact manager
        self.contact_manager = create_contact_manager(
            self.p2p_manager, on_contact_select=self._on_contact_selected
        )

        # Contacts tab layout
        self.contacts_tab = widgets.VBox([self.contact_manager.manager])

        # Add to tabs
        if len(self.tabs.children) < 2:
            self.tabs.children = self.tabs.children + (self.contacts_tab,)
        else:
            children = list(self.tabs.children)
            children[1] = self.contacts_tab
            self.tabs.children = tuple(children)

    def _init_security_tab(self):
        """Initialize the security tab."""
        # Create security dashboard
        self.security_dashboard = create_security_dashboard(self.security_manager, self.p2p_manager)

        # Create file transfer manager
        self.file_transfer = create_file_transfer_manager(self.p2p_manager)

        # Security tab layout with tabs
        security_tabs = widgets.Tab()
        security_tabs.children = [self.security_dashboard.dashboard, self.file_transfer.manager]
        security_tabs.set_title(0, "Security Dashboard")
        security_tabs.set_title(1, "File Transfers")

        self.security_tab = security_tabs

        # Add to main tabs
        if len(self.tabs.children) < 3:
            self.tabs.children = self.tabs.children + (self.security_tab,)
        else:
            children = list(self.tabs.children)
            children[2] = self.security_tab
            self.tabs.children = tuple(children)

    def _init_settings_tab(self):
        """Initialize the settings tab."""
        # Settings form
        self.settings_form = widgets.VBox(
            [
                widgets.HTML("<h3>Application Settings</h3>"),
                widgets.HBox(
                    [
                        widgets.Label("Auto-start with system:"),
                        widgets.ToggleButton(description="", value=False),
                    ]
                ),
                widgets.HBox(
                    [
                        widgets.Label("Theme:"),
                        widgets.Dropdown(options=["Light", "Dark", "System"], value="System"),
                    ]
                ),
                widgets.HTML("<h3>Network Settings</h3>"),
                widgets.HBox([widgets.Label("Port:"), widgets.IntText(value=8765)]),
                widgets.HTML("<h3>Privacy</h3>"),
                widgets.HBox(
                    [
                        widgets.Label("Auto-accept files:"),
                        widgets.ToggleButton(description="", value=True),
                    ]
                ),
                widgets.HTML("<h3>About</h3>"),
                widgets.HTML("Scrambled Eggs v1.0.0<br>Secure P2P Messenger"),
            ]
        )

        # Add to tabs
        if len(self.tabs.children) < 4:
            self.tabs.children = self.tabs.children + (self.settings_form,)
        else:
            children = list(self.tabs.children)
            children[3] = self.settings_form
            self.tabs.children = tuple(children)

    def _start_background_tasks(self):
        """Start background tasks for the application."""
        # This would start tasks like:
        # - Checking for new messages
        # - Updating connection status
        # - Refreshing UI components

    def _on_send_message(self, _):
        """Handle send message button click."""
        if not self.current_chat or not self.message_input.value.strip():
            return

        message = self.message_input.value.strip()

        try:
            # Send the message through the P2P manager
            if self.current_chat.startswith("group:"):
                # Group message
                group_id = self.current_chat[6:]  # Remove 'group:' prefix
                self.p2p_manager.send_group_message(group_id, message)
            else:
                # Direct message
                self.p2p_manager.send_message(self.current_chat, message)

            # Clear the input
            self.message_input.value = ""

            # Update the chat display
            self._update_chat_display()

        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self._show_error(f"Failed to send message: {e}")

    def _on_attach_file(self, _):
        """Handle attach file button click."""
        if not self.current_chat:
            self._show_error("Please select a chat first")
            return

        # This would typically open a file dialog
        # For now, we'll just show a message
        print("File attachment dialog would open here")

    def _on_toggle_encryption(self, change):
        """Handle encryption toggle."""
        self.is_chat_encrypted = change["new"]
        status = "enabled" if self.is_chat_encrypted else "disabled"
        self._show_status(f"End-to-end encryption {status}")

    def _on_contact_selected(self, contact_id):
        """Handle contact selection."""
        self.current_chat = contact_id
        self._update_chat_display()

        # Update the chat title
        contact_info = self.p2p_manager.get_contact_info(contact_id)
        self.chat_display.clear_output()
        with self.chat_display:
            print(f"Chat with {contact_info.get('name', contact_id)}")

    def _update_chat_display(self):
        """Update the chat display with messages."""
        if not self.current_chat:
            return

        # Get messages for the current chat
        if self.current_chat.startswith("group:"):
            messages = self.p2p_manager.get_group_messages(self.current_chat[6:])
        else:
            messages = self.p2p_manager.get_messages(self.current_chat)

        # Display messages
        self.chat_display.clear_output()
        with self.chat_display:
            for msg in messages:
                sender = msg.get("sender_name", msg.get("sender_id", "Unknown"))
                time = msg.get("timestamp", "").strftime("%H:%M")

                if msg.get("is_own", False):
                    # Right-aligned for own messages
                    print(f"<div style='text-align: right; margin: 5px;'>")
                    print(
                        f"  <div style='background-color: #e3f2fd; display: inline-block; padding: 8px 12px; border-radius: 15px; max-width: 70%;'>"
                    )
                    print(f"    <div>{msg['content']}</div>")
                    print(f"    <div style='font-size: 0.8em; color: #666;'>{time}</div>")
                    print("  </div>")
                    print("</div>")
                else:
                    # Left-aligned for received messages
                    print(f"<div style='text-align: left; margin: 5px;'>")
                    print(
                        f"  <div><strong>{sender}</strong> <span style='font-size: 0.8em; color: #666;'>{time}</span></div>"
                    )
                    print(
                        f"  <div style='background-color: #f5f5f5; display: inline-block; padding: 8px 12px; border-radius: 15px; max-width: 70%;'>"
                    )
                    print(f"    {msg['content']}")
                    print("  </div>")
                    print("</div>")

    def _show_status(self, message: str):
        """Show a status message."""
        # This would typically show a temporary status message
        print(f"Status: {message}")

    def _show_error(self, message: str):
        """Show an error message."""
        # This would typically show an error message in the UI
        print(f"Error: {message}")

    def display(self):
        """Display the application."""
        display(self.main_layout)

    async def start(self):
        """Start the application."""
        # Start the P2P manager
        await self.p2p_manager.start()

        # Display the UI
        self.display()

        # Show initial status
        self._show_status("Application started")

    async def stop(self):
        """Stop the application."""
        # Stop the P2P manager
        await self.p2p_manager.stop()

        # Clean up resources
        self._show_status("Application stopped")


def create_app(p2p_manager, security_manager, gate_system):
    """Create and return a new ScrambledEggsApp instance.

    Args:
        p2p_manager: Instance of P2PManager
        security_manager: Instance of SecurityManager
        gate_system: Instance of GateSystem

    Returns:
        ScrambledEggsApp: The created application instance
    """
    return ScrambledEggsApp(p2p_manager, security_manager, gate_system)
