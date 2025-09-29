"""
Brixa - Main Application Window

This module contains the main window implementation for the Brixa secure messaging application.
"""

import logging
from typing import Any, Dict

from PySide6.QtCore import Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from app.file_transfer.secure_file_sharing import SecureFileSharing
from app.group_chat.group_manager import GroupManager
from app.network.tor_integration import TorManager
from app.p2p.p2p_manager import P2PManager

# Application modules
from app.security.scrambled_eggs_crypto import ClippyAI, ScrambledEggsCrypto
from app.ui.dialogs.file_transfer_dialog import FileTransferDialog
from app.ui.widgets.location_widget import LocationWidget


class MainWindow(QMainWindow):
    """
    Brixa Main Application Window

    The main window serves as the central hub for all Brixa functionality,
    including secure messaging, voice/video calls, file sharing, and more.
    """

    # Signals
    message_sent = Signal(str, str)  # recipient_id, content
    call_initiated = Signal(str, bool)  # recipient_id, video_enabled
    file_sent = Signal(str, str)  # recipient_id, file_path
    group_created = Signal(str, list)  # group_name, member_ids
    screen_share_started = Signal(str)  # stream_id
    security_status_updated = Signal(dict)  # security_status

    def __init__(self, app_manager: AppManager, parent=None):
        """
        Initialize the main window.

        Args:
            app_manager: Reference to the application manager
            parent: Parent widget
        """
        super().__init__(parent)
        self.app_manager = app_manager
        self.current_contact = None
        self.unread_messages = {}  # contact_id: count
        self.groups = {}  # group_id: group_data
        self.active_calls = {}  # call_id: call_data
        self.file_transfers = {}  # transfer_id: transfer_data

        # Initialize managers
        self.crypto = ScrambledEggsCrypto()
        self.clippy_ai = ClippyAI()
        self.p2p_manager = P2PManager()
        self.tor_manager = TorManager()
        self.file_sharing = SecureFileSharing()
        self.group_manager = GroupManager()
        self.screen_share = ScreenShareManager()

        # UI state
        self.dark_mode = False
        self.font_size = 12
        self.emoji_picker_visible = False
        self.security_level = "high"  # low, medium, high

        # Set up UI
        self.setup_ui()
        self.setup_connections()
        self.setup_tray_icon()
        self.update_ui()

        # Start with contacts list visible
        self.stacked_widget.setCurrentIndex(0)

        # Update UI periodically
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000)  # Update every second

        # Start background services
        self.initialize_services()

        self.logger = logging.getLogger(__name__)
        self.logger.info("Brixa main window initialized")

    def setup_ui(self):
        """Set up the user interface with all components."""
        self.setWindowTitle("Brixa - Secure Communication Platform")
        self.setMinimumSize(1200, 800)

        # Load and apply styles
        self.load_styles()

        # Set window icon
        self.setWindowIcon(QIcon(":/icons/app_icon.png"))

        # Create central widget and main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Create main splitter
        self.main_splitter = QSplitter(Qt.Horizontal)

        # Left panel - Navigation and contacts
        self.setup_left_panel()

        # Center panel - Chat/Group view
        self.setup_center_panel()

        # Right panel - Extras (optional, can be toggled)
        self.setup_right_panel()

        # Add location widget to the right panel
        self.location_widget = LocationWidget()
        self.right_panel_layout.insertWidget(0, self.location_widget)

        # Connect location refresh signal
        self.location_widget.refresh_requested.connect(self.update_location_info)

        # Add panels to main splitter
        self.main_splitter.addWidget(self.left_panel)
        self.main_splitter.addWidget(self.center_panel)
        self.main_splitter.addWidget(self.right_panel)
        self.main_splitter.setStretchFactor(0, 1)
        self.main_splitter.setStretchFactor(1, 3)
        self.main_splitter.setStretchFactor(2, 1)
        self.main_splitter.setSizes([300, 600, 300])

        # Add main splitter to layout
        self.main_layout.addWidget(self.main_splitter)

        # Create status bar
        self.setup_status_bar()

        # Create menu bar
        self.create_menu_bar()

        # Create dock widgets
        self.setup_dock_widgets()

        # Apply initial theme
        self.apply_theme()

    def setup_left_panel(self):
        """Set up the left panel with navigation and contacts."""
        self.left_panel = QWidget()
        left_layout = QVBoxLayout(self.left_panel)
        left_layout.setContentsMargins(5, 5, 5, 5)
        left_layout.setSpacing(5)

        # App logo and title
        logo_layout = QHBoxLayout()
        self.logo_label = QLabel()
        self.logo_label.setPixmap(
            QPixmap(":/icons/app_icon.png").scaled(
                32, 32, Qt.KeepAspectRatio, Qt.SmoothTransformation
            )
        )

        self.app_title = QLabel("Brixa")
        self.app_title.setStyleSheet("font-size: 18px; font-weight: bold;")

        logo_layout.addWidget(self.logo_label)
        logo_layout.addWidget(self.app_title)
        logo_layout.addStretch()

        # Search bar
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search messages, contacts, or groups...")
        self.search_edit.setClearButtonEnabled(True)
        self.search_edit.addAction(QIcon(":/icons/search.png"), QLineEdit.LeadingPosition)

        # Tab widget for different views
        self.left_tabs = QTabWidget()
        self.left_tabs.setTabPosition(QTabWidget.West)

        # Chats tab
        self.chats_tab = QWidget()
        self.setup_chats_tab()

        # Contacts tab
        self.contacts_tab = QWidget()
        self.setup_contacts_tab()

        # Groups tab
        self.groups_tab = QWidget()
        self.setup_groups_tab()

        # Add tabs
        self.left_tabs.addTab(self.chats_tab, "")
        self.left_tabs.setTabIcon(0, QIcon(":/icons/chat.png"))
        self.left_tabs.setTabToolTip(0, "Chats")

        self.left_tabs.addTab(self.contacts_tab, "")
        self.left_tabs.setTabIcon(1, QIcon(":/icons/contacts.png"))
        self.left_tabs.setTabToolTip(1, "Contacts")

        self.left_tabs.addTab(self.groups_tab, "")
        self.left_tabs.setTabIcon(2, QIcon(":/icons/groups.png"))
        self.left_tabs.setTabToolTip(2, "Groups")

        # Add widgets to layout
        left_layout.addLayout(logo_layout)
        left_layout.addWidget(self.search_edit)
        left_layout.addWidget(self.left_tabs)

        # Status indicator
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(12, 12)
        self.status_indicator.setStyleSheet("background-color: #4caf50; border-radius: 6px;")

        # Status text
        self.status_text = QLabel("Secure")
        self.status_text.setStyleSheet("color: #666666; font-size: 12px;")

        # Status layout
        status_layout = QHBoxLayout()
        status_layout.addWidget(self.status_indicator)
        status_layout.addWidget(self.status_text)
        status_layout.addStretch()

        left_layout.addLayout(status_layout)

    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        new_chat_action = QAction("New Chat", self)
        new_chat_action.triggered.connect(self.on_new_chat)
        file_menu.addAction(new_chat_action)

        file_menu.addSeparator()

        settings_action = QAction("Settings", self)
        settings_action.triggered.connect(self.on_settings)
        file_menu.addAction(settings_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Contacts menu
        contacts_menu = menubar.addMenu("&Contacts")

        add_contact_action = QAction("Add Contact", self)
        add_contact_action.triggered.connect(self.on_add_contact)
        contacts_menu.addAction(add_contact_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        toggle_sidebar_action = QAction("Toggle Sidebar", self)
        toggle_sidebar_action.triggered.connect(self.on_toggle_sidebar)
        view_menu.addAction(toggle_sidebar_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.on_about)
        help_menu.addAction(about_action)

        documentation_action = QAction("Documentation", self)
        documentation_action.triggered.connect(self.on_documentation)
        help_menu.addAction(documentation_action)

        help_menu.addSeparator()

        report_issue_action = QAction("Report Issue", self)
        report_issue_action.triggered.connect(self.on_report_issue)
        help_menu.addAction(report_issue_action)

    def setup_connections(self):
        """Set up signal-slot connections."""
        # Connect UI signals
        self.contacts_list.contact_selected.connect(self.on_contact_selected)
        self.add_contact_btn.clicked.connect(self.on_add_contact)
        self.search_contacts.textChanged.connect(self.on_search_contacts)

        # Connect chat area signals
        self.chat_area.send_message.connect(self.on_send_message)
        self.chat_area.start_call.connect(self.on_start_call)
        self.chat_area.send_file.connect(self.on_send_file)

        # Connect call widget signals
        self.call_widget.call_ended.connect(self.on_call_ended)

        # Connect to app manager signals
        self.app_manager.message_received.connect(self.on_message_received)
        self.app_manager.call_received.connect(self.on_call_received)
        self.app_manager.file_received.connect(self.on_file_received)
        self.app_manager.contact_online_status_changed.connect(
            self.on_contact_online_status_changed
        )

    def update_ui(self):
        """Update the user interface."""
        # Update contacts list
        contacts = self.app_manager.contact_manager.get_contacts()
        self.contacts_list.update_contacts(contacts)

        # Update unread message counts
        for contact_id, count in self.unread_messages.items():
            self.contacts_list.set_unread_count(contact_id, count)

        # Update status bar
        self.statusBar.showMessage(
            f"Connected | {len(contacts)} contacts | "
            f"{sum(1 for c in contacts if c.is_online)} online"
        )

    # Event handlers
    def on_contact_selected(self, contact_id: str):
        """Handle contact selection."""
        contact = self.app_manager.contact_manager.get_contact(contact_id)
        if not contact:
            return

        self.current_contact = contact
        self.chat_area.set_contact(contact)

        # Load messages
        messages = self.app_manager.message_manager.get_messages(
            self.app_manager.user_id, contact_id
        )
        self.chat_area.set_messages(messages)

        # Mark messages as read
        self.unread_messages.pop(contact_id, None)
        self.contacts_list.set_unread_count(contact_id, 0)

        # Switch to chat view
        self.stacked_widget.setCurrentWidget(self.chat_area)

    def on_send_message(self, content: str):
        """Handle sending a message."""
        if not self.current_contact or not content.strip():
            return

        # Send the message
        success = self.app_manager.send_message(self.current_contact.id, content)

        if success:
            self.chat_area.clear_input()
        else:
            QMessageBox.warning(self, "Send Failed", "Failed to send message. Please try again.")

    def on_start_call(self, video_enabled: bool):
        """Handle starting a call."""
        if not self.current_contact:
            return

        # Start the call
        success = self.app_manager.start_call(self.current_contact.id, video_enabled)

        if success:
            self.call_widget.start_outgoing_call(self.current_contact, video_enabled)
            self.stacked_widget.setCurrentWidget(self.call_widget)

    def on_call_ended(self):
        """Handle call ending."""
        self.stacked_widget.setCurrentWidget(self.chat_area)

    def on_send_file(self, file_path: str):
        """Handle sending a file."""
        if not self.current_contact or not file_path:
            return

        # Show file transfer dialog
        dialog = FileTransferDialog(self.current_contact, file_path, parent=self)
        dialog.exec()

        # Start the file transfer
        self.app_manager.send_file(self.current_contact.id, file_path)

    def on_add_contact(self):
        """Handle adding a new contact."""
        dialog = AddContactDialog(self)
        if dialog.exec() == AddContactDialog.Accepted:
            contact_id = dialog.get_contact_id()
            name = dialog.get_contact_name()
            public_key = dialog.get_public_key()

            try:
                self.app_manager.contact_manager.add_contact(contact_id, name, public_key)
                self.update_ui()
            except ValueError as e:
                QMessageBox.warning(self, "Add Contact Failed", str(e))

    def on_message_received(self, message: Dict[str, Any]):
        """Handle receiving a new message."""
        # Update chat if it's the current contact
        if self.current_contact and message["sender_id"] == self.current_contact.id:
            self.chat_area.add_message(message)
        else:
            # Update unread count
            contact_id = message["sender_id"]
            self.unread_messages[contact_id] = self.unread_messages.get(contact_id, 0) + 1
            self.update_ui()

    def on_call_received(self, call_data: Dict[str, Any]):
        """Handle an incoming call."""
        contact = self.app_manager.contact_manager.get_contact(call_data["sender_id"])
        if not contact:
            return

        # Show call widget
        self.call_widget.start_incoming_call(contact, call_data.get("video_enabled", False))
        self.stacked_widget.setCurrentWidget(self.call_widget)

    def on_file_received(self, file_data: Dict[str, Any]):
        """Handle receiving a file."""
        # Show file transfer dialog
        contact = self.app_manager.contact_manager.get_contact(file_data["sender_id"])
        if contact:
            dialog = FileTransferDialog(
                contact,
                file_data["file_name"],
                incoming=True,
                file_size=file_data.get("file_size"),
                parent=self,
            )
            dialog.exec()

    def on_contact_online_status_changed(self, contact_id: str, online: bool):
        """Handle contact online status change."""
        self.contacts_list.update_online_status(contact_id, online)

    def on_search_contacts(self, text: str):
        """Handle contact search."""
        self.contacts_list.filter_contacts(text)

    def on_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self.app_manager, self)
        if dialog.exec() == SettingsDialog.Accepted:
            # Apply settings
            pass

    def on_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About Scrambled Eggs",
            "<h2>Scrambled Eggs</h2>"
            "<p>Version 1.0.0</p>"
            "<p>A secure, end-to-end encrypted messaging application.</p>"
            "<p>&copy; 2025 Scrambled Eggs Team</p>",
        )

    def on_documentation(self):
        """Open documentation in default web browser."""
        QDesktopServices.openUrl(QUrl("https://scrambled-eggs.readthedocs.io"))

    def on_report_issue(self):
        """Open issue tracker in default web browser."""
        QDesktopServices.openUrl(QUrl("https://github.com/yourusername/scrambled-eggs/issues"))

    def on_toggle_sidebar(self):
        """Toggle the visibility of the sidebar."""
        # Implementation depends on your UI framework

    def update_location_info(self):
        """Update the current location information."""
        try:
            # In a real implementation, this would get the actual device location
            # For now, we'll use a default location in Antarctica (McMurdo Station)
            self.location_widget.update_location(-77.85, 166.67, 100.0)
        except Exception as e:
            self.logger.error(f"Failed to update location: {e}")

    def cleanup(self):
        """Clean up resources before exit."""
        # Stop timers
        self.update_timer.stop()
        if hasattr(self, "location_widget") and hasattr(self.location_widget, "update_timer"):
            self.location_widget.update_timer.stop()
        event.accept()
