"""
Main application window for Scrambled Eggs.
"""
import logging
from typing import Optional, Dict, Any

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel,
    QListWidget, QListWidgetItem, QTextEdit, QLineEdit, QPushButton,
    QToolBar, QStatusBar, QMenuBar, QMenu, QFileDialog, QMessageBox,
    QTabWidget, QFrame, QStackedWidget, QSizePolicy, QScrollArea
)
from PySide6.QtCore import Qt, Signal, QSize, QTimer, QUrl
from PySide6.QtGui import QIcon, QAction, QFont, QPixmap, QDesktopServices

from app.managers.app_manager import AppManager
from app.ui.widgets.contact_list import ContactListWidget
from app.ui.widgets.chat_area import ChatAreaWidget
from app.ui.widgets.call_widget import CallWidget
from app.ui.dialogs.settings_dialog import SettingsDialog
from app.ui.dialogs.add_contact_dialog import AddContactDialog
from app.ui.dialogs.file_transfer_dialog import FileTransferDialog
from app.models.contact import Contact
from app.models.message import Message, MessageType

class MainWindow(QMainWindow):
    """Main application window."""
    
    # Signals
    message_sent = Signal(str, str)  # recipient_id, content
    call_initiated = Signal(str, bool)  # recipient_id, video_enabled
    file_sent = Signal(str, str)  # recipient_id, file_path
    
    def __init__(self, app_manager: AppManager, parent=None):
        """Initialize the main window."""
        super().__init__(parent)
        self.app_manager = app_manager
        self.current_contact = None
        self.unread_messages = {}  # contact_id: count
        
        self.setup_ui()
        self.setup_connections()
        self.update_ui()
        
        # Start with contacts list visible
        self.stacked_widget.setCurrentIndex(0)
        
        # Update UI periodically
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_ui)
        self.update_timer.start(1000)  # Update every second
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("Main window initialized")
    
    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("Scrambled Eggs - Secure Messenger")
        self.setMinimumSize(1000, 700)
        
        # Set application style
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QListWidget {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 5px;
            }
            QTextEdit, QLineEdit {
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 5px;
                padding: 8px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
            QTabWidget::pane {
                border: 1px solid #ddd;
                border-radius: 5px;
                margin: 0px;
                padding: 0px;
            }
            QTabBar::tab {
                background: #f0f0f0;
                padding: 8px 16px;
                border: 1px solid #ddd;
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background: white;
                border-bottom: 1px solid white;
                margin-bottom: -1px;
            }
        """)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Contacts/Conversations
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)
        
        # Search bar
        self.search_contacts = QLineEdit()
        self.search_contacts.setPlaceholderText("Search contacts...")
        left_layout.addWidget(self.search_contacts)
        
        # Contacts list
        self.contacts_list = ContactListWidget()
        left_layout.addWidget(self.contacts_list)
        
        # Add contact button
        self.add_contact_btn = QPushButton("Add Contact")
        left_layout.addWidget(self.add_contact_btn)
        
        # Right panel - Chat/Conversation
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(5)
        
        # Stacked widget for different views
        self.stacked_widget = QStackedWidget()
        
        # Welcome/No contact selected view
        welcome_widget = QWidget()
        welcome_layout = QVBoxLayout(welcome_widget)
        welcome_layout.addStretch()
        
        welcome_label = QLabel("Welcome to Scrambled Eggs")
        welcome_label.setAlignment(Qt.AlignCenter)
        welcome_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 20px;")
        welcome_layout.addWidget(welcome_label)
        
        instructions = QLabel(
            "Select a contact to start chatting, or add a new contact to get started."
        )
        instructions.setAlignment(Qt.AlignCenter)
        instructions.setWordWrap(True)
        welcome_layout.addWidget(instructions)
        welcome_layout.addStretch()
        
        self.stacked_widget.addWidget(welcome_widget)
        
        # Chat view
        self.chat_area = ChatAreaWidget()
        self.stacked_widget.addWidget(self.chat_area)
        
        # Call view
        self.call_widget = CallWidget()
        self.stacked_widget.addWidget(self.call_widget)
        
        right_layout.addWidget(self.stacked_widget)
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([300, 700])  # Initial sizes
        
        main_layout.addWidget(splitter)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready")
        
        # Set initial state
        self.update_ui()
    
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
            self.app_manager.user_id,
            contact_id
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
        success = self.app_manager.send_message(
            self.current_contact.id,
            content
        )
        
        if success:
            self.chat_area.clear_input()
        else:
            QMessageBox.warning(
                self,
                "Send Failed",
                "Failed to send message. Please try again."
            )
    
    def on_start_call(self, video_enabled: bool):
        """Handle starting a call."""
        if not self.current_contact:
            return
            
        # Start the call
        success = self.app_manager.start_call(
            self.current_contact.id,
            video_enabled
        )
        
        if success:
            self.call_widget.start_outgoing_call(
                self.current_contact,
                video_enabled
            )
            self.stacked_widget.setCurrentWidget(self.call_widget)
    
    def on_call_ended(self):
        """Handle call ending."""
        self.stacked_widget.setCurrentWidget(self.chat_area)
    
    def on_send_file(self, file_path: str):
        """Handle sending a file."""
        if not self.current_contact or not file_path:
            return
            
        # Show file transfer dialog
        dialog = FileTransferDialog(
            self.current_contact,
            file_path,
            parent=self
        )
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
                self.app_manager.contact_manager.add_contact(
                    contact_id,
                    name,
                    public_key
                )
                self.update_ui()
            except ValueError as e:
                QMessageBox.warning(self, "Add Contact Failed", str(e))
    
    def on_message_received(self, message: Dict[str, Any]):
        """Handle receiving a new message."""
        # Update chat if it's the current contact
        if (self.current_contact and 
            message['sender_id'] == self.current_contact.id):
            self.chat_area.add_message(message)
        else:
            # Update unread count
            contact_id = message['sender_id']
            self.unread_messages[contact_id] = \
                self.unread_messages.get(contact_id, 0) + 1
            self.update_ui()
    
    def on_call_received(self, call_data: Dict[str, Any]):
        """Handle an incoming call."""
        contact = self.app_manager.contact_manager.get_contact(
            call_data['sender_id']
        )
        if not contact:
            return
            
        # Show call widget
        self.call_widget.start_incoming_call(
            contact,
            call_data.get('video_enabled', False)
        )
        self.stacked_widget.setCurrentWidget(self.call_widget)
    
    def on_file_received(self, file_data: Dict[str, Any]):
        """Handle receiving a file."""
        # Show file transfer dialog
        contact = self.app_manager.contact_manager.get_contact(
            file_data['sender_id']
        )
        if contact:
            dialog = FileTransferDialog(
                contact,
                file_data['file_name'],
                incoming=True,
                file_size=file_data.get('file_size'),
                parent=self
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
            "<p>&copy; 2025 Scrambled Eggs Team</p>"
        )
    
    def on_documentation(self):
        """Open documentation in default web browser."""
        QDesktopServices.openUrl(QUrl("https://scrambled-eggs.readthedocs.io"))
    
    def on_report_issue(self):
        """Open issue tracker in default web browser."""
        QDesktopServices.openUrl(
            QUrl("https://github.com/yourusername/scrambled-eggs/issues")
        )
    
    def on_toggle_sidebar(self):
        """Toggle the visibility of the sidebar."""
        # Implementation depends on your UI framework
        pass
    
    def closeEvent(self, event):
        """Handle window close event."""
        # Stop the application
        self.app_manager.stop()
        event.accept()
