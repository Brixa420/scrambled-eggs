"""
Chat Window
----------
Provides a user interface for P2P messaging and calls.
"""
import asyncio
import json
import logging
from typing import Optional, Dict, Callable, List, Any, Tuple
import uuid
from datetime import datetime

from PySide6.QtCore import Qt, Signal, QSize, QTimer, QUrl, QObject, QDateTime, QSizeF, QSettings
from PySide6.QtGui import QIcon, QPixmap, QFont, QTextCursor, QAction, QDesktopServices
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, 
    QPushButton, QListWidget, QLabel, QSplitter, QFrame, QListWidgetItem,
    QMenu, QFileDialog, QMessageBox, QToolBar, QStatusBar, QApplication
)

from pathlib import Path
import uuid
from typing import Optional, Dict, Any, List

from ..p2p.webrtc_manager import WebRTCManager
from ..database.models import Contact, Message, Database
from ..database.message_store import MessageStore
from ..security.hybrid_encryption import HybridEncryption, default_hybrid_encryption

logger = logging.getLogger(__name__)

class VideoWidget(QWidget):
    """Widget to display video from a WebRTC track."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(0, 0, 0, 0)
        
        # Add a label to display the video
        self.video_label = QLabel("No video")
        self.video_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.video_label.setStyleSheet("background-color: black; color: white;")
        self.layout().addWidget(self.video_label)
        
        # Add controls
        controls = QHBoxLayout()
        
        self.mute_button = QPushButton("Mute")
        self.mute_button.setCheckable(True)
        self.mute_button.clicked.connect(self.toggle_mute)
        controls.addWidget(self.mute_button)
        
        self.video_button = QPushButton("Video Off")
        self.video_button.setCheckable(True)
        self.video_button.setChecked(True)
        self.video_button.clicked.connect(self.toggle_video)
        controls.addWidget(self.video_button)
        
        self.end_call_button = QPushButton("End Call")
        self.end_call_button.clicked.connect(self.end_call)
        controls.addWidget(self.end_call_button)
        
        self.layout().addLayout(controls)
        
        self.track = None
        self.is_muted = False
        self.is_video_enabled = True
    
    def set_track(self, track):
        """Set the video track to display."""
        self.track = track
        # In a real implementation, you would render the video frames here
        self.video_label.setText("Video stream active")
    
    def toggle_mute(self):
        """Toggle audio mute state."""
        self.is_muted = not self.is_muted
        self.mute_button.setText("Unmute" if self.is_muted else "Mute")
        # In a real implementation, you would mute the audio track here
    
    def toggle_video(self):
        """Toggle video on/off."""
        self.is_video_enabled = not self.is_video_enabled
        self.video_button.setText("Video On" if not self.is_video_enabled else "Video Off")
        self.video_label.setVisible(self.is_video_enabled)
        # In a real implementation, you would enable/disable the video track here
    
    def end_call(self):
        """End the current call."""
        self.parent().end_call()

class ChatMessageWidget(QWidget):
    """Widget to display a single chat message."""
    def __init__(self, sender: str, message: str, timestamp: str, is_self: bool = False, parent=None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(5, 2, 5, 2)
        
        # Sender label
        self.sender_label = QLabel(sender)
        font = self.sender_label.font()
        font.setBold(True)
        self.sender_label.setFont(font)
        
        # Message text
        self.message_label = QLabel(message)
        self.message_label.setWordWrap(True)
        self.message_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        
        # Timestamp
        self.time_label = QLabel(timestamp)
        self.time_label.setStyleSheet("color: gray; font-size: 10px;")
        
        # Add to layout
        if is_self:
            # Right-aligned for self
            self.layout().addWidget(self.sender_label, 0, Qt.AlignmentFlag.AlignRight)
            self.layout().addWidget(self.message_label, 0, Qt.AlignmentFlag.AlignRight)
            self.layout().addWidget(self.time_label, 0, Qt.AlignmentFlag.AlignRight)
            self.setStyleSheet("background-color: #e3f2fd; border-radius: 10px; padding: 5px;")
        else:
            # Left-aligned for others
            self.layout().addWidget(self.sender_label)
            self.layout().addWidget(self.message_label)
            self.layout().addWidget(self.time_label)
            self.setStyleSheet("background-color: #f5f5f5; border-radius: 10px; padding: 5px;")

class ChatWindow(QWidget):
    """Main chat window for P2P messaging and calls."""
    
    # Signals
    message_received = Signal(str, str, str)  # contact_id, message, message_id
    message_sent = Signal(str, str, str)  # contact_id, message, message_id
    call_started = Signal(str, bool)  # contact_id, is_video
    call_ended = Signal(str)  # contact_id
    
    # Signals
    message_received = Signal(str, str, str)  # contact_id, message, message_id
    message_sent = Signal(str, str, str)  # contact_id, message, message_id
    call_started = Signal(str, bool)  # contact_id, is_video
    call_ended = Signal(str)  # contact_id
    
    def __init__(self, webrtc_manager: WebRTCManager, parent=None):
        super().__init__(parent)
        self.webrtc_manager = webrtc_manager
        self.video_widget = None
        self.call_active = False
        self.current_contact_id = None
        
        # Initialize database
        self.db = Database()
        
        # Initialize encryption
        self.encryption_enabled = True  # Default to enabled
        self.hybrid_encryption = default_hybrid_encryption
        
        # Load settings
        self.settings = QSettings("ScrambledEggs", "ChatClient")
        self.load_settings()
        # Set up the UI
        self.setup_ui()
        
        # Connect WebRTC manager signals
        self.webrtc_manager.message_received.connect(self.on_message_received)
        self.webrtc_manager.call_event.connect(self.on_call_event)
        self.webrtc_manager.connection_changed.connect(self.on_connection_changed)
        
        # Connect signals
        self.message_received.connect(self._on_message_received_ui)
        self.message_sent.connect(self._on_message_sent_ui)
        
        # Load settings
        self.load_settings()
        
        # Load contacts and conversations
        self.load_contacts()
        self.load_conversation_list()
    
    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("Scrambled Eggs - Secure Chat")
        self.setMinimumSize(1000, 700)
        
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Create a splitter for contacts and chat
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Contacts panel
        contacts_panel = QWidget()
        contacts_layout = QVBoxLayout(contacts_panel)
        contacts_layout.setContentsMargins(5, 5, 5, 5)
        contacts_layout.setSpacing(5)
        
        # Search box
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search contacts...")
        self.search_edit.textChanged.connect(self.filter_contacts)
        contacts_layout.addWidget(self.search_edit)
        
        # Contacts list
        self.contacts_list = QListWidget()
        self.contacts_list.setIconSize(QSize(32, 32))
        self.contacts_list.itemClicked.connect(self.on_contact_selected)
        self.contacts_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.contacts_list.customContextMenuRequested.connect(self.show_contact_context_menu)
        contacts_layout.addWidget(self.contacts_list)
        
        # Add contact button
        add_contact_btn = QPushButton("Add Contact")
        add_contact_btn.clicked.connect(self.on_add_contact)
        contacts_layout.addWidget(add_contact_btn)
        
        # Main chat area
        self.chat_area = QWidget()
        chat_layout = QVBoxLayout(self.chat_area)
        chat_layout.setContentsMargins(0, 0, 0, 0)
        chat_layout.setSpacing(0)
        
        # Chat header
        self.chat_header = QToolBar()
        self.chat_header.setIconSize(QSize(24, 24))
        self.chat_header.setMovable(False)
        
        self.contact_name_label = QLabel("Select a contact")
        font = self.contact_name_label.font()
        font.setPointSize(12)
        font.setBold(True)
        self.contact_name_label.setFont(font)
        
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: gray;")
        
        self.chat_header.addWidget(self.contact_name_label)
        self.chat_header.addWidget(self.status_label)
        self.chat_header.addStretch()
        
        # Call buttons
        self.voice_call_btn = QPushButton()
        self.voice_call_btn.setIcon(QIcon.fromTheme("call-start"))
        self.voice_call_btn.setToolTip("Voice Call")
        self.voice_call_btn.clicked.connect(lambda: self.start_call(with_video=False))
        self.chat_header.addWidget(self.voice_call_btn)
        
        self.video_call_btn = QPushButton()
        self.video_call_btn.setIcon(QIcon.fromTheme("camera-video"))
        self.video_call_btn.setToolTip("Video Call")
        self.video_call_btn.clicked.connect(lambda: self.start_call(with_video=True))
        self.chat_header.addWidget(self.video_call_btn)
        
        # Encryption status indicator
        self.encryption_status = QLabel()
        self.encryption_status.setToolTip("End-to-end encryption status")
        self.chat_header.addWidget(self.encryption_status)
        self.update_encryption_status()
        
        chat_layout.addWidget(self.chat_header)
        
        # Message display area
        self.message_display = QTextEdit()
        self.message_display.setReadOnly(True)
        self.message_display.setStyleSheet("""
            QTextEdit {
                background-color: white;
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 10px;
            }
        """)
        chat_layout.addWidget(self.message_display, 1)  # Stretch factor 1
        
        # Message input area
        input_widget = QWidget()
        input_layout = QHBoxLayout(input_widget)
        input_layout.setContentsMargins(5, 5, 5, 5)
        
        # File attachment button
        self.attach_btn = QPushButton()
        self.attach_btn.setIcon(QIcon.fromTheme("mail-attachment"))
        self.attach_btn.setToolTip("Attach File")
        self.attach_btn.clicked.connect(self.on_attach_file)
        input_layout.addWidget(self.attach_btn)
        
        # Message input
        self.message_input = QTextEdit()
        self.message_input.setMaximumHeight(100)
        self.message_input.setPlaceholderText("Type a message...")
        input_layout.addWidget(self.message_input, 1)  # Stretch factor 1
        
        # Send button
        self.send_btn = QPushButton("Send")
        self.send_btn.clicked.connect(self.send_message)
        input_layout.addWidget(self.send_btn)
        
        chat_layout.addWidget(input_widget)
        
        # Add panels to splitter
        self.splitter.addWidget(contacts_panel)
        self.splitter.addWidget(self.chat_area)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 3)
        
        main_layout.addWidget(self.splitter)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.connection_status = QLabel("Disconnected")
        self.status_bar.addPermanentWidget(self.connection_status)
        main_layout.addWidget(self.status_bar)
        
        # Disable chat area initially
        self.set_chat_enabled(False)
    
    def load_contacts(self):
        """Load contacts from the WebRTC manager."""
        # In a real implementation, you would load contacts from a database
        # For now, we'll just clear the list
        self.contacts_list.clear()
        
        # Add a sample contact for testing
        sample_contact = Contact(
            id="sample_user",
            name="Sample User",
            public_key="sample_public_key",
            online=True
        )
        self.webrtc_manager.contacts[sample_contact.id] = sample_contact
        
        # Add contacts to the list
        for contact in self.webrtc_manager.contacts.values():
            self.add_contact_to_list(contact)
    
    def add_contact_to_list(self, contact: Contact):
        """Add a contact to the contacts list."""
        item = QListWidgetItem(contact.name)
        item.setData(Qt.ItemDataRole.UserRole, contact.id)
        
        # Set online/offline status
        if contact.online:
            item.setIcon(QIcon.fromTheme("user-available"))
            item.setForeground(Qt.GlobalColor.darkGreen)
        else:
            item.setIcon(QIcon.fromTheme("user-offline"))
            item.setForeground(Qt.GlobalColor.gray)
        
        self.contacts_list.addItem(item)
    
    def filter_contacts(self):
        """Filter the contacts list based on search text."""
        search_text = self.search_edit.text().lower()
        
        for i in range(self.contacts_list.count()):
            item = self.contacts_list.item(i)
            contact_id = item.data(Qt.ItemDataRole.UserRole)
            contact = self.webrtc_manager.contacts.get(contact_id)
            
            if contact and (search_text in contact.name.lower() or search_text in contact.id.lower()):
                item.setHidden(False)
            else:
                item.setHidden(True)
    
    def on_contact_selected(self, item):
        """Handle contact selection."""
        contact_id = item.data(Qt.ItemDataRole.UserRole)
        self.current_contact = self.webrtc_manager.contacts.get(contact_id)
        
        if self.current_contact:
            self.contact_name_label.setText(self.current_contact.name)
            self.status_label.setText("(Online)" if self.current_contact.online else "(Offline)")
            self.set_chat_enabled(True)
            
            # Load chat history
            self.load_chat_history()
    
    def set_chat_enabled(self, enabled: bool):
        """Enable or disable chat controls."""
        self.message_input.setEnabled(enabled)
        self.send_btn.setEnabled(enabled)
        self.attach_btn.setEnabled(enabled)
        self.voice_call_btn.setEnabled(enabled)
        self.video_call_btn.setEnabled(enabled)
    
    def load_chat_history(self):
        """Load chat history for the current contact."""
        if not self.current_contact:
            return
        
        self.message_display.clear()
        
        # In a real implementation, you would load messages from a database
        # For now, we'll just add a sample message
        self.add_message("Sample User", "Hello! This is a sample message.", "12:34 PM", is_self=False)
    
    def add_message(self, sender: str, message: str, timestamp: str, is_self: bool = False):
        """Add a message to the chat display."""
        # Create message widget
        message_widget = ChatMessageWidget(sender, message, timestamp, is_self)
        
        # Add to message display
        cursor = self.message_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        
        # Insert the widget
        self.message_display.textCursor().insertHtml("<br>")
        self.message_display.textCursor().insertHtml("<br>")  # Add some spacing
        
        # Insert the widget
        self.message_display.textCursor().insertHtml("<div>")
        self.message_document = self.message_display.document()
        self.message_document.addResource(QTextDocument.ResourceType.ImageResource, 
                                         QUrl("widget"), QVariant())
        
        # Insert the widget
        self.message_display.textCursor().insertHtml("</div>")
        
        # Scroll to bottom
        self.message_display.verticalScrollBar().setValue(
            self.message_display.verticalScrollBar().maximum()
        )
    
    def update_encryption_status(self):
        """Update the encryption status indicator based on current settings."""
        settings = QSettings("ScrambledEggs", "ScrambledEggs")
        self.encryption_enabled = settings.value("encryption/enabled", True, type=bool)
        
        if self.encryption_enabled:
            self.encryption_status.setText("🔒")
            self.encryption_status.setToolTip("End-to-end encryption is enabled")
            self.encryption_status.setStyleSheet("color: #4CAF50; font-size: 16px;")
        else:
            self.encryption_status.setText("⚠️")
            self.encryption_status.setToolTip("End-to-end encryption is disabled - messages will be sent in plain text")
            self.encryption_status.setStyleSheet("color: #f44336; font-size: 16px;")
    
    def load_settings(self):
        """Load application settings."""
        self.update_encryption_status()
    
    def send_message(self):
        """Send an encrypted message to the current contact.
        
        Messages will only be sent if encryption is successful. If encryption fails,
        the message will not be sent and an error will be shown to the user.
        """
        if not self.current_contact or not self.message_input.toPlainText().strip():
            return
        
        message_text = self.message_input.toPlainText().strip()
        timestamp = QTime.currentTime().toString("h:mm AP")
        
        # Get current encryption setting
        settings = QSettings("ScrambledEggs", "ScrambledEggs")
        encryption_enabled = settings.value("encryption/enabled", True, type=bool)
        
        # If encryption is disabled, show a warning and don't send the message
        if not encryption_enabled:
            QMessageBox.warning(
                self,
                "Encryption Required",
                "Message not sent: Encryption is disabled. Please enable encryption in settings.",
                QMessageBox.StandardButton.Ok
            )
            return
            
        # Check if we have the necessary components for encryption
        if not self.hybrid_encryption:
            QMessageBox.critical(
                self,
                "Encryption Error",
                "Message not sent: Encryption module not available.",
                QMessageBox.StandardButton.Ok
            )
            return
            
        if not hasattr(self.current_contact, 'public_key') or not self.current_contact.public_key:
            QMessageBox.critical(
                self,
                "Encryption Error",
                "Message not sent: No public key available for this contact.",
                QMessageBox.StandardButton.Ok
            )
            return
        
        try:
            # Encrypt the message
            encrypted_data = self.hybrid_encryption.encrypt(
                message_text,
                recipient_public_key=self.current_contact.public_key
            )
            
            # Convert to JSON string for sending
            message_to_send = json.dumps({
                'encrypted': True,
                'data': encrypted_data
            })
            
            # Add to chat display (only after successful encryption)
            self.add_message("You", message_text, timestamp, is_self=True)
            self.add_message("System", "🔒 Message sent with end-to-end encryption", timestamp, is_self=True)
            
            # Clear input (only after successful encryption)
            self.message_input.clear()
            
            # Send via WebRTC
            asyncio.create_task(self.webrtc_manager.send_message(
                self.current_contact.id, 
                message_to_send
            ))
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            QMessageBox.critical(
                self,
                "Encryption Failed",
                f"Message not sent: Failed to encrypt message.\n\nError: {str(e)}\n\nPlease try again or check your encryption settings.",
                QMessageBox.StandardButton.Ok
            )
    
    def on_message_received(self, sender_id: str, message: str, message_id: str = None):
        """Handle an incoming message."""
        contact = self.webrtc_manager.contacts.get(sender_id)
        if not contact:
            logger.warning(f"Received message from unknown contact: {sender_id}")
            return
        
        timestamp = QTime.currentTime().toString("h:mm AP")
        
        try:
            # Check if the message is encrypted
            try:
                message_data = json.loads(message)
                if isinstance(message_data, dict) and message_data.get('encrypted', False):
                    if not self.hybrid_encryption:
                        raise ValueError("Encryption not available")
                        
                    # Decrypt the message
                    decrypted_data = self.hybrid_encryption.decrypt(message_data['data'])
                    decrypted_message = decrypted_data.decode('utf-8')
                    
                    # Add to chat with encryption indicator
                    if self.current_contact and self.current_contact.id == sender_id:
                        self.add_message(contact.name, decrypted_message, timestamp, is_self=False)
                        self.add_message("System", "🔒 Message received with end-to-end encryption", 
                                       timestamp, is_self=False)
                    
                    # For notifications, show a generic message
                    notification_msg = "🔒 Encrypted message received"
                    
                else:
                    # Plain text message
                    if self.current_contact and self.current_contact.id == sender_id:
                        self.add_message(contact.name, message, timestamp, is_self=False)
                    notification_msg = message
                    
            except (json.JSONDecodeError, KeyError, ValueError) as e:
                # Not in expected encrypted format, treat as plain text
                logger.warning(f"Message not in encrypted format: {e}")
                if self.current_contact and self.current_contact.id == sender_id:
                    self.add_message(contact.name, message, timestamp, is_self=False)
                notification_msg = message
                
            # Show notification if the chat window is not active
            if not self.isActiveWindow():
                self.show_notification(f"New message from {contact.name}", notification_msg)
                
        except Exception as e:
            logger.error(f"Error processing incoming message: {e}")
            error_msg = f"Error processing message: {str(e)}"
            if self.current_contact and self.current_contact.id == sender_id:
                self.add_message("System", error_msg, timestamp, is_self=False)
            self.show_notification("Message Error", error_msg)
    
    def on_call_event(self, contact_id: str, event_type: str, *args):
        """Handle call-related events."""
        contact = self.webrtc_manager.contacts.get(contact_id)
        if not contact:
            return
        
        if event_type == 'incoming':
            is_video = args[0] if args else False
            self.show_incoming_call(contact, is_video)
        elif event_type == 'track':
            track_type = args[0] if args else ''
            if track_type == 'video':
                self.show_video(contact_id)
    
    def on_connection_changed(self, contact_id: str, connected: bool):
        """Handle connection state changes."""
        contact = self.webrtc_manager.contacts.get(contact_id)
        if not contact:
            return
        
        contact.online = connected
        
        # Update status in the UI
        for i in range(self.contacts_list.count()):
            item = self.contacts_list.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == contact_id:
                if connected:
                    item.setIcon(QIcon.fromTheme("user-available"))
                    item.setForeground(Qt.GlobalColor.darkGreen)
                else:
                    item.setIcon(QIcon.fromTheme("user-offline"))
                    item.setForeground(Qt.GlobalColor.gray)
                break
        
        # Update status label if this is the current contact
        if self.current_contact and self.current_contact.id == contact_id:
            self.status_label.setText("(Online)" if connected else "(Offline)")
    
    def start_call(self, with_video: bool = True):
        """Start a call with the current contact."""
        if not self.current_contact:
            return
        
        if self.call_active:
            return
        
        self.call_active = True
        self.show_video(self.current_contact.id, is_local=True)
        
        # Start the call in the background
        asyncio.create_task(self.webrtc_manager.start_call(self.current_contact.id, with_video))
    
    def end_call(self):
        """End the current call."""
        if not self.call_active or not self.current_contact:
            return
        
        self.call_active = False
        
        # Hide video widget
        if self.video_widget:
            self.video_widget.hide()
            self.video_widget.deleteLater()
            self.video_widget = None
        
        # End the call in the background
        asyncio.create_task(self.webrtc_manager.end_call(self.current_contact.id))
    
    def show_video(self, contact_id: str, is_local: bool = False):
        """Show video from a remote or local stream."""
        if not self.video_widget:
            self.video_widget = VideoWidget(self)
            self.chat_area.layout().insertWidget(1, self.video_widget)  # Insert after header
        
        # In a real implementation, you would set the video track here
        self.video_widget.show()
    
    def show_incoming_call(self, contact: Contact, is_video: bool):
        """Show incoming call dialog."""
        call_type = "video" if is_video else "voice"
        reply = QMessageBox.question(
            self,
            "Incoming Call",
            f"Incoming {call_type} call from {contact.name}. Accept?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Accept the call
            self.call_active = True
            self.show_video(contact.id)
        else:
            # Reject the call
            asyncio.create_task(self.webrtc_manager.end_call(contact.id))
    
    def show_contact_context_menu(self, position):
        """Show context menu for a contact."""
        item = self.contacts_list.itemAt(position)
        if not item:
            return
        
        contact_id = item.data(Qt.ItemDataRole.UserRole)
        contact = self.webrtc_manager.contacts.get(contact_id)
        if not contact:
            return
        
        menu = QMenu()
        
        # Add actions
        call_action = menu.addAction("Voice Call")
        video_call_action = menu.addAction("Video Call")
        menu.addSeparator()
        remove_action = menu.addAction("Remove Contact")
        
        # Show menu and get selected action
        action = menu.exec(self.contacts_list.mapToGlobal(position))
        
        if action == call_action:
            self.on_contact_selected(item)
            self.start_call(with_video=False)
        elif action == video_call_action:
            self.on_contact_selected(item)
            self.start_call(with_video=True)
        elif action == remove_action:
            self.remove_contact(contact)
    
    def on_add_contact(self):
        """Show add contact dialog."""
        # In a real implementation, you would show a dialog to add a new contact
        QMessageBox.information(
            self,
            "Add Contact",
            "This feature will be implemented in a future version.",
            QMessageBox.StandardButton.Ok
        )
    
    def on_attach_file(self):
        """Handle file attachment."""
        # In a real implementation, you would show a file dialog and handle the file
        QMessageBox.information(
            self,
            "Attach File",
            "This feature will be implemented in a future version.",
            QMessageBox.StandardButton.Ok
        )
    
    def remove_contact(self, contact: Contact):
        """Remove a contact."""
        reply = QMessageBox.question(
            self,
            "Remove Contact",
            f"Are you sure you want to remove {contact.name} from your contacts?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Remove from WebRTC manager
            asyncio.create_task(self.webrtc_manager.remove_contact(contact.id))
            
            # Remove from UI
            for i in range(self.contacts_list.count()):
                item = self.contacts_list.item(i)
                if item.data(Qt.ItemDataRole.UserRole) == contact.id:
                    self.contacts_list.takeItem(i)
                    break
            
            # Clear chat if this was the current contact
            if self.current_contact and self.current_contact.id == contact.id:
                self.current_contact = None
                self.contact_name_label.setText("Select a contact")
                self.status_label.clear()
                self.message_display.clear()
                self.set_chat_enabled(False)
    
    def show_notification(self, title: str, message: str):
        """Show a system notification."""
        # In a real implementation, you would show a system notification
        # For now, we'll just show a message box
        QMessageBox.information(self, title, message)
    
    def showEvent(self, event):
        """Handle show event."""
        super().showEvent(event)
        self.load_settings()
        
    def closeEvent(self, event):
        """Handle close event."""
        # Save window geometry
        self.settings.setValue("window/geometry", self.saveGeometry())
        
        if self.call_active and self.current_contact:
            asyncio.create_task(self.webrtc_manager.end_call(self.current_contact.id))
        
        # Clean up WebRTC manager
        asyncio.create_task(self.webrtc_manager.close())
        
        super().closeEvent(event)
        event.accept()
