"""
Chat area widget for displaying and sending messages.
"""

from typing import Any, Dict, List

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.models.contact import Contact


class MessageBubble(QFrame):
    """Widget for displaying a single message bubble."""

    def __init__(self, message: Dict[str, Any], is_own: bool = False, parent=None):
        """Initialize the message bubble."""
        super().__init__(parent)
        self.message = message
        self.is_own = is_own

        self.setup_ui()
        self.update_display()

    def setup_ui(self):
        """Set up the user interface."""
        self.setFrameShape(QFrame.NoFrame)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(2)

        # Message content
        self.content_label = QLabel()
        self.content_label.setWordWrap(True)
        self.content_label.setTextFormat(Qt.RichText)
        self.content_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse
        )
        self.content_label.setOpenExternalLinks(True)
        self.content_label.setStyleSheet(
            """
            QLabel {
                padding: 8px 12px;
                border-radius: 12px;
                background-color: #f0f0f0;
                color: #333333;
                font-size: 14px;
                line-height: 1.4;
            }
            QLabel a {
                color: #4a90e2;
                text-decoration: none;
            }
            QLabel a:hover {
                text-decoration: underline;
            }
        """
        )

        # Message metadata (time, status)
        meta_layout = QHBoxLayout()
        meta_layout.setContentsMargins(0, 0, 0, 0)
        meta_layout.setSpacing(5)

        self.time_label = QLabel()
        self.time_label.setStyleSheet("color: #888888; font-size: 10px;")

        self.status_icon = QLabel()
        self.status_icon.setFixedSize(12, 12)

        meta_layout.addWidget(self.time_label)
        meta_layout.addStretch()
        meta_layout.addWidget(self.status_icon)

        # Add to layout
        layout.addWidget(self.content_label)
        layout.addLayout(meta_layout)

        # Set alignment based on message ownership
        if self.is_own:
            layout.setAlignment(Qt.AlignRight)
            self.content_label.setStyleSheet(
                self.content_label.styleSheet()
                + """
                QLabel {
                    background-color: #4a90e2;
                    color: white;
                    border-top-right-radius: 2px;
                }
            """
            )
        else:
            layout.setAlignment(Qt.AlignLeft)
            self.content_label.setStyleSheet(
                self.content_label.styleSheet()
                + """
                QLabel {
                    background-color: #f0f0f0;
                    color: #333333;
                    border-top-left-radius: 2px;
                }
            """
            )

    def update_display(self):
        """Update the display with message data."""
        # Set message content
        self.content_label.setText(self.format_message_content())

        # Set timestamp
        from datetime import datetime

        timestamp = datetime.fromtimestamp(self.message.get("timestamp", 0))
        self.time_label.setText(timestamp.strftime("%H:%M"))

        # Set status icon
        status = self.message.get("status", "sent")
        if status == "sent":
            self.status_icon.setPixmap(QIcon(":/icons/sent.png").pixmap(12, 12))
        elif status == "delivered":
            self.status_icon.setPixmap(QIcon(":/icons/delivered.png").pixmap(12, 12))
        elif status == "read":
            self.status_icon.setPixmap(QIcon(":/icons/read.png").pixmap(12, 12))
        elif status == "error":
            self.status_icon.setPixmap(QIcon(":/icons/error.png").pixmap(12, 12))

    def format_message_content(self) -> str:
        """Format the message content with appropriate styling."""
        content = self.message.get("content", "")

        # Basic HTML escaping
        content = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        # Replace newlines with <br>
        content = content.replace("\n", "<br>")

        # Auto-link URLs
        import re

        url_pattern = re.compile(r"https?://[^\s<]+")
        content = url_pattern.sub(lambda m: f'<a href="{m.group(0)}">{m.group(0)}</a>', content)

        return content


class ChatAreaWidget(QWidget):
    """Widget for displaying and sending messages in a chat."""

    # Signals
    send_message = Signal(str)  # message content
    start_call = Signal(bool)  # video_enabled
    send_file = Signal(str)  # file_path

    def __init__(self, parent=None):
        """Initialize the chat area."""
        super().__init__(parent)
        self.contact = None
        self.messages = []

        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header with contact info and call buttons
        header = QFrame()
        header.setFrameShape(QFrame.StyledPanel)
        header.setStyleSheet(
            """
            QFrame {
                background-color: #f8f8f8;
                border-bottom: 1px solid #e0e0e0;
                padding: 10px;
            }
        """
        )

        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(10, 5, 10, 5)

        # Contact info
        self.contact_name = QLabel("Select a contact")
        self.contact_name.setStyleSheet(
            """
            QLabel {
                font-size: 16px;
                font-weight: bold;
            }
        """
        )

        self.contact_status = QLabel("")
        self.contact_status.setStyleSheet("color: #888888; font-size: 12px;")

        contact_info = QVBoxLayout()
        contact_info.setSpacing(2)
        contact_info.addWidget(self.contact_name)
        contact_info.addWidget(self.contact_status)

        # Call buttons
        call_buttons = QHBoxLayout()
        call_buttons.setSpacing(5)

        self.voice_call_btn = QPushButton()
        self.voice_call_btn.setIcon(QIcon(":/icons/call.png"))
        self.voice_call_btn.setToolTip("Voice call")
        self.voice_call_btn.setFixedSize(32, 32)
        self.voice_call_btn.setStyleSheet(
            """
            QPushButton {
                border: 1px solid #e0e0e0;
                border-radius: 16px;
                background-color: white;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
            }
        """
        )

        self.video_call_btn = QPushButton()
        self.video_call_btn.setIcon(QIcon(":/icons/video_call.png"))
        self.video_call_btn.setToolTip("Video call")
        self.video_call_btn.setFixedSize(32, 32)
        self.video_call_btn.setStyleSheet(
            """
            QPushButton {
                border: 1px solid #e0e0e0;
                border-radius: 16px;
                background-color: white;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
            }
        """
        )

        call_buttons.addWidget(self.voice_call_btn)
        call_buttons.addWidget(self.video_call_btn)

        # Add to header
        header_layout.addLayout(contact_info)
        header_layout.addStretch()
        header_layout.addLayout(call_buttons)

        # Messages area
        self.messages_area = QScrollArea()
        self.messages_area.setWidgetResizable(True)
        self.messages_area.setFrameShape(QFrame.NoFrame)
        self.messages_area.setStyleSheet(
            """
            QScrollArea {
                background-color: #f5f5f5;
                border: none;
            }
            QWidget#messagesContainer {
                background-color: #f5f5f5;
            }
        """
        )

        # Container for messages
        self.messages_container = QWidget()
        self.messages_container.setObjectName("messagesContainer")
        self.messages_layout = QVBoxLayout(self.messages_container)
        self.messages_layout.setContentsMargins(20, 20, 20, 20)
        self.messages_layout.setSpacing(5)
        self.messages_layout.addStretch()

        self.messages_area.setWidget(self.messages_container)

        # Message input area
        input_frame = QFrame()
        input_frame.setFrameShape(QFrame.StyledPanel)
        input_frame.setStyleSheet(
            """
            QFrame {
                background-color: #f8f8f8;
                border-top: 1px solid #e0e0e0;
                padding: 10px;
            }
        """
        )

        input_layout = QVBoxLayout(input_frame)
        input_layout.setContentsMargins(5, 5, 5, 5)
        input_layout.setSpacing(5)

        # Toolbar with formatting options
        toolbar = QHBoxLayout()
        toolbar.setSpacing(5)

        self.format_bold = self.create_tool_button("Bold", ":/icons/format_bold.png")
        self.format_italic = self.create_tool_button("Italic", ":/icons/format_italic.png")
        self.format_code = self.create_tool_button("Code", ":/icons/code.png")

        toolbar.addWidget(self.format_bold)
        toolbar.addWidget(self.format_italic)
        toolbar.addWidget(self.format_code)
        toolbar.addStretch()

        # File attachment button
        self.attach_btn = self.create_tool_button("Attach file", ":/icons/attach_file.png")
        toolbar.addWidget(self.attach_btn)

        # Message input
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setAcceptRichText(False)
        self.message_input.setMaximumHeight(100)
        self.message_input.setStyleSheet(
            """
            QTextEdit {
                border: 1px solid #e0e0e0;
                border-radius: 5px;
                padding: 8px;
                font-size: 14px;
                background-color: white;
            }
            QTextEdit:focus {
                border: 1px solid #4a90e2;
            }
        """
        )

        # Send button
        self.send_btn = QPushButton("Send")
        self.send_btn.setFixedWidth(80)
        self.send_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #4a90e2;
                color: white;
                border: none;
                border-radius: 5px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #357abd;
            }
            QPushButton:disabled {
                background-color: #cccccc;
            }
        """
        )

        # Input layout
        input_layout.addLayout(toolbar)
        input_layout.addWidget(self.message_input)

        # Bottom bar with send button
        bottom_bar = QHBoxLayout()
        bottom_bar.addStretch()
        bottom_bar.addWidget(self.send_btn)

        input_layout.addLayout(bottom_bar)

        # Add to main layout
        layout.addWidget(header)
        layout.addWidget(self.messages_area, 1)
        layout.addWidget(input_frame)

        # Connect signals
        self.send_btn.clicked.connect(self.on_send_clicked)
        self.message_input.textChanged.connect(self.on_text_changed)
        self.attach_btn.clicked.connect(self.on_attach_clicked)
        self.voice_call_btn.clicked.connect(lambda: self.start_call.emit(False))
        self.video_call_btn.clicked.connect(lambda: self.start_call.emit(True))

        # Enable drag and drop for files
        self.setAcceptDrops(True)

    def create_tool_button(self, tooltip: str, icon_path: str) -> QPushButton:
        """Create a tool button for the message input toolbar."""
        button = QPushButton()
        button.setIcon(QIcon(icon_path))
        button.setToolTip(tooltip)
        button.setFixedSize(24, 24)
        button.setStyleSheet(
            """
            QPushButton {
                border: none;
                background: transparent;
                padding: 2px;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
                border-radius: 3px;
            }
        """
        )
        return button

    def set_contact(self, contact: Contact):
        """Set the current contact and load messages."""
        self.contact = contact
        self.contact_name.setText(contact.name)
        self.contact_status.setText("Online" if contact.is_online else "Offline")

        # Clear existing messages
        self.clear_messages()

        # Load messages for this contact
        # In a real app, this would load from the database
        self.load_messages()

    def load_messages(self):
        """Load messages for the current contact."""
        if not self.contact:
            return

        # In a real app, this would load messages from the database
        # For now, we'll just add some sample messages
        self.add_message(
            {
                "id": "1",
                "sender_id": self.contact.id,
                "content": "Hello! How are you?",
                "timestamp": 1625000000,
                "status": "read",
            }
        )

        self.add_message(
            {
                "id": "2",
                "sender_id": "me",
                "content": "Hi! I'm doing great, thanks for asking!",
                "timestamp": 1625000100,
                "status": "read",
            }
        )

        self.add_message(
            {
                "id": "3",
                "sender_id": self.contact.id,
                "content": "Would you like to have a call later?",
                "timestamp": 1625000200,
                "status": "read",
            }
        )

    def add_message(self, message: Dict[str, Any]):
        """Add a message to the chat."""
        is_own = message.get("sender_id") == "me"

        # Create message bubble
        bubble = MessageBubble(message, is_own)

        # Add to layout
        self.messages_layout.insertWidget(
            self.messages_layout.count() - 1, bubble  # Before the stretch
        )

        # Scroll to bottom
        QTimer.singleShot(100, self.scroll_to_bottom)

        # Add to messages list
        self.messages.append(message)

    def set_messages(self, messages: List[Dict[str, Any]]):
        """Set the messages to display."""
        self.clear_messages()

        for message in messages:
            self.add_message(message)

    def clear_messages(self):
        """Clear all messages from the chat."""
        # Remove all widgets except the stretch
        while self.messages_layout.count() > 1:  # Keep the stretch
            item = self.messages_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.messages = []

    def scroll_to_bottom(self):
        """Scroll the messages area to the bottom."""
        scrollbar = self.messages_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def on_send_clicked(self):
        """Handle send button click."""
        text = self.message_input.toPlainText().strip()
        if not text:
            return

        # Emit signal with message content
        self.send_message.emit(text)

        # Clear input
        self.message_input.clear()

    def on_text_changed(self):
        """Handle text changes in the message input."""
        text = self.message_input.toPlainText().strip()
        self.send_btn.setEnabled(bool(text))

    def on_attach_clicked(self):
        """Handle attach file button click."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File",
            "",
            "All Files (*);;Images (*.png *.jpg *.jpeg);;Documents (*.pdf *.doc *.docx)",
        )

        if file_path:
            self.send_file.emit(file_path)

    # Drag and drop support
    def dragEnterEvent(self, event):
        """Handle drag enter event."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        """Handle drop event."""
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.send_file.emit(url.toLocalFile())

        event.acceptProposedAction()

    def keyPressEvent(self, event):
        """Handle key press events."""
        # Send message on Ctrl+Enter or Cmd+Enter
        if event.key() == Qt.Key_Return and (
            event.modifiers() & Qt.ControlModifier or event.modifiers() & Qt.MetaModifier
        ):
            self.on_send_clicked()
        else:
            super().keyPressEvent(event)
