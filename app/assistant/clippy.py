"""
Clippy Assistant - An intelligent assistant for Scrambled Eggs
"""
import random
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Awaitable, Any
from enum import Enum, auto

from PySide6.QtCore import QObject, Signal, QTimer, QUrl, Qt
from PySide6.QtGui import QPixmap, QIcon, QDesktopServices
from PySideboard.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QLabel, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTextEdit, QWidget, QScrollArea, QFrame, QSizePolicy
)

from app.models.message import Message, MessageType
from app.crypto.encryption_manager import EncryptionManager

logger = logging.getLogger(__name__)

class ClippyState(Enum):
    IDLE = auto()
    LISTENING = auto()
    PROCESSING = auto()
    RESPONDING = auto()
    HELPING = auto()

@dataclass
class ClippyMessage:
    """A message in the Clippy conversation."""
    text: str
    is_from_user: bool
    timestamp: float = field(default_factory=lambda: time.time())
    message_type: MessageType = MessageType.TEXT
    metadata: dict = field(default_factory=dict)

class ClippyPersonality:
    """Defines Clippy's personality and responses."""
    
    def __init__(self):
        self.greetings = [
            "Hi there! I'm Clippy, your Scrambled Eggs assistant. How can I help you today?",
            "Hello! I'm Clippy, here to help you with Scrambled Eggs. What can I do for you?",
            "Greetings! I'm Clippy, your friendly assistant. Need help with something?"
        ]
        
        self.help_responses = {
            "encrypt": [
                "To encrypt a message, simply type it in the chat and click send. I'll handle the encryption automatically!",
                "Encryption happens automatically when you send messages. Just type and send - I'll take care of the rest!"
            ],
            "decrypt": [
                "Decryption is automatic when you receive messages. Just read them in the chat!",
                "No need to worry about decryption - I'll show you decrypted messages as soon as they arrive."
            ],
            "file": [
                "To send an encrypted file, click the paperclip icon and select the file you want to send.",
                "Sending files is easy! Just click the attachment button and choose your file. It will be encrypted before sending."
            ],
            "call": [
                "To start a secure call, click the phone or video icon in the chat with your contact.",
                "Initiating a call is simple! Just open a chat and click the call button at the top."
            ],
            "contact": [
                "To add a contact, go to the Contacts tab and click 'Add Contact'. You'll need their public key.",
                "Adding contacts is easy! Go to Contacts and click the plus icon. Make sure you have their public key handy."
            ],
            "default": [
                "I'm not sure how to help with that. Could you try rephrasing your question?",
                "I'm still learning! Could you ask me something else?",
                "Hmm, I'm not sure about that one. Try asking about encryption, files, or contacts!"
            ]
        }
        
        self.tips = [
            "Did you know? All your messages are end-to-end encrypted by default!",
            "Tip: You can verify your contacts' keys to ensure secure communication.",
            "Remember: Never share your private key with anyone!",
            "Tip: Use the paperclip icon to send encrypted files to your contacts.",
            "Did you know? You can make secure voice and video calls too!"
        ]
        
        self.positive_feedback = [
            "Great!", "Awesome!", "Perfect!", "Excellent!", "Got it!"
        ]
        
        self.negative_feedback = [
            "I'm sorry, I didn't understand that.",
            "I'm not sure what you mean.",
            "Could you rephrase that?"
        ]
    
    def get_random_response(self, category: str = "default") -> str:
        """Get a random response from the specified category."""
        responses = self.help_responses.get(category, self.help_responses["default"])
        return random.choice(responses)
    
    def get_greeting(self) -> str:
        """Get a random greeting."""
        return random.choice(self.greetings)
    
    def get_tip(self) -> str:
        """Get a random tip."""
        return random.choice(self.tips)
    
    def get_positive_feedback(self) -> str:
        """Get a random positive feedback message."""
        return random.choice(self.positive_feedback)
    
    def get_negative_feedback(self) -> str:
        """Get a random negative feedback message."""
        return random.choice(self.negative_feedback)


class ClippyAssistant(QObject):
    """Clippy Assistant - An intelligent assistant for Scrambled Eggs."""
    
    # Signals
    message_received = Signal(ClippyMessage)
    state_changed = Signal(ClippyState)
    tip_available = Signal(str)
    
    def __init__(self, parent=None):
        """Initialize the Clippy assistant."""
        super().__init__(parent)
        self.personality = ClippyPersonality()
        self.state = ClippyState.IDLE
        self.conversation: List[ClippyMessage] = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._check_for_tips)
        self.timer.start(60000)  # Check for tips every minute
        
        # Start with a greeting
        self._add_system_message(self.personality.get_greeting())
    
    def set_state(self, new_state: ClippyState):
        """Set the current state of the assistant."""
        if self.state != new_state:
            self.state = new_state
            self.state_changed.emit(new_state)
    
    def process_message(self, message: str):
        """Process a message from the user."""
        # Add user message to conversation
        user_msg = ClippyMessage(
            text=message,
            is_from_user=True,
            message_type=MessageType.TEXT
        )
        self.conversation.append(user_msg)
        
        # Process the message
        self.set_state(ClippyState.PROCESSING)
        
        # Simple keyword matching for demo purposes
        # In a real implementation, this would use NLP
        message_lower = message.lower()
        
        if any(word in message_lower for word in ["hello", "hi", "hey"]):
            response = f"{self.personality.get_positive_feedback()} {self.personality.get_greeting()}"
        elif any(word in message_lower for word in ["help", "how", "what", "where"]):
            if "encrypt" in message_lower or "secure" in message_lower:
                response = self.personality.get_random_response("encrypt")
            elif "decrypt" in message_lower or "read" in message_lower:
                response = self.personality.get_random_response("decrypt")
            elif "file" in message_lower or "send" in message_lower:
                response = self.personality.get_random_response("file")
            elif "call" in message_lower or "video" in message_lower or "voice" in message_lower:
                response = self.personality.get_random_response("call")
            elif "contact" in message_lower or "add" in message_lower:
                response = self.personality.get_random_response("contact")
            else:
                response = self.personality.get_random_response("default")
        else:
            response = self.personality.get_random_response("default")
        
        # Add a small delay to simulate processing
        QTimer.singleShot(1000, lambda: self._send_response(response))
    
    def _send_response(self, response: str):
        """Send a response to the user."""
        clippy_msg = ClippyMessage(
            text=response,
            is_from_user=False,
            message_type=MessageType.TEXT
        )
        self.conversation.append(clippy_msg)
        self.message_received.emit(clippy_msg)
        self.set_state(ClippyState.IDLE)
    
    def _add_system_message(self, text: str):
        """Add a system message to the conversation."""
        msg = ClippyMessage(
            text=text,
            is_from_user=False,
            message_type=MessageType.SYSTEM
        )
        self.conversation.append(msg)
        self.message_received.emit(msg)
    
    def _check_for_tips(self):
        """Check if we should show a tip to the user."""
        # Only show tips occasionally (20% chance)
        if random.random() < 0.2:
            self.tip_available.emit(self.personality.get_tip())
    
    def reset_conversation(self):
        """Reset the conversation."""
        self.conversation = []
        self._add_system_message(self.personality.get_greeting())


class ClippyUI(QWidget):
    """User interface for the Clippy assistant."""
    
    def __init__(self, parent=None):
        """Initialize the Clippy UI."""
        super().__init__(parent)
        self.assistant = ClippyAssistant()
        self.init_ui()
        self.setup_connections()
    
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Clippy Assistant")
        self.setMinimumSize(400, 500)
        
        # Main layout
        layout = QVBoxLayout(self)
        
        # Conversation area
        self.conversation_area = QScrollArea()
        self.conversation_area.setWidgetResizable(True)
        self.conversation_widget = QWidget()
        self.conversation_layout = QVBoxLayout(self.conversation_widget)
        self.conversation_layout.setAlignment(Qt.AlignTop)
        self.conversation_area.setWidget(self.conversation_widget)
        
        # Input area
        self.input_field = QTextEdit()
        self.input_field.setMaximumHeight(100)
        self.input_field.setPlaceholderText("Type your message here...")
        
        # Buttons
        button_layout = QHBoxLayout()
        self.send_button = QPushButton("Send")
        self.help_button = QPushButton("Help")
        self.clear_button = QPushButton("Clear")
        
        button_layout.addWidget(self.help_button)
        button_layout.addWidget(self.clear_button)
        button_layout.addStretch()
        button_layout.addWidget(self.send_button)
        
        # Add widgets to layout
        layout.addWidget(self.conversation_area)
        layout.addWidget(QLabel("Ask me anything:"))
        layout.addWidget(self.input_field)
        layout.addLayout(button_layout)
        
        # Set style
        self.setStyleSheet("""
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QPushButton {
                padding: 5px 15px;
                border: 1px solid #0078d7;
                border-radius: 4px;
                background-color: #f0f0f0;
                color: #0078d7;
            }
            QPushButton:hover {
                background-color: #e0e0e0;
            }
            QPushButton:pressed {
                background-color: #d0d0d0;
            }
            QTextEdit {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
            }
            QLabel#user_message {
                background-color: #e3f2fd;
                border-radius: 10px;
                padding: 8px 12px;
                margin: 5px 0;
                max-width: 80%;
                align-self: flex-end;
            }
            QLabel#assistant_message {
                background-color: #f5f5f5;
                border-radius: 10px;
                padding: 8px 12px;
                margin: 5px 0;
                max-width: 80%;
                align-self: flex-start;
            }
        """)
    
    def setup_connections(self):
        """Set up signal-slot connections."""
        self.send_button.clicked.connect(self.send_message)
        self.help_button.clicked.connect(self.show_help)
        self.clear_button.clicked.connect(self.clear_conversation)
        self.assistant.message_received.connect(self.display_message)
        self.assistant.tip_available.connect(self.show_tip)
        self.input_field.returnPressed.connect(self.send_message)
    
    def send_message(self):
        """Send a message to the assistant."""
        message = self.input_field.toPlainText().strip()
        if message:
            self.display_message(ClippyMessage(
                text=message,
                is_from_user=True,
                message_type=MessageType.TEXT
            ))
            self.assistant.process_message(message)
            self.input_field.clear()
    
    def display_message(self, message: ClippyMessage):
        """Display a message in the conversation area."""
        label = QLabel(message.text)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        
        # Set alignment and style based on sender
        if message.is_from_user:
            label.setAlignment(Qt.AlignRight)
            label.setObjectName("user_message")
            label.setStyleSheet("""
                QLabel#user_message {
                    background-color: #e3f2fd;
                    border-radius: 10px;
                    padding: 8px 12px;
                    margin: 5px 0 5px 20%;
                    max-width: 80%;
                }
            """)
        else:
            label.setAlignment(Qt.AlignLeft)
            label.setObjectName("assistant_message")
            label.setStyleSheet("""
                QLabel#assistant_message {
                    background-color: #f5f5f5;
                    border-radius: 10px;
                    padding: 8px 12px;
                    margin: 5px 20% 5px 0;
                    max-width: 80%;
                }
            """)
        
        self.conversation_layout.addWidget(label)
        
        # Scroll to bottom
        self.conversation_area.verticalScrollBar().setValue(
            self.conversation_area.verticalScrollBar().maximum()
        )
    
    def show_help(self):
        """Show help information."""
        help_text = """
        <h3>Clippy Assistant Help</h3>
        <p>I can help you with:</p>
        <ul>
            <li>Sending and receiving encrypted messages</li>
            <li>Sharing files securely</li>
            <li>Making secure calls</li>
            <li>Managing your contacts</li>
            <li>And more!</li>
        </ul>
        <p>Just ask me anything, like:</p>
        <ul>
            <li>"How do I send an encrypted message?"</li>
            <li>"How does the encryption work?"</li>
            <li>"How do I add a contact?"</li>
        </ul>
        """
        self.display_message(ClippyMessage(
            text=help_text,
            is_from_user=False,
            message_type=MessageType.SYSTEM
        ))
    
    def show_tip(self, tip: str):
        """Show a helpful tip."""
        self.display_message(ClippyMessage(
            text=f"<b>Tip:</b> {tip}",
            is_from_user=False,
            message_type=MessageType.SYSTEM
        ))
    
    def clear_conversation(self):
        """Clear the conversation."""
        # Clear the layout
        while self.conversation_layout.count():
            item = self.conversation_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Reset the conversation
        self.assistant.reset_conversation()


# Example usage
if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show the Clippy UI
    clippy = ClippyUI()
    clippy.show()
    
    sys.exit(app.exec())
