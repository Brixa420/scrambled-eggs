"""
Status Bar for Scrambled Eggs
---------------------------
Provides a custom status bar implementation with message queuing and timeout support.
"""

import logging
from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QHBoxLayout, QLabel, QStatusBar, QWidget

logger = logging.getLogger(__name__)


class StatusBar(QStatusBar):
    """Custom status bar with message queuing and timeout support."""

    # Signal emitted when the status message changes
    message_changed = Signal(str)

    def __init__(self, parent=None):
        """Initialize the status bar."""
        super().__init__(parent)
        self.setObjectName("status_bar")

        # Set default timeout for temporary messages (in milliseconds)
        self.default_timeout = 5000  # 5 seconds

        # Create a container widget for the status bar content
        self.container = QWidget()
        self.layout = QHBoxLayout(self.container)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(10)

        # Create message label
        self.message_label = QLabel()
        self.message_label.setObjectName("status_message")
        self.message_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.layout.addWidget(self.message_label, 1)  # Stretch factor of 1

        # Add the container to the status bar
        self.addPermanentWidget(self.container, 1)

        # Timer for temporary messages
        self.message_timer = QTimer(self)
        self.message_timer.setSingleShot(True)
        self.message_timer.timeout.connect(self.clear_message)

        # Initialize with empty message
        self.clear_message()

    def show_message(self, message: str, timeout: Optional[int] = None):
        """
        Show a message in the status bar.

        Args:
            message: The message to display
            timeout: Time in milliseconds before the message is cleared.
                    If None, uses the default timeout. If 0, the message stays until cleared.
        """
        logger.debug(f"Status message: {message}")
        self.message_label.setText(message)
        self.message_changed.emit(message)

        # Stop any existing timer
        self.message_timer.stop()

        # Set up new timer if timeout is not 0
        if timeout != 0:
            self.message_timer.start(timeout if timeout is not None else self.default_timeout)

    def clear_message(self):
        """Clear the status bar message."""
        self.message_label.clear()
        self.message_changed.emit("")

    def current_message(self) -> str:
        """Get the current status message."""
        return self.message_label.text()

    def set_default_timeout(self, timeout: int):
        """Set the default timeout for temporary messages.

        Args:
            timeout: Time in milliseconds before temporary messages are cleared.
        """
        self.default_timeout = max(0, timeout)

    def show_temporary_message(self, message: str, timeout: Optional[int] = None):
        """Show a temporary message that will be automatically cleared.

        Args:
            message: The message to display
            timeout: Time in milliseconds before the message is cleared.
                    If None, uses the default timeout.
        """
        self.show_message(message, timeout or self.default_timeout)

    def show_permanent_message(self, message: str):
        """Show a message that stays until explicitly cleared.

        Args:
            message: The message to display
        """
        self.show_message(message, 0)


if __name__ == "__main__":
    """Simple test for the status bar."""
    import sys

    from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget

    app = QApplication(sys.argv)

    window = QMainWindow()
    window.setWindowTitle("Status Bar Test")
    window.resize(400, 200)

    # Create a central widget
    central_widget = QWidget()
    layout = QVBoxLayout(central_widget)

    # Create and add the status bar
    status_bar = StatusBar()
    window.setStatusBar(status_bar)

    # Add test buttons
    btn_show = QPushButton("Show Temporary Message (5s)")
    btn_show.clicked.connect(
        lambda: status_bar.show_temporary_message("This is a temporary message")
    )
    layout.addWidget(btn_show)

    btn_permanent = QPushButton("Show Permanent Message")
    btn_permanent.clicked.connect(
        lambda: status_bar.show_permanent_message("This is a permanent message")
    )
    layout.addWidget(btn_permanent)

    btn_clear = QPushButton("Clear Message")
    btn_clear.clicked.connect(status_bar.clear_message)
    layout.addWidget(btn_clear)

    btn_custom = QPushButton("Show Custom Timeout (2s)")
    btn_custom.clicked.connect(
        lambda: status_bar.show_message("This message will disappear in 2 seconds", 2000)
    )
    layout.addWidget(btn_custom)

    # Add stretch to push buttons to the top
    layout.addStretch()

    window.setCentralWidget(central_widget)
    window.show()

    # Show initial message
    status_bar.show_temporary_message("Status bar ready")

    sys.exit(app.exec())
