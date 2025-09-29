"""
Message Status Component

Provides visual indicators for message delivery status.
"""

from datetime import datetime
from enum import Enum, auto

import ipywidgets as widgets
from IPython.display import display


class MessageStatus(Enum):
    """Enumeration of possible message statuses."""

    SENDING = auto()
    SENT = auto()
    DELIVERED = auto()
    READ = auto()
    FAILED = auto()


class MessageStatusIndicator:
    """Component for displaying message status indicators."""

    # Icons for different statuses
    STATUS_ICONS = {
        MessageStatus.SENDING: "🔄",
        MessageStatus.SENT: "✓",
        MessageStatus.DELIVERED: "✓✓",
        MessageStatus.READ: "✓✓✓",
        MessageStatus.FAILED: "✗",
    }

    # Tooltips for different statuses
    STATUS_TOOLTIPS = {
        MessageStatus.SENDING: "Sending...",
        MessageStatus.SENT: "Sent",
        MessageStatus.DELIVERED: "Delivered",
        MessageStatus.READ: "Read",
        MessageStatus.FAILED: "Failed to send",
    }

    def __init__(self, p2p_manager):
        """Initialize the message status indicator.

        Args:
            p2p_manager: Instance of P2PManager
        """
        self.p2p_manager = p2p_manager
        self.status_widgets = {}  # message_id -> status widget
        self._init_ui()

    def _init_ui(self):
        """Initialize the UI components."""
        # Container for status indicators
        self.container = widgets.VBox([])

        # Subscribe to message status updates
        self.p2p_manager.on_message_status_update(self._on_message_status_update)

    def _on_message_status_update(
        self, message_id: str, status: MessageStatus, timestamp: datetime
    ):
        """Handle message status updates.

        Args:
            message_id: ID of the message
            status: New status of the message
            timestamp: When the status was updated
        """
        # Create a new status widget if it doesn't exist
        if message_id not in self.status_widgets:
            self._create_status_widget(message_id)

        # Update the status
        self._update_status_widget(message_id, status, timestamp)

    def _create_status_widget(self, message_id: str):
        """Create a new status widget for a message.

        Args:
            message_id: ID of the message
        """
        # Create the status indicator
        status_icon = widgets.HTML(value=self.STATUS_ICONS[MessageStatus.SENDING])
        status_icon.add_class("message-status")

        # Create a timestamp label
        timestamp_label = widgets.HTML(
            value=f"<span class='timestamp'>{datetime.now().strftime('%H:%M')}</span>"
        )
        timestamp_label.add_class("message-timestamp")

        # Create a container for the status
        status_container = widgets.HBox([status_icon, timestamp_label])
        status_container.add_class("message-status-container")

        # Store the widget
        self.status_widgets[message_id] = {
            "container": status_container,
            "icon": status_icon,
            "timestamp": timestamp_label,
            "status": MessageStatus.SENDING,
        }

        # Add the widget to the container
        self.container.children = (*self.container.children, status_container)

    def _update_status_widget(self, message_id: str, status: MessageStatus, timestamp: datetime):
        """Update a status widget.

        Args:
            message_id: ID of the message
            status: New status
            timestamp: When the status was updated
        """
        if message_id not in self.status_widgets:
            return

        widget = self.status_widgets[message_id]
        widget["status"] = status
        widget["icon"].value = self.STATUS_ICONS[status]
        widget["timestamp"].value = f"<span class='timestamp'>{timestamp.strftime('%H:%M')}</span>"

        # Add tooltip
        tooltip = self.STATUS_TOOLTIPS[status]
        widget["icon"].tooltip = f"{tooltip} at {timestamp.strftime('%H:%M:%S')}"

        # Add CSS class based on status
        widget["container"].add_class(f"status-{status.name.lower()}")

    def display(self):
        """Display the status indicators."""
        display(self.container)

    def clear(self):
        """Clear all status indicators."""
        self.status_widgets.clear()
        self.container.children = ()


def create_message_status_indicator(p2p_manager):
    """Create and display a message status indicator.

    Args:
        p2p_manager: Instance of P2PManager

    Returns:
        MessageStatusIndicator: The created indicator instance
    """
    indicator = MessageStatusIndicator(p2p_manager)
    indicator.display()
    return indicator
