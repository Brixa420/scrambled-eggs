"""
Contact list widget for displaying and managing contacts.
"""

from typing import List

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMenu,
    QStyledItemDelegate,
    QVBoxLayout,
    QWidget,
)

from app.models.contact import Contact


class ContactListItem(QWidget):
    """Custom widget for displaying a contact in the list."""

    def __init__(self, contact: Contact, parent=None):
        """Initialize the contact list item."""
        super().__init__(parent)
        self.contact = contact
        self.unread_count = 0

        self.setup_ui()
        self.update_display()

    def setup_ui(self):
        """Set up the user interface."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(10)

        # Avatar
        self.avatar_label = QLabel()
        self.avatar_label.setFixedSize(40, 40)
        self.avatar_label.setStyleSheet(
            """
            QLabel {
                border-radius: 20px;
                background-color: #e0e0e0;
                border: 1px solid #ccc;
            }
        """
        )

        # Default avatar with initials
        if self.contact.avatar:
            pixmap = QPixmap()
            pixmap.loadFromData(self.contact.avatar)
            self.avatar_label.setPixmap(
                pixmap.scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            )
        else:
            # Create a colored circle with initials
            colors = [
                "#ff9a9e",
                "#fad0c4",
                "#a1c4fd",
                "#c2e9fb",
                "#d4fc79",
                "#96e6a1",
                "#84fab0",
                "#8fd3f4",
                "#a6c1ee",
                "#fbc2eb",
            ]
            color = colors[hash(self.contact.id) % len(colors)]

            self.avatar_label.setStyleSheet(
                f"""
                QLabel {{
                    border-radius: 20px;
                    background-color: {color};
                    border: 1px solid #ccc;
                    color: white;
                    font-weight: bold;
                    font-size: 16px;
                    qproperty-alignment: AlignCenter;
                }}
            """
            )

            # Get initials
            name_parts = self.contact.name.split()
            if len(name_parts) >= 2:
                initials = name_parts[0][0] + name_parts[-1][0]
            else:
                initials = self.contact.name[:2].upper()

            self.avatar_label.setText(initials)

        layout.addWidget(self.avatar_label)

        # Contact info
        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(0, 0, 0, 0)
        info_layout.setSpacing(2)

        # Name and status
        name_layout = QHBoxLayout()

        self.name_label = QLabel(self.contact.name)
        self.name_label.setStyleSheet("font-weight: bold;")
        name_layout.addWidget(self.name_label)

        # Online status indicator
        self.status_indicator = QLabel()
        self.status_indicator.setFixedSize(10, 10)
        self.status_indicator.setStyleSheet(
            """
            QLabel {
                border-radius: 5px;
                background-color: #cccccc;
            }
        """
        )
        name_layout.addWidget(self.status_indicator)

        name_layout.addStretch()

        # Last seen/last message time
        self.time_label = QLabel()
        self.time_label.setStyleSheet("color: #888888; font-size: 11px;")
        name_layout.addWidget(self.time_label)

        info_layout.addLayout(name_layout)

        # Last message preview
        self.preview_label = QLabel()
        self.preview_label.setStyleSheet("color: #666666; font-size: 12px;")
        self.preview_label.setMaximumWidth(200)
        self.preview_label.setWordWrap(True)
        info_layout.addWidget(self.preview_label)

        layout.addLayout(info_layout, 1)

        # Unread count badge
        self.unread_badge = QLabel()
        self.unread_badge.setFixedSize(20, 20)
        self.unread_badge.setAlignment(Qt.AlignCenter)
        self.unread_badge.setStyleSheet(
            """
            QLabel {
                background-color: #4a90e2;
                color: white;
                border-radius: 10px;
                font-size: 10px;
                font-weight: bold;
                padding: 2px;
                min-width: 20px;
                max-width: 20px;
                min-height: 20px;
                max-height: 20px;
            }
        """
        )
        self.unread_badge.hide()
        layout.addWidget(self.unread_badge)

        # Set up context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def update_display(self):
        """Update the display with current contact data."""
        self.name_label.setText(self.contact.name)

        # Update online status
        if self.contact.is_online:
            self.status_indicator.setStyleSheet(
                """
                QLabel {
                    border-radius: 5px;
                    background-color: #4caf50;
                }
            """
            )
        else:
            self.status_indicator.setStyleSheet(
                """
                QLabel {
                    border-radius: 5px;
                    background-color: #cccccc;
                }
            """
            )

        # Update last seen/last message time
        if self.contact.last_message_time:
            from datetime import datetime

            last_seen = datetime.fromtimestamp(self.contact.last_message_time)
            now = datetime.now()

            if last_seen.date() == now.date():
                self.time_label.setText(last_seen.strftime("%H:%M"))
            elif (now - last_seen).days < 7:
                self.time_label.setText(last_seen.strftime("%a"))
            else:
                self.time_label.setText(last_seen.strftime("%m/%d/%Y"))

        # Update last message preview
        if self.contact.last_message:
            preview = self.contact.last_message
            if len(preview) > 30:
                preview = preview[:27] + "..."
            self.preview_label.setText(preview)

        # Update unread count
        self.set_unread_count(self.unread_count)

    def set_unread_count(self, count: int):
        """Set the unread message count."""
        self.unread_count = count
        if count > 0:
            self.unread_badge.setText(str(count) if count < 100 else "99+")
            self.unread_badge.show()

            # Highlight unread messages
            self.setStyleSheet(
                """
                QWidget {
                    background-color: #f0f7ff;
                    border-radius: 5px;
                }
            """
            )
        else:
            self.unread_badge.hide()
            self.setStyleSheet("")

    def show_context_menu(self, position):
        """Show the context menu for the contact."""
        menu = QMenu(self)

        # Context menu actions
        start_chat = menu.addAction("Start Chat")
        start_chat.triggered.connect(lambda: self.contact_clicked.emit())

        voice_call = menu.addAction("Voice Call")
        voice_call.triggered.connect(lambda: self.call_triggered.emit(False))

        video_call = menu.addAction("Video Call")
        video_call.triggered.connect(lambda: self.call_triggered.emit(True))

        menu.addSeparator()

        view_profile = menu.addAction("View Profile")
        view_profile.triggered.connect(self.view_profile)

        menu.addSeparator()

        remove_contact = menu.addAction("Remove Contact")
        remove_contact.triggered.connect(self.remove_contact)

        # Show the menu at the cursor position
        menu.exec_(self.mapToGlobal(position))

    def view_profile(self):
        """View the contact's profile."""
        # This would open a profile dialog in a real app

    def remove_contact(self):
        """Remove this contact."""
        # This would be connected to the contact manager in the main app

    # Signals
    contact_clicked = Signal()
    call_triggered = Signal(bool)  # True for video call


class ContactListWidget(QListWidget):
    """List widget for displaying contacts."""

    contact_selected = Signal(str)  # contact_id
    call_requested = Signal(str, bool)  # contact_id, video_enabled

    def __init__(self, parent=None):
        """Initialize the contact list."""
        super().__init__(parent)
        self.setObjectName("contactList")
        self.setIconSize(QSize(40, 40))
        self.setSelectionMode(QListWidget.SingleSelection)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollMode(QListWidget.ScrollPerPixel)
        self.setFrameShape(QFrame.NoFrame)

        # Custom item delegate for styling
        self.setItemDelegate(ContactListItemDelegate(self))

        # Connect signals
        self.itemClicked.connect(self.on_item_clicked)

    def update_contacts(self, contacts: List[Contact]):
        """Update the contact list."""
        self.clear()

        # Sort contacts: online first, then by name
        online = [c for c in contacts if c.is_online]
        offline = [c for c in contacts if not c.is_online]

        sorted_contacts = sorted(online, key=lambda x: x.name.lower()) + sorted(
            offline, key=lambda x: x.name.lower()
        )

        for contact in sorted_contacts:
            self.add_contact(contact)

    def add_contact(self, contact: Contact):
        """Add a contact to the list."""
        item = QListWidgetItem()
        item.setSizeHint(QSize(0, 60))  # Fixed height for each contact
        item.setData(Qt.UserRole, contact.id)

        contact_widget = ContactListItem(contact)
        contact_widget.contact_clicked.connect(
            lambda cid=contact.id: self.contact_selected.emit(cid)
        )
        contact_widget.call_triggered.connect(
            lambda video, cid=contact.id: self.call_requested.emit(cid, video)
        )

        self.addItem(item)
        self.setItemWidget(item, contact_widget)

    def set_unread_count(self, contact_id: str, count: int):
        """Set the unread message count for a contact."""
        for i in range(self.count()):
            item = self.item(i)
            if item.data(Qt.UserRole) == contact_id:
                widget = self.itemWidget(item)
                if widget:
                    widget.set_unread_count(count)
                break

    def update_online_status(self, contact_id: str, online: bool):
        """Update the online status of a contact."""
        for i in range(self.count()):
            item = self.item(i)
            if item.data(Qt.UserRole) == contact_id:
                widget = self.itemWidget(item)
                if widget:
                    widget.contact.is_online = online
                    widget.update_display()
                break

    def filter_contacts(self, text: str):
        """Filter contacts by name or ID."""
        text = text.lower()
        for i in range(self.count()):
            item = self.item(i)
            widget = self.itemWidget(item)
            if widget:
                matches = text in widget.contact.name.lower() or text in widget.contact.id.lower()
                item.setHidden(not matches)

    def on_item_clicked(self, item):
        """Handle item click."""
        contact_id = item.data(Qt.UserRole)
        self.contact_selected.emit(contact_id)


class ContactListItemDelegate(QStyledItemDelegate):
    """Custom delegate for styling contact list items."""

    def paint(self, painter, option, index):
        """Custom paint method for the delegate."""
        # Let the default painter handle the background and selection
        option.widget.style().drawControl(QStyle.CE_ItemViewItem, option, painter, option.widget)

        # Get the widget and draw it
        widget = option.widget.itemWidget(index.model().index(index.row(), 0))
        if widget:
            painter.save()
            painter.translate(option.rect.topLeft())
            widget.render(painter, QPoint(0, 0))
            painter.restore()

    def sizeHint(self, option, index):
        """Return the size hint for the item."""
        return QSize(0, 60)  # Fixed height for each contact
