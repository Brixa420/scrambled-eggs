"""
Key Management Dialog for Scrambled Eggs
---------------------------------------
Provides a dialog for managing encryption keys.
"""

import json
import logging
import os
from pathlib import Path

from PySide6.QtCore import QDate, QDateTime, QSize, Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDateEdit,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class KeyManagementDialog(QDialog):
    """A dialog for managing encryption keys."""

    def __init__(self, parent=None):
        """Initialize the key management dialog."""
        super().__init__(parent)
        self.setWindowTitle("Key Management - Scrambled Eggs")
        self.setMinimumSize(800, 600)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # Initialize UI
        self.init_ui()

        # Load keys
        self.load_keys()

    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Create toolbar
        self.create_toolbar()
        main_layout.addWidget(self.toolbar)

        # Create splitter for key list and details
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Create key list widget
        self.create_key_list_widget()
        splitter.addWidget(self.key_list_widget)

        # Create key details widget
        self.create_key_details_widget()
        splitter.addWidget(self.key_details_widget)

        # Set initial sizes
        splitter.setSizes([200, 400])

        # Add splitter to main layout
        main_layout.addWidget(splitter, 1)  # 1 is stretch factor

        # Create status bar
        self.status_bar = QStatusBar()
        main_layout.addWidget(self.status_bar)

        # Update status
        self.update_status()

    def create_toolbar(self):
        """Create the toolbar with key management actions."""
        self.toolbar = QToolBar("Key Management")
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextUnderIcon)

        # Create actions
        self.new_key_action = QAction(
            self.style().standardIcon(self.style().StandardPixmap.SP_FileIcon), "New Key", self
        )
        self.new_key_action.triggered.connect(self.new_key)
        self.new_key_action.setStatusTip("Create a new encryption key")

        self.import_key_action = QAction(
            self.style().standardIcon(self.style().StandardPixmap.SP_ArrowUp), "Import", self
        )
        self.import_key_action.triggered.connect(self.import_key)
        self.import_key_action.setStatusTip("Import a key from a file")

        self.export_key_action = QAction(
            self.style().standardIcon(self.style().StandardPixmap.SP_ArrowDown), "Export", self
        )
        self.export_key_action.triggered.connect(self.export_key)
        self.export_key_action.setStatusTip("Export the selected key to a file")
        self.export_key_action.setEnabled(False)

        self.delete_key_action = QAction(
            self.style().standardIcon(self.style().StandardPixmap.SP_TrashIcon), "Delete", self
        )
        self.delete_key_action.triggered.connect(self.delete_key)
        self.delete_key_action.setStatusTip("Delete the selected key")
        self.delete_key_action.setEnabled(False)

        self.refresh_action = QAction(
            self.style().standardIcon(self.style().StandardPixmap.SP_BrowserReload), "Refresh", self
        )
        self.refresh_action.triggered.connect(self.refresh_keys)
        self.refresh_action.setStatusTip("Refresh the key list")

        # Add actions to toolbar
        self.toolbar.addAction(self.new_key_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.import_key_action)
        self.toolbar.addAction(self.export_key_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.delete_key_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.refresh_action)

    def create_key_list_widget(self):
        """Create the key list widget."""
        self.key_list_widget = QWidget()
        layout = QVBoxLayout(self.key_list_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        # Search box
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search keys...")
        self.search_edit.textChanged.connect(self.filter_keys)
        layout.addWidget(self.search_edit)

        # Key list
        self.key_list = QTreeWidget()
        self.key_list.setHeaderHidden(True)
        self.key_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.key_list.itemSelectionChanged.connect(self.on_key_selected)
        self.key_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.key_list.customContextMenuRequested.connect(self.show_context_menu)

        # Add key list to layout
        layout.addWidget(self.key_list)

    def create_key_details_widget(self):
        """Create the key details widget."""
        self.key_details_widget = QWidget()
        layout = QVBoxLayout(self.key_details_widget)

        # Key info group
        info_group = QGroupBox("Key Information")
        info_layout = QFormLayout()

        self.key_name_edit = QLineEdit()
        self.key_name_edit.setPlaceholderText("Enter a name for this key")
        info_layout.addRow("Name:", self.key_name_edit)

        self.key_id_edit = QLineEdit()
        self.key_id_edit.setReadOnly(True)
        info_layout.addRow("Key ID:", self.key_id_edit)

        self.key_type_combo = QComboBox()
        self.key_type_combo.addItems(["AES-256", "RSA-4096", "ECC-384", "ChaCha20"])
        info_layout.addRow("Type:", self.key_type_combo)

        self.key_created_edit = QDateTimeEdit()
        self.key_created_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.key_created_edit.setReadOnly(True)
        info_layout.addRow("Created:", self.key_created_edit)

        self.key_expires_edit = QDateTimeEdit()
        self.key_expires_edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        self.key_expires_edit.setCalendarPopup(True)
        self.key_expires_edit.setDateTime(QDateTime.currentDateTime().addYears(1))
        info_layout.addRow("Expires:", self.key_expires_edit)

        self.key_enabled_check = QCheckBox("Key is enabled")
        self.key_enabled_check.setChecked(True)
        info_layout.addRow("", self.key_enabled_check)

        info_group.setLayout(info_layout)

        # Key metadata group
        meta_group = QGroupBox("Metadata")
        meta_layout = QFormLayout()

        self.key_owner_edit = QLineEdit()
        self.key_owner_edit.setPlaceholderText("Key owner or organization")
        meta_layout.addRow("Owner:", self.key_owner_edit)

        self.key_email_edit = QLineEdit()
        self.key_email_edit.setPlaceholderText("owner@example.com")
        meta_layout.addRow("Email:", self.key_email_edit)

        self.key_notes_edit = QTextEdit()
        self.key_notes_edit.setPlaceholderText("Additional notes about this key")
        self.key_notes_edit.setMaximumHeight(100)
        meta_layout.addRow("Notes:", self.key_notes_edit)

        meta_group.setLayout(meta_layout)

        # Key usage group
        usage_group = QGroupBox("Key Usage")
        usage_layout = QVBoxLayout()

        self.usage_encrypt_check = QCheckBox("Encryption")
        self.usage_encrypt_check.setChecked(True)
        usage_layout.addWidget(self.usage_encrypt_check)

        self.usage_decrypt_check = QCheckBox("Decryption")
        self.usage_decrypt_check.setChecked(True)
        usage_layout.addWidget(self.usage_decrypt_check)

        self.usage_sign_check = QCheckBox("Digital Signatures")
        self.usage_sign_check.setChecked(True)
        usage_layout.addWidget(self.usage_sign_check)

        self.usage_verify_check = QCheckBox("Signature Verification")
        self.usage_verify_check.setChecked(True)
        usage_layout.addWidget(self.usage_verify_check)

        usage_group.setLayout(usage_layout)

        # Key details
        details_group = QGroupBox("Key Details")
        details_layout = QFormLayout()

        self.key_algorithm_edit = QLineEdit()
        self.key_algorithm_edit.setReadOnly(True)
        details_layout.addRow("Algorithm:", self.key_algorithm_edit)

        self.key_size_edit = QLineEdit()
        self.key_size_edit.setReadOnly(True)
        details_layout.addRow("Key Size:", self.key_size_edit)

        self.key_fingerprint_edit = QLineEdit()
        self.key_fingerprint_edit.setReadOnly(True)
        details_layout.addRow("Fingerprint:", self.key_fingerprint_edit)

        details_group.setLayout(details_layout)

        # Button box
        button_box = QDialogButtonBox()
        self.save_button = button_box.addButton("Save", QDialogButtonBox.ButtonRole.AcceptRole)
        self.save_button.clicked.connect(self.save_key)
        self.save_button.setEnabled(False)

        self.cancel_button = button_box.addButton("Cancel", QDialogButtonBox.ButtonRole.RejectRole)
        self.cancel_button.clicked.connect(self.cancel_edit)
        self.cancel_button.setEnabled(False)

        # Add all groups to layout
        layout.addWidget(info_group)
        layout.addWidget(meta_group)
        layout.addWidget(usage_group)
        layout.addWidget(details_group)
        layout.addStretch()
        layout.addWidget(button_box)

    def load_keys(self):
        """Load the list of keys."""
        self.key_list.clear()

        # In a real implementation, this would load keys from a secure storage
        # For now, we'll use some sample data
        sample_keys = [
            {
                "id": "a1b2c3d4",
                "name": "Personal Key",
                "type": "AES-256",
                "created": "2023-01-15 10:30:00",
                "expires": "2024-01-15 10:30:00",
                "enabled": True,
                "owner": "John Doe",
                "email": "john.doe@example.com",
                "notes": "My personal encryption key",
            },
            {
                "id": "e5f6g7h8",
                "name": "Work Key",
                "type": "RSA-4096",
                "created": "2023-02-20 14:15:00",
                "expires": "2025-02-20 14:15:00",
                "enabled": True,
                "owner": "Acme Corp",
                "email": "security@acme.com",
                "notes": "Corporate encryption key",
            },
            {
                "id": "i9j0k1l2",
                "name": "Backup Key",
                "type": "ECC-384",
                "created": "2023-03-10 09:45:00",
                "expires": "2024-03-10 09:45:00",
                "enabled": False,
                "owner": "John Doe",
                "email": "john.doe@example.com",
                "notes": "Backup key for emergency use",
            },
        ]

        # Group keys by owner
        owners = {}
        for key in sample_keys:
            owner = key.get("owner", "Unknown")
            if owner not in owners:
                owners[owner] = []
            owners[owner].append(key)

        # Add keys to the tree widget
        for owner, keys in owners.items():
            owner_item = QTreeWidgetItem([owner])
            owner_item.setData(0, Qt.ItemDataRole.UserRole, None)  # No data for group items

            for key in keys:
                key_item = QTreeWidgetItem([key["name"]])
                key_item.setData(0, Qt.ItemDataRole.UserRole, key)

                # Set icon based on key type
                if key["type"] == "AES-256":
                    icon = self.style().standardIcon(self.style().StandardPixmap.SP_FileIcon)
                elif key["type"] == "RSA-4096":
                    icon = self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon)
                else:
                    icon = self.style().standardIcon(self.style().StandardPixmap.SP_DriveHDIcon)

                key_item.setIcon(0, icon)

                # Disable if key is not enabled
                if not key["enabled"]:
                    key_item.setForeground(0, QColor("gray"))

                owner_item.addChild(key_item)

            self.key_list.addTopLevelItem(owner_item)

        # Expand all items
        self.key_list.expandAll()

        # Update status
        self.update_status()

    def filter_keys(self, text):
        """Filter the key list based on search text."""
        search_text = text.lower()

        for i in range(self.key_list.topLevelItemCount()):
            owner_item = self.key_list.topLevelItem(i)
            any_visible = False

            for j in range(owner_item.childCount()):
                key_item = owner_item.child(j)
                key_data = key_item.data(0, Qt.ItemDataRole.UserRole)

                # Show if search text is in key name or other attributes
                if (
                    search_text in key_item.text(0).lower()
                    or (key_data and search_text in key_data.get("id", "").lower())
                    or (key_data and search_text in key_data.get("email", "").lower())
                ):
                    key_item.setHidden(False)
                    any_visible = True
                else:
                    key_item.setHidden(True)

            # Show owner if any children are visible
            owner_item.setHidden(not any_visible)

    def on_key_selected(self):
        """Handle key selection change."""
        selected_items = self.key_list.selectedItems()

        if not selected_items:
            self.clear_key_details()
            self.export_key_action.setEnabled(False)
            self.delete_key_action.setEnabled(False)
            return

        item = selected_items[0]
        key_data = item.data(0, Qt.ItemDataRole.UserRole)

        # Only enable actions for key items (not group items)
        is_key_item = key_data is not None
        self.export_key_action.setEnabled(is_key_item)
        self.delete_key_action.setEnabled(is_key_item)

        if is_key_item:
            self.show_key_details(key_data)
        else:
            self.clear_key_details()

    def show_key_details(self, key_data):
        """Show details for the selected key."""
        # Enable/disable form fields
        self.set_form_enabled(True)

        # Set form values
        self.key_name_edit.setText(key_data.get("name", ""))
        self.key_id_edit.setText(key_data.get("id", ""))

        # Set key type
        key_type = key_data.get("type", "AES-256")
        index = self.key_type_combo.findText(key_type)
        if index >= 0:
            self.key_type_combo.setCurrentIndex(index)

        # Set dates
        created_date = QDateTime.fromString(key_data.get("created", ""), "yyyy-MM-dd HH:mm:ss")
        if created_date.isValid():
            self.key_created_edit.setDateTime(created_date)

        expires_date = QDateTime.fromString(key_data.get("expires", ""), "yyyy-MM-dd HH:mm:ss")
        if expires_date.isValid():
            self.key_expires_edit.setDateTime(expires_date)

        # Set checkboxes
        self.key_enabled_check.setChecked(key_data.get("enabled", True))

        # Set metadata
        self.key_owner_edit.setText(key_data.get("owner", ""))
        self.key_email_edit.setText(key_data.get("email", ""))
        self.key_notes_edit.setPlainText(key_data.get("notes", ""))

        # Set key details (read-only)
        self.key_algorithm_edit.setText(key_data.get("type", ""))
        self.key_size_edit.setText(str(len(key_data.get("id", "")) * 4) + " bits")  # Fake size
        self.key_fingerprint_edit.setText(
            ":".join(
                key_data.get("id", "")[i : i + 2]
                for i in range(0, min(16, len(key_data.get("id", ""))), 2)
            )
        )

        # Store the current key ID for updates
        self.current_key_id = key_data.get("id")

        # Enable save/cancel buttons
        self.save_button.setEnabled(True)
        self.cancel_button.setEnabled(True)

    def clear_key_details(self):
        """Clear the key details form."""
        # Disable form fields
        self.set_form_enabled(False)

        # Clear all fields
        self.key_name_edit.clear()
        self.key_id_edit.clear()
        self.key_type_combo.setCurrentIndex(0)
        self.key_created_edit.setDateTime(QDateTime.currentDateTime())
        self.key_expires_edit.setDateTime(QDateTime.currentDateTime().addYears(1))
        self.key_enabled_check.setChecked(True)
        self.key_owner_edit.clear()
        self.key_email_edit.clear()
        self.key_notes_edit.clear()
        self.key_algorithm_edit.clear()
        self.key_size_edit.clear()
        self.key_fingerprint_edit.clear()

        # Clear current key ID
        if hasattr(self, "current_key_id"):
            del self.current_key_id

        # Disable save/cancel buttons
        self.save_button.setEnabled(False)
        self.cancel_button.setEnabled(False)

    def set_form_enabled(self, enabled):
        """Enable or disable the key details form."""
        self.key_name_edit.setEnabled(enabled)
        self.key_type_combo.setEnabled(enabled)
        self.key_expires_edit.setEnabled(enabled)
        self.key_enabled_check.setEnabled(enabled)
        self.key_owner_edit.setEnabled(enabled)
        self.key_email_edit.setEnabled(enabled)
        self.key_notes_edit.setEnabled(enabled)

    def show_context_menu(self, position):
        """Show the context menu for the key list."""
        item = self.key_list.itemAt(position)
        if not item:
            return

        key_data = item.data(0, Qt.ItemDataRole.UserRole)
        if not key_data:  # Group item
            return

        menu = QMenu()

        export_action = menu.addAction("Export Key")
        export_action.triggered.connect(self.export_key)

        menu.addSeparator()

        delete_action = menu.addAction("Delete Key")
        delete_action.triggered.connect(self.delete_key)

        menu.exec(self.key_list.viewport().mapToGlobal(position))

    def new_key(self):
        """Create a new key."""
        # Clear the form and enable editing
        self.clear_key_details()
        self.set_form_enabled(True)

        # Generate a random key ID (in a real app, this would be a proper key ID)
        import random
        import string

        key_id = "".join(random.choices(string.hexdigits.lower(), k=8))

        # Set default values
        self.key_id_edit.setText(key_id)
        self.key_created_edit.setDateTime(QDateTime.currentDateTime())
        self.key_expires_edit.setDateTime(QDateTime.currentDateTime().addYears(1))

        # Set focus to name field
        self.key_name_edit.setFocus()

        # Enable save/cancel buttons
        self.save_button.setEnabled(True)
        self.cancel_button.setEnabled(True)

        # Set mode to new key
        self.is_new_key = True

    def save_key(self):
        """Save the current key."""
        # Validate inputs
        if not self.key_name_edit.text().strip():
            QMessageBox.warning(self, "Validation Error", "Please enter a name for the key.")
            self.key_name_edit.setFocus()
            return

        # In a real implementation, this would save the key to secure storage
        # For now, we'll just show a message
        key_name = self.key_name_edit.text()

        if hasattr(self, "is_new_key"):
            QMessageBox.information(self, "Success", f"Created new key: {key_name}")
            del self.is_new_key
        else:
            QMessageBox.information(self, "Success", f"Updated key: {key_name}")

        # Reload keys to show the new/updated key
        self.load_keys()

        # Clear the form
        self.clear_key_details()

    def cancel_edit(self):
        """Cancel the current edit operation."""
        if hasattr(self, "is_new_key"):
            del self.is_new_key

        self.clear_key_details()

    def import_key(self):
        """Import a key from a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Key", "", "Key Files (*.key *.pem *.der);;All Files (*)"
        )

        if file_path:
            try:
                # In a real implementation, this would import the key
                key_name = QFileInfo(file_path).baseName()
                QMessageBox.information(self, "Success", f"Imported key: {key_name}")

                # Reload keys
                self.load_keys()

            except Exception as e:
                QMessageBox.critical(self, "Import Error", f"Failed to import key: {str(e)}")

    def export_key(self):
        """Export the selected key to a file."""
        selected_items = self.key_list.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        key_data = item.data(0, Qt.ItemDataRole.UserRole)

        if not key_data:
            return

        default_name = f"{key_data.get('name', 'key').replace(' ', '_')}.key"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Key",
            default_name,
            "Key Files (*.key);;PEM Format (*.pem);;DER Format (*.der);;All Files (*)",
        )

        if file_path:
            try:
                # In a real implementation, this would export the key
                QMessageBox.information(self, "Success", f"Exported key to: {file_path}")

            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export key: {str(e)}")

    def delete_key(self):
        """Delete the selected key."""
        selected_items = self.key_list.selectedItems()
        if not selected_items:
            return

        item = selected_items[0]
        key_data = item.data(0, Qt.ItemDataRole.UserRole)

        if not key_data:
            return

        key_name = key_data.get("name", "this key")

        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete '{key_name}'?\n\nThis action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                # In a real implementation, this would delete the key from storage
                QMessageBox.information(self, "Success", f"Deleted key: {key_name}")

                # Reload keys
                self.load_keys()

                # Clear the form
                self.clear_key_details()

            except Exception as e:
                QMessageBox.critical(self, "Deletion Error", f"Failed to delete key: {str(e)}")

    def refresh_keys(self):
        """Refresh the key list."""
        self.load_keys()
        self.status_bar.showMessage("Key list refreshed", 3000)

    def update_status(self):
        """Update the status bar with key count."""
        key_count = 0

        for i in range(self.key_list.topLevelItemCount()):
            owner_item = self.key_list.topLevelItem(i)
            key_count += owner_item.childCount()

        self.status_bar.showMessage(f"{key_count} keys loaded")

    def closeEvent(self, event):
        """Handle window close event."""
        # In a real implementation, you might want to save window state here
        event.accept()


if __name__ == "__main__":
    import sys

    from PySide6.QtWidgets import QApplication

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Create and run the application
    app = QApplication(sys.argv)

    # Create and show the dialog
    dialog = KeyManagementDialog()
    dialog.show()

    sys.exit(app.exec())
