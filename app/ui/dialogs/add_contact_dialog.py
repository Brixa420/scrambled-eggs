"""
Add Contact Dialog

Provides a dialog for adding new contacts to the application.
"""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QMessageBox,
    QVBoxLayout,
)


class AddContactDialog(QDialog):
    """Dialog for adding a new contact."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Contact")
        self.setMinimumWidth(400)

        self.setup_ui()

    def setup_ui(self):
        """Initialize the dialog UI components."""
        layout = QVBoxLayout(self)

        # Form layout for contact details
        form_layout = QFormLayout()

        # Name field
        self.name_edit = QLineEdit()
        form_layout.addRow("Name:", self.name_edit)

        # Email field
        self.email_edit = QLineEdit()
        self.email_edit.setPlaceholderText("example@domain.com")
        form_layout.addRow("Email:", self.email_edit)

        # Public key field
        self.public_key_edit = QLineEdit()
        self.public_key_edit.setPlaceholderText("Paste public key here...")
        form_layout.addRow("Public Key:", self.public_key_edit)

        layout.addLayout(form_layout)

        # Buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel, Qt.Horizontal, self
        )
        button_box.accepted.connect(self.validate_and_accept)
        button_box.rejected.connect(self.reject)

        layout.addWidget(button_box)

    def validate_and_accept(self):
        """Validate input before accepting the dialog."""
        name = self.name_edit.text().strip()
        email = self.email_edit.text().strip()
        public_key = self.public_key_edit.text().strip()

        if not name:
            QMessageBox.warning(self, "Validation Error", "Name is required.")
            return

        if not email or "@" not in email:
            QMessageBox.warning(self, "Validation Error", "Please enter a valid email address.")
            return

        if not public_key:
            QMessageBox.warning(self, "Validation Error", "Public key is required.")
            return

        self.accept()

    def get_contact_data(self):
        """Return the contact data as a dictionary."""
        return {
            "name": self.name_edit.text().strip(),
            "email": self.email_edit.text().strip(),
            "public_key": self.public_key_edit.text().strip(),
        }
