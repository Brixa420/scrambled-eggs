"""
Dialog modules for the application.

This package contains various dialog windows used throughout the application.
"""

from .add_contact_dialog import AddContactDialog
from .file_transfer_dialog import FileTransferDialog
from .settings_dialog import SettingsDialog

__all__ = ["SettingsDialog", "AddContactDialog", "FileTransferDialog"]
