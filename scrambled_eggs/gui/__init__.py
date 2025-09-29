"""
Scrambled Eggs GUI Package
-------------------------
Provides a graphical user interface for the Scrambled Eggs encryption system.
"""

# This file makes the gui directory a Python package

from .file_encryption_dialog import FileEncryptionDialog
from .key_management_dialog import KeyManagementDialog
from .login_dialog import LoginDialog

# Import key components to make them available at the package level
from .main_window import MainWindow
from .settings_dialog import SettingsDialog
from .status_bar import StatusBar

__all__ = [
    "MainWindow",
    "LoginDialog",
    "FileEncryptionDialog",
    "KeyManagementDialog",
    "SettingsDialog",
    "StatusBar",
]
