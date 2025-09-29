"""
Main Window for Scrambled Eggs GUI
---------------------------------
Provides the main application window with menu, toolbar, and status bar.
"""

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from PySide6.QtCore import QByteArray, QPoint, QSettings, QSize, QStandardPaths, Qt, QTimer
from PySide6.QtGui import QAction, QColor, QIcon, QKeySequence, QPalette, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDockWidget,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from ..controller import ScrambledEggsController
from .file_encryption_dialog import FileEncryptionDialog
from .key_management_dialog import KeyManagementDialog
from .login_dialog import LoginDialog
from .settings_dialog import SettingsDialog
from .status_bar import StatusBar

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main application window for Scrambled Eggs."""

    def __init__(self, app: QApplication):
        """Initialize the main window."""
        super().__init__()
        self.app = app
        self.settings = QSettings("ScrambledEggs", "ScrambledEggs")

        # Initialize controller
        self.controller = ScrambledEggsController()
        if not self.controller.initialize():
            QMessageBox.critical(
                self,
                "Initialization Error",
                "Failed to initialize encryption engine. Please check the logs.",
            )
            sys.exit(1)

        self.current_user: Optional[Dict[str, Any]] = None

        # UI state
        self.recent_files = []
        self.max_recent_files = 10

        # Initialize UI
        self.init_ui()

        # Load settings
        self.load_settings()

        # Show login dialog if not already authenticated
        self.show_login_dialog()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Scrambled Eggs")
        self.setMinimumSize(800, 600)

        # Initialize preferences dialog as None, will be created when needed
        self._prefs_dialog = None

        # Set application icon
        self.setWindowIcon(self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon))

        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create menu bar
        self.create_menu_bar()

        # Create toolbar
        self.create_toolbar()

        # Create main content area
        self.create_main_content()

        # Create status bar
        self.status_bar = StatusBar()
        self.setStatusBar(self.status_bar)

        # Update UI based on authentication state
        self.update_ui_for_authentication()

    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        self.new_action = QAction("&New...", self)
        self.new_action.setShortcut(QKeySequence.StandardKey.New)
        self.new_action.triggered.connect(self.new_file)
        file_menu.addAction(self.new_action)

        # Add Preferences to the menu (typically under File or a dedicated menu)
        self.prefs_action = QAction("Prefere&nces...", self)
        self.prefs_action.setMenuRole(QAction.PreferencesRole)  # Standard role on macOS
        self.prefs_action.triggered.connect(self.show_preferences)
        file_menu.addSeparator()
        file_menu.addAction(self.prefs_action)

        self.open_action = QAction("&Open...", self)
        self.open_action.setShortcut(QKeySequence.StandardKey.Open)
        self.open_action.triggered.connect(self.open_file)
        file_menu.addAction(self.open_action)

        self.save_action = QAction("&Save", self)
        self.save_action.setShortcut(QKeySequence.StandardKey.Save)
        self.save_action.triggered.connect(self.save_file)
        file_menu.addAction(self.save_action)

        self.save_as_action = QAction("Save &As...", self)
        self.save_as_action.setShortcut(QKeySequence.StandardKey.SaveAs)
        self.save_as_action.triggered.connect(self.save_file_as)
        file_menu.addAction(self.save_as_action)

        file_menu.addSeparator()

        # Recent files submenu
        self.recent_menu = file_menu.addMenu("Recent Files")
        self.recent_menu.aboutToShow.connect(self.update_recent_files_menu)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("&Edit")

        self.undo_action = QAction("&Undo", self)
        self.undo_action.setShortcut(QKeySequence.StandardKey.Undo)
        self.undo_action.triggered.connect(self.undo)
        edit_menu.addAction(self.undo_action)

        self.redo_action = QAction("&Redo", self)
        self.redo_action.setShortcut(QKeySequence.StandardKey.Redo)
        self.redo_action.triggered.connect(self.redo)
        edit_menu.addAction(self.redo_action)

        edit_menu.addSeparator()

        self.cut_action = QAction("Cu&t", self)
        self.cut_action.setShortcut(QKeySequence.StandardKey.Cut)
        self.cut_action.triggered.connect(self.cut)
        edit_menu.addAction(self.cut_action)

        self.copy_action = QAction("&Copy", self)
        self.copy_action.setShortcut(QKeySequence.StandardKey.Copy)
        self.copy_action.triggered.connect(self.copy)
        edit_menu.addAction(self.copy_action)

        self.paste_action = QAction("&Paste", self)
        self.paste_action.setShortcut(QKeySequence.StandardKey.Paste)
        self.paste_action.triggered.connect(self.paste)
        edit_menu.addAction(self.paste_action)

        # Security menu
        security_menu = menubar.addMenu("&Security")

        self.encrypt_file_action = QAction("&Encrypt File...", self)
        self.encrypt_file_action.triggered.connect(self.encrypt_file)
        security_menu.addAction(self.encrypt_file_action)

        self.decrypt_file_action = QAction("&Decrypt File...", self)
        self.decrypt_file_action.triggered.connect(self.decrypt_file)
        security_menu.addAction(self.decrypt_file_action)

        security_menu.addSeparator()

        self.manage_keys_action = QAction("&Manage Keys...", self)
        self.manage_keys_action.triggered.connect(self.manage_keys)
        security_menu.addAction(self.manage_keys_action)

        self.change_password_action = QAction("Change &Password...", self)
        self.change_password_action.triggered.connect(self.change_password)
        security_menu.addAction(self.change_password_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        self.toolbar_toggle = view_menu.addAction("&Toolbar")
        self.toolbar_toggle.setCheckable(True)
        self.toolbar_toggle.setChecked(True)
        self.toolbar_toggle.triggered.connect(self.toggle_toolbar)

        self.statusbar_toggle = view_menu.addAction("Status &Bar")
        self.statusbar_toggle.setCheckable(True)
        self.statusbar_toggle.setChecked(True)
        self.statusbar_toggle.triggered.connect(self.toggle_statusbar)

        # Settings menu
        settings_menu = menubar.addMenu("&Settings")

        preferences_action = QAction("&Preferences...", self)
        preferences_action.triggered.connect(self.show_preferences)
        settings_menu.addAction(preferences_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

        about_qt_action = QAction("About &Qt", self)
        about_qt_action.triggered.connect(QApplication.aboutQt)
        help_menu.addAction(about_qt_action)

    def create_toolbar(self):
        """Create the toolbar."""
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setMovable(False)
        self.addToolBar(self.toolbar)

        # Add actions to toolbar
        self.toolbar.addAction(self.new_action)
        self.toolbar.addAction(self.open_action)
        self.toolbar.addAction(self.save_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.cut_action)
        self.toolbar.addAction(self.copy_action)
        self.toolbar.addAction(self.paste_action)
        self.toolbar.addSeparator()
        self.toolbar.addAction(self.encrypt_file_action)
        self.toolbar.addAction(self.decrypt_file_action)
        self.toolbar.addSeparator()

        # Add download installer button
        self.download_installer_action = QAction(
            QIcon.fromTheme("system-software-install"), "Download Installer", self
        )
        self.download_installer_action.triggered.connect(self.download_installer)
        self.toolbar.addAction(self.download_installer_action)

    def create_main_content(self):
        """Create the main content area."""
        # Create a tab widget for the main area
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)

        # Add a welcome tab
        welcome_widget = QWidget()
        welcome_layout = QVBoxLayout(welcome_widget)

        # Add a welcome message
        welcome_label = QLabel("<h1>Welcome to Scrambled Eggs</h1>")
        welcome_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        welcome_layout.addWidget(welcome_label)

        # Add some quick actions
        quick_actions = QHBoxLayout()

        new_file_btn = QPushButton("New File")
        new_file_btn.clicked.connect(self.new_file)
        quick_actions.addWidget(new_file_btn)

        open_file_btn = QPushButton("Open File")
        open_file_btn.clicked.connect(self.open_file)
        quick_actions.addWidget(open_file_btn)

        encrypt_btn = QPushButton("Encrypt File")
        encrypt_btn.clicked.connect(self.encrypt_file)
        quick_actions.addWidget(encrypt_btn)

        welcome_layout.addLayout(quick_actions)
        welcome_layout.addStretch()

        # Add the welcome tab
        self.tab_widget.addTab(welcome_widget, "Welcome")

        # Set the tab widget as the central widget
        self.setCentralWidget(self.tab_widget)

    def load_settings(self):
        """Load application settings."""
        # Restore window geometry
        if self.settings.contains("window_geometry"):
            self.restoreGeometry(self.settings.value("window_geometry"))

        # Restore window state
        if self.settings.contains("window_state"):
            self.restoreState(self.settings.value("window_state"))

        # Load recent files
        self.recent_files = self.settings.value("recent_files", [])
        if not isinstance(self.recent_files, list):
            self.recent_files = []

    def save_settings(self):
        """Save application settings."""
        # Save window geometry and state
        self.settings.setValue("window_geometry", self.saveGeometry())
        self.settings.setValue("window_state", self.saveState())

        # Save recent files
        self.settings.setValue("recent_files", self.recent_files)

    def closeEvent(self, event):
        """Handle window close event."""
        # Save settings before closing
        self.save_settings()

        # Close all tabs
        while self.tab_widget.count() > 0:
            if not self.maybe_save_tab(0):
                event.ignore()
                return

        # Clean up resources
        self.cleanup()

        # Accept the close event
        event.accept()

    def cleanup(self):
        """Clean up resources."""
        # Clear sensitive data from memory
        if self.encryption_engine:
            self.encryption_engine = None

        # Clear clipboard
        clipboard = QApplication.clipboard()
        clipboard.clear()

    def show_login_dialog(self):
        """Show the login dialog."""
        dialog = LoginDialog(self)
        if dialog.exec() == QDialog.Accepted:
            username = dialog.get_username()
            password = dialog.get_password()

            if self.controller.login(username, password):
                self.current_user = {"username": username, "authenticated": True}
                self.update_ui_for_authentication()
                self.status_bar.show_message(f"Logged in as {username}")
            else:
                QMessageBox.warning(
                    self, "Login Failed", "Invalid username or password. Please try again."
                )
                self.show_login_dialog()  # Show login dialog again
        else:
            # If login was cancelled, close the application
            self.close()

    def show_preferences(self):
        """Show the preferences dialog."""
        if not hasattr(self, "_prefs_dialog") or self._prefs_dialog is None:
            from .preferences_dialog import PreferencesDialog

            self._prefs_dialog = PreferencesDialog(self)

        self._prefs_dialog.show()
        self._prefs_dialog.raise_()
        self._prefs_dialog.activateWindow()

    def apply_preferences(self):
        """Apply preferences from settings."""
        # Apply theme if it has changed
        theme = self.settings.value("ui/theme", "System")
        self.apply_theme(theme)

        # Apply other preferences...

        logger.info("Preferences applied")

    def apply_theme(self, theme_name: str):
        """Apply the selected theme."""
        # This is a simplified example - you would implement your theming logic here
        if theme_name == "Dark":
            self.app.setStyle("Fusion")
            dark_palette = self.app.palette()
            dark_palette.setColor(dark_palette.Window, QColor(53, 53, 53))
            dark_palette.setColor(dark_palette.WindowText, Qt.white)
            dark_palette.setColor(dark_palette.Base, QColor(35, 35, 35))
            dark_palette.setColor(dark_palette.AlternateBase, QColor(53, 53, 53))
            dark_palette.setColor(dark_palette.ToolTipBase, QColor(255, 255, 255))
            dark_palette.setColor(dark_palette.ToolTipText, Qt.white)
            dark_palette.setColor(dark_palette.Text, Qt.white)
            dark_palette.setColor(dark_palette.Button, QColor(53, 53, 53))
            dark_palette.setColor(dark_palette.ButtonText, Qt.white)
            dark_palette.setColor(dark_palette.BrightText, Qt.red)
            dark_palette.setColor(dark_palette.Link, QColor(42, 130, 218))
            dark_palette.setColor(dark_palette.Highlight, QColor(42, 130, 218))
            dark_palette.setColor(dark_palette.HighlightedText, Qt.black)
            self.app.setPalette(dark_palette)
        elif theme_name == "Light":
            self.app.setStyle("Fusion")
            self.app.setPalette(self.app.style().standardPalette())
        else:  # System
            self.app.setStyle("")
            self.app.setPalette(self.app.style().standardPalette())

    def update_ui_for_authentication(self):
        """Update the UI based on authentication state."""
        is_authenticated = self.current_user is not None

        # Enable/disable actions based on authentication
        self.new_action.setEnabled(is_authenticated)
        self.decrypt_file_action.setEnabled(is_authenticated)
        self.manage_keys_action.setEnabled(is_authenticated)
        self.change_password_action.setEnabled(is_authenticated)

        # Update status bar
        self.update_status_bar()

    def update_status_bar(self):
        """Update the status bar with system status."""
        if not hasattr(self, "controller"):
            return

        status = self.controller.get_system_status()
        status_text = f"User: {status['username'] or 'Not logged in'} | "
        status_text += f"Keys: {status['key_count']} | "
        status_text += "HSM: " + ("Connected" if status["hsm_connected"] else "Disconnected")

        self.status_bar.showMessage(status_text)

    def update_recent_files_menu(self):
        """Update the recent files menu."""
        self.recent_menu.clear()

        if not self.recent_files:
            self.recent_menu.addAction("No recent files").setEnabled(False)
            return

        for i, file_path in enumerate(self.recent_files[: self.max_recent_files]):
            action = self.recent_menu.addAction(
                f"&{i + 1} {os.path.basename(file_path)}",
                lambda checked=False, path=file_path: self.open_recent_file(path),
            )
            action.setData(file_path)
            action.setStatusTip(file_path)

        self.recent_menu.addSeparator()
        self.recent_menu.addAction("Clear Recent Files", self.clear_recent_files)

    def add_recent_file(self, file_path):
        """Add a file to the recent files list."""
        if file_path in self.recent_files:
            self.recent_files.remove(file_path)

        self.recent_files.insert(0, file_path)

        # Trim the list if it's too long
        if len(self.recent_files) > self.max_recent_files:
            self.recent_files = self.recent_files[: self.max_recent_files]

        # Save the updated list
        self.settings.setValue("recent_files", self.recent_files)

    def clear_recent_files(self):
        """Clear the recent files list."""
        self.recent_files = []
        self.settings.setValue("recent_files", self.recent_files)

    def open_recent_file(self, file_path):
        """Open a file from the recent files list."""
        if not os.path.exists(file_path):
            QMessageBox.warning(
                self, "File Not Found", f"The file '{file_path}' could not be found."
            )
            self.recent_files.remove(file_path)
            self.settings.setValue("recent_files", self.recent_files)
            return

        self.open_file(file_path)

    def new_file(self):
        """Create a new file."""
        # Create a new tab with an editor
        editor = QPlainTextEdit()
        editor.setStyleSheet(
            """
            QPlainTextEdit {
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.5;
                color: #333;
                background-color: #fff;
                border: none;
                padding: 10px;
            }
        """
        )

        # Add the editor to a new tab
        tab_index = self.tab_widget.addTab(editor, "Untitled")
        self.tab_widget.setCurrentIndex(tab_index)

        # Set focus to the new editor
        editor.setFocus()

        # Add close button to the tab
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)

    def encrypt_file(self):
        """Encrypt a file using the controller."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Encrypt", "", "All Files (*)"
        )

        if file_path:
            success, message = self.controller.encrypt_file(file_path)
            if success:
                self.status_bar.showMessage(f"File encrypted: {message}")
                self.add_recent_file(message)
                QMessageBox.information(
                    self,
                    "Encryption Complete",
                    f"File encrypted successfully.\nSaved as: {message}",
                )
            else:
                QMessageBox.critical(
                    self, "Encryption Failed", f"Failed to encrypt file: {message}"
                )

    def decrypt_file(self):
        """Decrypt a file using the controller."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Decrypt", "", "Encrypted Files (*.enc);;All Files (*)"
        )

        if file_path:
            success, message = self.controller.decrypt_file(file_path)
            if success:
                self.status_bar.showMessage(f"File decrypted: {message}")
                self.add_recent_file(message)
                QMessageBox.information(
                    self,
                    "Decryption Complete",
                    f"File decrypted successfully.\nSaved as: {message}",
                )
            else:
                QMessageBox.critical(
                    self, "Decryption Failed", f"Failed to decrypt file: {message}"
                )

    def manage_keys(self):
        """Open the key management dialog."""
        dialog = KeyManagementDialog(self)
        dialog.exec()

    def change_password(self):
        """Change the current user's password."""
        from PySide6.QtWidgets import QInputDialog

        new_password, ok = QInputDialog.getText(
            self, "Change Password", "Enter new password:", QInputDialog.DialogCode.Accepted, ""
        )

        if ok and new_password:
            # In a real implementation, this would update the password
            QMessageBox.information(
                self, "Password Changed", "Your password has been changed successfully."
            )

    def toggle_toolbar(self, visible):
        """Show or hide the toolbar."""
        self.toolbar.setVisible(visible)

    def toggle_statusbar(self, visible):
        """Show or hide the status bar."""
        self.statusBar().setVisible(visible)
        self.statusbar_toggle.setChecked(visible)

    def download_installer(self):
        """Download the installer to the user's desktop."""
        try:
            # Get the desktop path
            import os
            from pathlib import Path

            desktop = str(Path.home() / "Desktop")

            # Define the installer filename and path
            installer_name = "ScrambledEggs-Installer.exe"
            installer_path = os.path.join(desktop, installer_name)

            # In a real application, you would download the installer from a server
            # For now, we'll just create a placeholder file
            with open(installer_path, "wb") as f:
                f.write(b"This is a placeholder for the Scrambled Eggs installer.")

            # Show success message
            from PySide6.QtWidgets import QMessageBox

            QMessageBox.information(
                self,
                "Download Complete",
                f"Installer has been downloaded to your desktop.\n\n{installer_path}",
                QMessageBox.StandardButton.Ok,
            )

            self.statusBar().showMessage("Installer downloaded successfully", 5000)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Download Failed",
                f"Failed to download installer: {str(e)}",
                QMessageBox.StandardButton.Ok,
            )
            self.statusBar().showMessage("Failed to download installer", 5000)

    def show_about(self):
        """Show the about dialog."""
        from PySide6.QtWidgets import QMessageBox

        about_text = """
        <h1>Scrambled Eggs</h1>
        <p>Version 1.0.0</p>
        <p>A secure file encryption tool with advanced features.</p>
        <p>&copy; 2023 Scrambled Eggs Team. All rights reserved.</p>
        """
        QMessageBox.about(self, "About Scrambled Eggs", about_text)


if __name__ == "__main__":
    import sys

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler("scrambled_eggs.log")],
    )

    # Create and run the application
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    # Create and show the main window
    window = MainWindow(app)
    window.show()

    # Run the application
    sys.exit(app.exec())
