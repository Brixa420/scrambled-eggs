"""
Settings Dialog for Scrambled Eggs
---------------------------------
Provides a dialog for application settings and preferences.
"""

import logging
import os
import platform
from pathlib import Path

from PySide6.QtCore import QSettings, QSize, QStandardPaths, Qt
from PySide6.QtGui import QColor, QDoubleValidator, QFont, QIcon, QIntValidator, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class SettingsDialog(QDialog):
    """A dialog for application settings and preferences."""

    def __init__(self, parent=None):
        """Initialize the settings dialog."""
        super().__init__(parent)
        self.setWindowTitle("Settings - Scrambled Eggs")
        self.setMinimumSize(800, 600)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # Initialize settings
        self.settings = QSettings("ScrambledEggs", "ScrambledEggs")

        # Initialize UI
        self.init_ui()

        # Load settings
        self.load_settings()

    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Create sidebar
        self.create_sidebar()
        main_layout.addWidget(self.sidebar, 0)  # 0 = fixed width

        # Create line separator
        line = QFrame()
        line.setFrameShape(QFrame.Shape.VLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        main_layout.addWidget(line, 0)  # 0 = fixed width

        # Create stacked widget for settings pages
        self.stacked_widget = QStackedWidget()

        # Create settings pages
        self.create_general_page()
        self.create_security_page()
        self.create_network_page()
        self.create_appearance_page()
        self.create_shortcuts_page()
        self.create_about_page()

        # Add pages to stacked widget
        self.stacked_widget.addWidget(self.general_page)
        self.stacked_widget.addWidget(self.security_page)
        self.stacked_widget.addWidget(self.network_page)
        self.stacked_widget.addWidget(self.appearance_page)
        self.stacked_widget.addWidget(self.shortcuts_page)
        self.stacked_widget.addWidget(self.about_page)

        # Add stacked widget to main layout
        main_layout.addWidget(self.stacked_widget, 1)  # 1 = stretch

        # Add button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Apply
            | QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.RestoreDefaults
            | QDialogButtonBox.StandardButton.Help
        )

        # Connect buttons
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        apply_button = button_box.button(QDialogButtonBox.StandardButton.Apply)
        apply_button.clicked.connect(self.apply_settings)

        defaults_button = button_box.button(QDialogButtonBox.StandardButton.RestoreDefaults)
        defaults_button.clicked.connect(self.restore_defaults)

        help_button = button_box.button(QDialogButtonBox.StandardButton.Help)
        help_button.clicked.connect(self.show_help)

        # Add button box to main layout
        main_layout.addWidget(button_box, 0, Qt.AlignmentFlag.AlignBottom)

    def create_sidebar(self):
        """Create the sidebar navigation."""
        self.sidebar = QListWidget()
        self.sidebar.setFixedWidth(180)
        self.sidebar.setIconSize(QSize(24, 24))
        self.sidebar.setMovement(QListView.Movement.Static)
        self.sidebar.setCurrentRow(0)
        self.sidebar.setSpacing(2)

        # Add sidebar items
        sidebar_items = [
            ("General", "SP_ComputerIcon"),
            ("Security", "SP_MessageBoxShield"),
            ("Network", "SP_ComputerIcon"),
            ("Appearance", "SP_DesktopIcon"),
            ("Shortcuts", "SP_FileDialogDetailedView"),
            ("About", "SP_MessageBoxInformation"),
        ]

        for i, (text, icon_name) in enumerate(sidebar_items):
            item = QListWidgetItem(text)
            item.setIcon(self.style().standardIcon(getattr(self.style().StandardPixmap, icon_name)))
            item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
            item.setFlags(Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
            self.sidebar.addItem(item)

        # Connect signal
        self.sidebar.currentRowChanged.connect(self.stacked_widget.setCurrentIndex)

    def create_general_page(self):
        """Create the General settings page."""
        self.general_page = QWidget()
        layout = QVBoxLayout(self.general_page)

        # Application settings group
        app_group = QGroupBox("Application Settings")
        app_layout = QFormLayout()

        # Language
        self.language_combo = QComboBox()
        self.language_combo.addItems(["English", "Spanish", "French", "German", "Chinese"])
        app_layout.addRow("Language:", self.language_combo)

        # Theme
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System", "Light", "Dark", "High Contrast"])
        app_layout.addRow("Theme:", self.theme_combo)

        # Check for updates
        self.updates_check = QCheckBox("Automatically check for updates")
        self.updates_check.setChecked(True)
        app_layout.addRow("", self.updates_check)

        # Beta updates
        self.beta_check = QCheckBox("Include beta/pre-release versions")
        app_layout.addRow("", self.beta_check)

        app_group.setLayout(app_layout)

        # File handling group
        file_group = QGroupBox("File Handling")
        file_layout = QFormLayout()

        # Default save location
        self.save_location_edit = QLineEdit()
        self.save_location_btn = QPushButton("Browse...")
        self.save_location_btn.clicked.connect(self.browse_save_location)

        location_layout = QHBoxLayout()
        location_layout.addWidget(self.save_location_edit)
        location_layout.addWidget(self.save_location_btn)

        file_layout.addRow("Default save location:", location_layout)

        # File history
        self.file_history_spin = QSpinBox()
        self.file_history_spin.setRange(0, 100)
        self.file_history_spin.setSuffix(" items")
        file_layout.addRow("File history size:", self.file_history_spin)

        # Auto-save
        self.autosave_check = QCheckBox("Auto-save changes")
        self.autosave_check.setChecked(True)
        file_layout.addRow("", self.autosave_check)

        # Auto-save interval
        self.autosave_spin = QSpinBox()
        self.autosave_spin.setRange(1, 60)
        self.autosave_spin.setSuffix(" minutes")
        self.autosave_spin.setValue(5)
        file_layout.addRow("Auto-save interval:", self.autosave_spin)

        file_group.setLayout(file_layout)

        # Add groups to layout
        layout.addWidget(app_group)
        layout.addWidget(file_group)
        layout.addStretch()

    def create_security_page(self):
        """Create the Security settings page."""
        self.security_page = QWidget()
        layout = QVBoxLayout(self.security_page)

        # Encryption settings group
        enc_group = QGroupBox("Message Encryption")
        enc_layout = QFormLayout()

        # End-to-end encryption toggle
        self.encryption_check = QCheckBox("Enable end-to-end encryption")
        self.encryption_check.setChecked(True)
        self.encryption_check.setToolTip("Encrypt messages before sending for added security")
        enc_layout.addRow("", self.encryption_check)

        # Encryption status
        self.encryption_status = QLabel("🔒 Encryption is enabled and secure")
        self.encryption_status.setStyleSheet("color: #4CAF50; padding: 5px;")
        enc_layout.addRow("Status:", self.encryption_status)

        # Algorithm selection
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(
            ["AES-256-GCM (Recommended)", "AES-256-CBC with HMAC-SHA256", "ChaCha20-Poly1305"]
        )
        self.algorithm_combo.setToolTip(
            "AES-256-GCM is recommended for most use cases as it provides both encryption and "
            "authentication. ChaCha20-Poly1305 is a good alternative for better performance on mobile devices."
        )
        enc_layout.addRow("Encryption Algorithm:", self.algorithm_combo)

        # Key management
        key_layout = QHBoxLayout()
        self.export_key_btn = QPushButton("Export Public Key")
        self.import_key_btn = QPushButton("Import Contact's Key")
        key_layout.addWidget(self.export_key_btn)
        key_layout.addWidget(self.import_key_btn)
        enc_layout.addRow("Key Management:", key_layout)

        enc_group.setLayout(enc_layout)

        # Password settings group
        pass_group = QGroupBox("Application Security")
        pass_layout = QFormLayout()

        # Auto-lock
        self.autolock_check = QCheckBox("Auto-lock application after period of inactivity")
        self.autolock_check.setChecked(True)
        pass_layout.addRow("", self.autolock_check)

        # Auto-lock timeout
        self.autolock_spin = QSpinBox()
        self.autolock_spin.setRange(1, 60)
        self.autolock_spin.setSuffix(" minutes")
        self.autolock_spin.setValue(15)
        pass_layout.addRow("Lock after:", self.autolock_spin)

        # Password strength
        self.strength_combo = QComboBox()
        self.strength_combo.addItems(
            ["Low (faster)", "Medium", "High (slower)", "Paranoid (slowest)"]
        )
        pass_layout.addRow("Password strength:", self.strength_combo)

        # Clear clipboard
        self.clipboard_check = QCheckBox("Clear clipboard after copying sensitive data")
        self.clipboard_check.setChecked(True)
        pass_layout.addRow("", self.clipboard_check)

        # Clipboard timeout
        self.clipboard_spin = QSpinBox()
        self.clipboard_spin.setRange(5, 300)
        self.clipboard_spin.setSuffix(" seconds")
        self.clipboard_spin.setValue(30)
        pass_layout.addRow("Clear clipboard after:", self.clipboard_spin)

        pass_group.setLayout(pass_layout)

        # Privacy settings group
        privacy_group = QGroupBox("Privacy Settings")
        privacy_layout = QFormLayout()

        # Analytics
        self.analytics_check = QCheckBox("Send anonymous usage statistics")
        self.analytics_check.setChecked(True)
        privacy_layout.addRow("", self.analytics_check)

        # Crash reporting
        self.crash_check = QCheckBox("Automatically send crash reports")
        self.crash_check.setChecked(True)
        privacy_layout.addRow("", self.crash_check)

        # Message history
        self.history_check = QCheckBox("Save message history locally")
        self.history_check.setChecked(True)
        privacy_layout.addRow("", self.history_check)

        privacy_group.setLayout(privacy_layout)

        # Add groups to layout
        layout.addWidget(enc_group)
        layout.addWidget(pass_group)
        layout.addWidget(privacy_group)
        layout.addStretch()

        # Connect signals
        self.encryption_check.toggled.connect(self.update_encryption_ui)
        self.export_key_btn.clicked.connect(self.export_public_key)
        self.import_key_btn.clicked.connect(self.import_contact_key)

        # Initial UI update
        self.update_encryption_ui()

    def update_encryption_ui(self):
        """Update the encryption UI based on current settings."""
        enabled = self.encryption_check.isChecked()
        if enabled:
            self.encryption_status.setText("🔒 Encryption is enabled and secure")
            self.encryption_status.setStyleSheet("color: #4CAF50; padding: 5px;")
        else:
            self.encryption_status.setText(
                "⚠️ Encryption is disabled - messages will be sent in plain text"
            )
            self.encryption_status.setStyleSheet("color: #f44336; padding: 5px;")

        # Enable/disable algorithm selection based on encryption state
        self.algorithm_combo.setEnabled(enabled)
        self.export_key_btn.setEnabled(enabled)
        self.import_key_btn.setEnabled(enabled)

    def export_public_key(self):
        """Export the public key to a file."""
        # This would be implemented to export the public key
        QMessageBox.information(
            self,
            "Export Public Key",
            "Public key export functionality will be implemented here.",
            QMessageBox.StandardButton.Ok,
        )

    def import_contact_key(self):
        """Import a contact's public key from a file."""
        # This would be implemented to import a contact's public key
        QMessageBox.information(
            self,
            "Import Contact's Key",
            "Key import functionality will be implemented here.",
            QMessageBox.StandardButton.Ok,
        )

        # Key derivation settings group
        kdf_group = QGroupBox("Key Derivation Settings")
        kdf_layout = QFormLayout()

        # Key derivation function
        self.kdf_combo = QComboBox()
        self.kdf_combo.addItems(["Argon2id (Recommended)", "Scrypt", "PBKDF2-HMAC-SHA256"])
        self.kdf_combo.setToolTip(
            "Argon2id is the winner of the Password Hashing Competition and is recommended. "
            "Scrypt is also secure but older. PBKDF2 is included for compatibility but is not "
            "recommended for new systems."
        )
        kdf_layout.addRow("Key Derivation Function:", self.kdf_combo)

        # Work factor (iterations)
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(10000, 10000000)
        self.iterations_spin.setValue(600000)
        self.iterations_spin.setSuffix(" iterations")
        self.iterations_spin.setToolTip(
            "Higher values make brute force attacks more difficult but increase the time to derive keys. "
            "Recommended: 600,000+ for PBKDF2, 3+ for Argon2/Scrypt"
        )
        kdf_layout.addRow("Work Factor:", self.iterations_spin)

        # Memory cost (for Argon2/Scrypt)
        self.memory_spin = QSpinBox()
        self.memory_spin.setRange(16, 2048)
        self.memory_spin.setValue(256)
        self.memory_spin.setSuffix(" MB")
        self.memory_spin.setToolTip(
            "Amount of memory to use for key derivation. Higher values increase security by making "
            "parallel attacks more difficult. Recommended: 128MB-1GB"
        )
        kdf_layout.addRow("Memory Cost:", self.memory_spin)

        # Parallelism
        self.parallelism_spin = QSpinBox()
        self.parallelism_spin.setRange(1, 32)
        self.parallelism_spin.setValue(4)
        self.parallelism_spin.setSuffix(" threads")
        self.parallelism_spin.setToolTip(
            "Number of parallel threads to use for key derivation. Should be set to the number of CPU cores."
        )
        kdf_layout.addRow("Parallelism:", self.parallelism_spin)

        # KDF info label
        kdf_info = QLabel(
            "<small>Key derivation functions make brute force attacks more difficult by requiring "
            "significant computational resources. The recommended settings provide a good balance "
            "between security and performance on modern hardware.</small>"
        )
        kdf_info.setWordWrap(True)
        kdf_layout.addRow("", kdf_info)

        kdf_group.setLayout(kdf_layout)
        enc_layout.addRow(kdf_group)

        enc_group.setLayout(enc_layout)

        # Key management group
        key_group = QGroupBox("Key Management")
        key_layout = QVBoxLayout()

        # Key list
        self.key_table = QTableWidget()
        self.key_table.setColumnCount(4)
        self.key_table.setHorizontalHeaderLabels(["Name", "Type", "Created", "Status"])
        self.key_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.key_table.verticalHeader().setVisible(False)
        self.key_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.key_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        # Add some sample data
        self.key_table.setRowCount(3)
        self.key_table.setItem(0, 0, QTableWidgetItem("Personal Key"))
        self.key_table.setItem(0, 1, QTableWidgetItem("AES-256"))
        self.key_table.setItem(0, 2, QTableWidgetItem("2023-01-15"))
        self.key_table.setItem(0, 3, QTableWidgetItem("Active"))

        self.key_table.setItem(1, 0, QTableWidgetItem("Work Key"))
        self.key_table.setItem(1, 1, QTableWidgetItem("RSA-4096"))
        self.key_table.setItem(1, 2, QTableWidgetItem("2023-02-20"))
        self.key_table.setItem(1, 3, QTableWidgetItem("Active"))

        self.key_table.setItem(2, 0, QTableWidgetItem("Backup Key"))
        self.key_table.setItem(2, 1, QTableWidgetItem("ECC-384"))
        self.key_table.setItem(2, 2, QTableWidgetItem("2023-03-10"))
        self.key_table.setItem(2, 3, QTableWidgetItem("Inactive"))

        # Buttons
        btn_layout = QHBoxLayout()

        self.new_key_btn = QPushButton("New Key")
        self.import_key_btn = QPushButton("Import")
        self.export_key_btn = QPushButton("Export")
        self.delete_key_btn = QPushButton("Delete")

        btn_layout.addWidget(self.new_key_btn)
        btn_layout.addWidget(self.import_key_btn)
        btn_layout.addWidget(self.export_key_btn)
        btn_layout.addWidget(self.delete_key_btn)

        key_layout.addWidget(self.key_table)
        key_layout.addLayout(btn_layout)
        key_group.setLayout(key_layout)

        # Add groups to layout
        layout.addWidget(enc_group)
        layout.addWidget(key_group)
        layout.addStretch()

    def create_network_page(self):
        """Create the Network settings page."""
        self.network_page = QWidget()
        layout = QVBoxLayout(self.network_page)

        # Proxy settings group
        proxy_group = QGroupBox("Proxy Settings")
        proxy_layout = QFormLayout()

        # Proxy type
        self.proxy_combo = QComboBox()
        self.proxy_combo.addItems(["No Proxy", "System Proxy", "Manual Configuration"])
        proxy_layout.addRow("Proxy:", self.proxy_combo)

        # Proxy host
        self.proxy_host_edit = QLineEdit()
        self.proxy_host_edit.setPlaceholderText("proxy.example.com")
        proxy_layout.addRow("Host:", self.proxy_host_edit)

        # Proxy port
        self.proxy_port_edit = QLineEdit()
        self.proxy_port_edit.setPlaceholderText("8080")
        self.proxy_port_edit.setValidator(QIntValidator(1, 65535))
        proxy_layout.addRow("Port:", self.proxy_port_edit)

        # Proxy authentication
        self.proxy_auth_check = QCheckBox("Authentication required")
        proxy_layout.addRow("", self.proxy_auth_check)

        # Proxy username
        self.proxy_user_edit = QLineEdit()
        self.proxy_user_edit.setPlaceholderText("username")
        proxy_layout.addRow("Username:", self.proxy_user_edit)

        # Proxy password
        self.proxy_pass_edit = QLineEdit()
        self.proxy_pass_edit.setPlaceholderText("password")
        self.proxy_pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        proxy_layout.addRow("Password:", self.proxy_pass_edit)

        # Test connection button
        self.test_proxy_btn = QPushButton("Test Connection")
        proxy_layout.addRow("", self.test_proxy_btn)

        proxy_group.setLayout(proxy_layout)

        # Connection settings group
        conn_group = QGroupBox("Connection Settings")
        conn_layout = QFormLayout()

        # Timeout
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 300)
        self.timeout_spin.setValue(30)
        self.timeout_spin.setSuffix(" seconds")
        conn_layout.addRow("Connection timeout:", self.timeout_spin)

        # Retries
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(3)
        conn_layout.addRow("Retry attempts:", self.retries_spin)

        conn_group.setLayout(conn_layout)

        # Add groups to layout
        layout.addWidget(proxy_group)
        layout.addWidget(conn_group)
        layout.addStretch()

    def create_appearance_page(self):
        """Create the Appearance settings page."""
        self.appearance_page = QWidget()
        layout = QVBoxLayout(self.appearance_page)

        # Theme settings group
        theme_group = QGroupBox("Theme")
        theme_layout = QFormLayout()

        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System", "Light", "Dark", "High Contrast"])
        theme_layout.addRow("Theme:", self.theme_combo)

        # Accent color
        self.accent_color_btn = QPushButton("Choose Color...")
        self.accent_color_btn.clicked.connect(self.choose_accent_color)
        theme_layout.addRow("Accent color:", self.accent_color_btn)

        # Font
        self.font_btn = QPushButton("Choose Font...")
        self.font_btn.clicked.connect(self.choose_font)
        theme_layout.addRow("Font:", self.font_btn)

        # Font size
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setValue(10)
        self.font_size_spin.setSuffix(" pt")
        theme_layout.addRow("Font size:", self.font_size_spin)

        # Icons
        self.icon_theme_combo = QComboBox()
        self.icon_theme_combo.addItems(["System", "Light", "Dark", "Colorful"])
        theme_layout.addRow("Icon theme:", self.icon_theme_combo)

        theme_group.setLayout(theme_layout)

        # Layout settings group
        layout_group = QGroupBox("Layout")
        layout_layout = QFormLayout()

        # Toolbar style
        self.toolbar_combo = QComboBox()
        self.toolbar_combo.addItems(
            ["Icons Only", "Text Only", "Text Beside Icons", "Text Under Icons"]
        )
        layout_layout.addRow("Toolbar style:", self.toolbar_combo)

        # Status bar
        self.statusbar_check = QCheckBox("Show status bar")
        self.statusbar_check.setChecked(True)
        layout_layout.addRow("", self.statusbar_check)

        # Menu bar
        self.menubar_check = QCheckBox("Show menu bar")
        self.menubar_check.setChecked(True)
        layout_layout.addRow("", self.menubar_check)

        # Tooltips
        self.tooltips_check = QCheckBox("Show tooltips")
        self.tooltips_check.setChecked(True)
        layout_layout.addRow("", self.tooltips_check)

        # Animations
        self.animations_check = QCheckBox("Enable animations")
        self.animations_check.setChecked(True)
        layout_layout.addRow("", self.animations_check)

        layout_group.setLayout(layout_layout)

        # Add groups to layout
        layout.addWidget(theme_group)
        layout.addWidget(layout_group)
        layout.addStretch()

    def create_shortcuts_page(self):
        """Create the Shortcuts settings page."""
        self.shortcuts_page = QWidget()
        layout = QVBoxLayout(self.shortcuts_page)

        # Shortcuts table
        self.shortcuts_table = QTableWidget()
        self.shortcuts_table.setColumnCount(3)
        self.shortcuts_table.setHorizontalHeaderLabels(["Action", "Shortcut", "Description"])
        self.shortcuts_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.shortcuts_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.shortcuts_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.Stretch
        )
        self.shortcuts_table.verticalHeader().setVisible(False)
        self.shortcuts_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.shortcuts_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        # Add sample shortcuts
        shortcuts = [
            ("New File", "Ctrl+N", "Create a new file"),
            ("Open File", "Ctrl+O", "Open an existing file"),
            ("Save", "Ctrl+S", "Save the current file"),
            ("Save As", "Ctrl+Shift+S", "Save the current file with a new name"),
            ("Encrypt", "Ctrl+E", "Encrypt the current file"),
            ("Decrypt", "Ctrl+D", "Decrypt the current file"),
            ("Cut", "Ctrl+X", "Cut the selected text"),
            ("Copy", "Ctrl+C", "Copy the selected text"),
            ("Paste", "Ctrl+V", "Paste text from clipboard"),
            ("Select All", "Ctrl+A", "Select all text"),
            ("Find", "Ctrl+F", "Find text in the current file"),
            ("Replace", "Ctrl+H", "Find and replace text"),
            ("Zoom In", "Ctrl++", "Zoom in the view"),
            ("Zoom Out", "Ctrl+-", "Zoom out the view"),
            ("Reset Zoom", "Ctrl+0", "Reset zoom to default"),
            ("Toggle Fullscreen", "F11", "Toggle fullscreen mode"),
            ("Preferences", "Ctrl+,", "Open settings dialog"),
            ("Help", "F1", "Show help"),
            ("About", "", "Show about dialog"),
        ]

        self.shortcuts_table.setRowCount(len(shortcuts))

        for i, (action, shortcut, desc) in enumerate(shortcuts):
            self.shortcuts_table.setItem(i, 0, QTableWidgetItem(action))
            self.shortcuts_table.setItem(i, 1, QTableWidgetItem(shortcut))
            self.shortcuts_table.setItem(i, 2, QTableWidgetItem(desc))

        # Buttons
        btn_layout = QHBoxLayout()

        self.change_btn = QPushButton("Change Shortcut...")
        self.reset_btn = QPushButton("Reset to Defaults")
        self.import_btn = QPushButton("Import...")
        self.export_btn = QPushButton("Export...")

        btn_layout.addWidget(self.change_btn)
        btn_layout.addWidget(self.reset_btn)
        btn_layout.addStretch()
        btn_layout.addWidget(self.import_btn)
        btn_layout.addWidget(self.export_btn)

        # Add widgets to layout
        layout.addWidget(self.shortcuts_table)
        layout.addLayout(btn_layout)

    def create_about_page(self):
        """Create the About settings page."""
        self.about_page = QWidget()
        layout = QVBoxLayout(self.about_page)

        # Logo and app name
        logo_label = QLabel()
        logo_pixmap = QPixmap(":/icons/app_icon.png").scaled(
            64, 64, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        )
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        app_name = QLabel("Scrambled Eggs")
        app_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = app_name.font()
        font.setPointSize(24)
        font.setBold(True)
        app_name.setFont(font)

        version = QLabel("Version 1.0.0")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Info text
        info_text = """
        <p>A secure file encryption tool with advanced features.</p>
        <p>© 2023 Scrambled Eggs Team. All rights reserved.</p>
        <p>Licensed under the MIT License.</p>
        """
        info_label = QLabel(info_text)
        info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        info_label.setWordWrap(True)

        # Links
        links_layout = QHBoxLayout()
        links_layout.addStretch()

        website_btn = QPushButton("Website")
        docs_btn = QPushButton("Documentation")
        github_btn = QPushButton("GitHub")
        report_btn = QPushButton("Report Issue")

        links_layout.addWidget(website_btn)
        links_layout.addWidget(docs_btn)
        links_layout.addWidget(github_btn)
        links_layout.addWidget(report_btn)
        links_layout.addStretch()

        # System info
        sys_group = QGroupBox("System Information")
        sys_layout = QFormLayout()

        # Get system info
        import platform
        import sys

        from PySide6.QtCore import QSysInfo

        sys_info = [
            (
                "Operating System",
                f"{platform.system()} {platform.release()} ({platform.version()})",
            ),
            ("Python Version", platform.python_version()),
            ("Qt Version", QLibraryInfo.version().toString()),
            ("Architecture", platform.machine()),
            ("CPU Cores", str(os.cpu_count())),
            ("Memory", f"{psutil.virtual_memory().total / (1024**3):.1f} GB"),
            ("Screen Resolution", self.get_screen_resolution()),
            ("DPI", f"{self.logicalDpiX()} x {self.logicalDpiY()}"),
        ]

        for name, value in sys_info:
            label = QLabel(value)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            sys_layout.addRow(f"{name}:", label)

        # Copy button
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_system_info)

        sys_layout.addRow("", copy_btn)
        sys_group.setLayout(sys_layout)

        # Add widgets to layout
        layout.addStretch()
        layout.addWidget(logo_label)
        layout.addWidget(app_name)
        layout.addWidget(version)
        layout.addWidget(info_label)
        layout.addLayout(links_layout)
        layout.addStretch()
        layout.addWidget(sys_group)

    def get_screen_resolution(self):
        """Get the primary screen resolution."""
        screen = self.screen()
        size = screen.size()
        return f"{size.width()} x {size.height()}"

    def copy_system_info(self):
        """Copy system information to clipboard."""
        import platform
        import sys

        from PySide6.QtCore import QLibraryInfo, QSysInfo

        info = []
        info.append("=== System Information ===")
        info.append(f"Application: Scrambled Eggs 1.0.0")
        info.append(
            f"Operating System: {platform.system()} {platform.release()} ({platform.version()})"
        )
        info.append(f"Python Version: {platform.python_version()}")
        info.append(f"Qt Version: {QLibraryInfo.version().toString()}")
        info.append(f"Architecture: {platform.machine()}")
        info.append(f"CPU Cores: {os.cpu_count()}")
        info.append(f"Memory: {psutil.virtual_memory().total / (1024**3):.1f} GB")
        info.append(f"Screen Resolution: {self.get_screen_resolution()}")
        info.append(f"DPI: {self.logicalDpiX()} x {self.logicalDpiY()}")

        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(info))

        self.status_bar.showMessage("System information copied to clipboard", 3000)

    def browse_save_location(self):
        """Open a dialog to choose the default save location."""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Choose Default Save Location", self.save_location_edit.text() or str(Path.home())
        )

        if dir_path:
            self.save_location_edit.setText(dir_path)

    def choose_accent_color(self):
        """Open a color dialog to choose the accent color."""
        color = QColorDialog.getColor()
        if color.isValid():
            # Update the button's color preview
            self.accent_color_btn.setStyleSheet(
                f"background-color: {color.name()}; "
                f"border: 1px solid {color.darker().name()}; "
                "border-radius: 3px; padding: 2px;"
            )

    def choose_font(self):
        """Open a font dialog to choose the application font."""
        font, ok = QFontDialog.getFont()
        if ok:
            self.font_btn.setText(f"{font.family()}, {font.pointSize()}pt")

    def load_settings(self):
        """Load settings from QSettings."""
        # General settings
        self.language_combo.setCurrentText(self.settings.value("general/language", "English"))
        self.theme_combo.setCurrentText(self.settings.value("general/theme", "System"))
        self.updates_check.setChecked(self.settings.value("general/check_updates", True, type=bool))
        self.beta_check.setChecked(self.settings.value("general/beta_updates", False, type=bool))

        # File handling
        default_save = str(Path.home() / "ScrambledEggs")
        self.save_location_edit.setText(self.settings.value("file/save_location", default_save))
        self.file_history_spin.setValue(self.settings.value("file/history_size", 10, type=int))
        self.autosave_check.setChecked(self.settings.value("file/autosave", True, type=bool))
        self.autosave_spin.setValue(self.settings.value("file/autosave_interval", 5, type=int))

        # Security settings
        self.autolock_check.setChecked(self.settings.value("security/autolock", True, type=bool))
        self.autolock_spin.setValue(self.settings.value("security/autolock_timeout", 15, type=int))
        self.strength_combo.setCurrentText(
            self.settings.value("security/password_strength", "High (slower)")
        )
        self.clipboard_check.setChecked(
            self.settings.value("security/clear_clipboard", True, type=bool)
        )
        self.clipboard_spin.setValue(
            self.settings.value("security/clipboard_timeout", 30, type=int)
        )

        # Privacy settings
        self.analytics_check.setChecked(self.settings.value("privacy/analytics", True, type=bool))
        self.crash_check.setChecked(self.settings.value("privacy/crash_reports", True, type=bool))

        # Encryption settings
        self.algorithm_combo.setCurrentText(
            self.settings.value("encryption/algorithm", "AES-256-CBC")
        )
        self.kdf_combo.setCurrentText(self.settings.value("encryption/kdf", "PBKDF2-HMAC-SHA256"))
        self.iterations_spin.setValue(
            self.settings.value("encryption/iterations", 600000, type=int)
        )
        self.memory_spin.setValue(self.settings.value("encryption/memory", 64, type=int))
        self.parallelism_spin.setValue(self.settings.value("encryption/parallelism", 4, type=int))

        # Network settings
        self.proxy_combo.setCurrentText(self.settings.value("network/proxy_type", "No Proxy"))
        self.proxy_host_edit.setText(self.settings.value("network/proxy_host", ""))
        self.proxy_port_edit.setText(self.settings.value("network/proxy_port", ""))
        self.proxy_auth_check.setChecked(
            self.settings.value("network/proxy_auth", False, type=bool)
        )
        self.proxy_user_edit.setText(self.settings.value("network/proxy_username", ""))
        self.proxy_pass_edit.setText(self.settings.value("network/proxy_password", ""))
        self.timeout_spin.setValue(self.settings.value("network/timeout", 30, type=int))
        self.retries_spin.setValue(self.settings.value("network/retries", 3, type=int))

        # Appearance settings
        self.theme_combo.setCurrentText(self.settings.value("appearance/theme", "System"))
        self.font_size_spin.setValue(self.settings.value("appearance/font_size", 10, type=int))
        self.icon_theme_combo.setCurrentText(self.settings.value("appearance/icon_theme", "System"))
        self.toolbar_combo.setCurrentText(
            self.settings.value("appearance/toolbar_style", "Text Under Icons")
        )
        self.statusbar_check.setChecked(
            self.settings.value("appearance/show_statusbar", True, type=bool)
        )
        self.menubar_check.setChecked(
            self.settings.value("appearance/show_menubar", True, type=bool)
        )
        self.tooltips_check.setChecked(
            self.settings.value("appearance/show_tooltips", True, type=bool)
        )
        self.animations_check.setChecked(
            self.settings.value("appearance/enable_animations", True, type=bool)
        )

    def save_settings(self):
        """Save settings to QSettings."""
        # General settings
        self.settings.setValue("general/language", self.language_combo.currentText())
        self.settings.setValue("general/theme", self.theme_combo.currentText())
        self.settings.setValue("general/check_updates", self.updates_check.isChecked())
        self.settings.setValue("general/beta_updates", self.beta_check.isChecked())

        # File handling
        self.settings.setValue("file/save_location", self.save_location_edit.text())
        self.settings.setValue("file/history_size", self.file_history_spin.value())
        self.settings.setValue("file/autosave", self.autosave_check.isChecked())
        self.settings.setValue("file/autosave_interval", self.autosave_spin.value())

        # Security settings
        self.settings.setValue("security/autolock", self.autolock_check.isChecked())
        self.settings.setValue("security/autolock_timeout", self.autolock_spin.value())
        self.settings.setValue("security/password_strength", self.strength_combo.currentText())
        self.settings.setValue("security/clear_clipboard", self.clipboard_check.isChecked())
        self.settings.setValue("security/clipboard_timeout", self.clipboard_spin.value())

        # Privacy settings
        self.settings.setValue("privacy/analytics", self.analytics_check.isChecked())
        self.settings.setValue("privacy/crash_reports", self.crash_check.isChecked())

        # Encryption settings
        self.settings.setValue("encryption/algorithm", self.algorithm_combo.currentText())
        self.settings.setValue("encryption/kdf", self.kdf_combo.currentText())
        self.settings.setValue("encryption/iterations", self.iterations_spin.value())
        self.settings.setValue("encryption/memory", self.memory_spin.value())
        self.settings.setValue("encryption/parallelism", self.parallelism_spin.value())

        # Network settings
        self.settings.setValue("network/proxy_type", self.proxy_combo.currentText())
        self.settings.setValue("network/proxy_host", self.proxy_host_edit.text())
        self.settings.setValue("network/proxy_port", self.proxy_port_edit.text())
        self.settings.setValue("network/proxy_auth", self.proxy_auth_check.isChecked())
        self.settings.setValue("network/proxy_username", self.proxy_user_edit.text())
        self.settings.setValue("network/proxy_password", self.proxy_pass_edit.text())
        self.settings.setValue("network/timeout", self.timeout_spin.value())
        self.settings.setValue("network/retries", self.retries_spin.value())

        # Appearance settings
        self.settings.setValue("appearance/theme", self.theme_combo.currentText())
        self.settings.setValue("appearance/font_size", self.font_size_spin.value())
        self.settings.setValue("appearance/icon_theme", self.icon_theme_combo.currentText())
        self.settings.setValue("appearance/toolbar_style", self.toolbar_combo.currentText())
        self.settings.setValue("appearance/show_statusbar", self.statusbar_check.isChecked())
        self.settings.setValue("appearance/show_menubar", self.menubar_check.isChecked())
        self.settings.setValue("appearance/show_tooltips", self.tooltips_check.isChecked())
        self.settings.setValue("appearance/enable_animations", self.animations_check.isChecked())

        # Sync to ensure settings are saved immediately
        self.settings.sync()

        # Show status message
        self.status_bar.showMessage("Settings saved successfully", 3000)

    def restore_defaults(self):
        """Restore default settings."""
        reply = QMessageBox.question(
            self,
            "Restore Defaults",
            "Are you sure you want to restore all settings to their default values?\n\n"
            "This cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            # Clear all settings
            self.settings.clear()

            # Reload settings (which will use defaults)
            self.load_settings()

            # Show status message
            self.status_bar.showMessage("Default settings restored", 3000)

    def show_help(self):
        """Show help documentation."""
        QMessageBox.information(
            self,
            "Help",
            "For help and documentation, please visit:\n\n"
            "https://scrambled-eggs.example.com/help",
        )

    def apply_settings(self):
        """Apply the current settings."""
        self.save_settings()

        # In a real application, you would apply the settings here
        # For example, update the application theme, language, etc.

        # Show status message
        self.status_bar.showMessage("Settings applied", 3000)

    def accept(self):
        """Handle the OK button click."""
        self.save_settings()
        super().accept()

    def reject(self):
        """Handle the Cancel button click."""
        # Check if there are unsaved changes
        # In a real application, you would compare current settings with saved settings
        # For now, we'll just close the dialog
        super().reject()


if __name__ == "__main__":
    import sys

    from PySide6.QtWidgets import QApplication

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Create and run the application
    app = QApplication(sys.argv)

    # Set application style
    app.setStyle("Fusion")

    # Create and show the dialog
    dialog = SettingsDialog()
    dialog.show()

    sys.exit(app.exec())
