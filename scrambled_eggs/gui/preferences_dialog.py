"""
Preferences Dialog for Scrambled Eggs
------------------------------------
Allows users to configure application preferences.
"""
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, 
    QTabWidget, QWidget, QFormLayout, QCheckBox,
    QSpinBox, QComboBox, QLabel, QLineEdit, QFileDialog
)
from PySide6.QtCore import Qt, QSettings

class PreferencesDialog(QDialog):
    """Dialog for configuring application preferences."""
    
    def __init__(self, parent=None):
        """Initialize the preferences dialog."""
        super().__init__(parent)
        self.settings = QSettings("ScrambledEggs", "ScrambledEggs")
        self.init_ui()
        self.load_settings()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Preferences")
        self.setMinimumSize(600, 400)
        
        # Main layout
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tabs = QTabWidget()
        
        # General tab
        general_tab = QWidget()
        general_layout = QFormLayout(general_tab)
        
        # Theme selection
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System", "Light", "Dark"])
        general_layout.addRow("Theme:", self.theme_combo)
        
        # Auto-save
        self.auto_save = QCheckBox("Enable auto-save")
        general_layout.addRow(self.auto_save)
        
        # Auto-save interval
        self.auto_save_interval = QSpinBox()
        self.auto_save_interval.setRange(1, 60)
        self.auto_save_interval.setSuffix(" minutes")
        general_layout.addRow("Auto-save interval:", self.auto_save_interval)
        
        # Add general tab
        self.tabs.addTab(general_tab, "General")
        
        # Security tab
        security_tab = QWidget()
        security_layout = QFormLayout(security_tab)
        
        # Auto-lock
        self.auto_lock = QCheckBox("Enable auto-lock")
        security_layout.addRow(self.auto_lock)
        
        # Auto-lock timeout
        self.auto_lock_timeout = QSpinBox()
        self.auto_lock_timeout.setRange(1, 120)
        self.auto_lock_timeout.setSuffix(" minutes")
        security_layout.addRow("Auto-lock timeout:", self.auto_lock_timeout)
        
        # Clear clipboard
        self.clear_clipboard = QCheckBox("Clear clipboard after copying sensitive data")
        security_layout.addRow(self.clear_clipboard)
        
        # Clear clipboard timeout
        self.clear_clipboard_timeout = QSpinBox()
        self.clear_clipboard_timeout.setRange(1, 300)
        self.clear_clipboard_timeout.setSuffix(" seconds")
        security_layout.addRow("Clear clipboard after:", self.clear_clipboard_timeout)
        
        # Add security tab
        self.tabs.addTab(security_tab, "Security")
        
        # Paths tab
        paths_tab = QWidget()
        paths_layout = QFormLayout(paths_tab)
        
        # Default save location
        self.save_location = QLineEdit()
        self.save_location.setReadOnly(True)
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_save_location)
        
        location_layout = QHBoxLayout()
        location_layout.addWidget(self.save_location)
        location_layout.addWidget(browse_button)
        paths_layout.addRow("Default save location:", location_layout)
        
        # Add paths tab
        self.tabs.addTab(paths_tab, "Paths")
        
        # Add tabs to main layout
        main_layout.addWidget(self.tabs)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.ok_button = QPushButton("OK")
        self.ok_button.clicked.connect(self.accept)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        self.apply_button = QPushButton("Apply")
        self.apply_button.clicked.connect(self.apply_changes)
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.apply_button)
        
        main_layout.addLayout(button_layout)
    
    def browse_save_location(self):
        """Open a dialog to select the default save location."""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Default Save Location",
            self.save_location.text() or ""
        )
        if directory:
            self.save_location.setText(directory)
    
    def load_settings(self):
        """Load settings from QSettings."""
        # General settings
        self.theme_combo.setCurrentText(
            self.settings.value("ui/theme", "System")
        )
        self.auto_save.setChecked(
            self.settings.value("auto_save/enabled", False, type=bool)
        )
        self.auto_save_interval.setValue(
            self.settings.value("auto_save/interval", 5, type=int)
        )
        
        # Security settings
        self.auto_lock.setChecked(
            self.settings.value("security/auto_lock", True, type=bool)
        )
        self.auto_lock_timeout.setValue(
            self.settings.value("security/auto_lock_timeout", 5, type=int)
        )
        self.clear_clipboard.setChecked(
            self.settings.value("security/clear_clipboard", True, type=bool)
        )
        self.clear_clipboard_timeout.setValue(
            self.settings.value("security/clear_clipboard_timeout", 30, type=int)
        )
        
        # Paths
        self.save_location.setText(
            self.settings.value("paths/save_location", "")
        )
    
    def save_settings(self):
        """Save settings to QSettings."""
        # General settings
        self.settings.setValue("ui/theme", self.theme_combo.currentText())
        self.settings.setValue("auto_save/enabled", self.auto_save.isChecked())
        self.settings.setValue("auto_save/interval", self.auto_save_interval.value())
        
        # Security settings
        self.settings.setValue("security/auto_lock", self.auto_lock.isChecked())
        self.settings.setValue("security/auto_lock_timeout", self.auto_lock_timeout.value())
        self.settings.setValue("security/clear_clipboard", self.clear_clipboard.isChecked())
        self.settings.setValue("security/clear_clipboard_timeout", self.clear_clipboard_timeout.value())
        
        # Paths
        self.settings.setValue("paths/save_location", self.save_location.text())
        
        # Notify about changes
        self.settings.sync()
    
    def apply_changes(self):
        """Apply changes without closing the dialog."""
        self.save_settings()
        # Emit signal or call method to apply changes
        if hasattr(self.parent(), 'apply_preferences'):
            self.parent().apply_preferences()
    
    def accept(self):
        """Save settings and close the dialog."""
        self.save_settings()
        super().accept()
        
        # Apply changes after the dialog is closed
        if hasattr(self.parent(), 'apply_preferences'):
            self.parent().apply_preferences()
