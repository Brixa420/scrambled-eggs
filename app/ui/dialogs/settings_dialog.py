"""
Settings dialog for configuring application preferences.
"""
from typing import Dict, Any, Optional

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QTabWidget, QWidget, QComboBox, QSpinBox,
    QCheckBox, QDialogButtonBox, QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtGui import QIcon

from app.core.config import Config
from app.managers.settings_manager import SettingsManager

class SettingsDialog(QDialog):
    """Dialog for configuring application settings."""
    
    settings_saved = Signal(dict)
    
    def __init__(self, settings_manager: SettingsManager, parent=None):
        """Initialize the settings dialog."""
        super().__init__(parent)
        self.settings_manager = settings_manager
        self.current_settings = settings_manager.get_settings()
        
        self.setWindowTitle("Settings")
        self.setMinimumSize(600, 500)
        
        self.setup_ui()
        self.load_settings()
    
    def setup_ui(self):
        """Set up the user interface."""
        main_layout = QVBoxLayout(self)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Add tabs
        self.general_tab = self.create_general_tab()
        self.network_tab = self.create_network_tab()
        self.privacy_tab = self.create_privacy_tab()
        self.about_tab = self.create_about_tab()
        
        self.tab_widget.addTab(self.general_tab, "General")
        self.tab_widget.addTab(self.network_tab, "Network")
        self.tab_widget.addTab(self.privacy_tab, "Privacy & Security")
        self.tab_widget.addTab(self.about_tab, "About")
        
        main_layout.addWidget(self.tab_widget)
        
        # Add dialog buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.Apply
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        apply_btn = button_box.button(QDialogButtonBox.Apply)
        apply_btn.clicked.connect(self.apply_settings)
        
        main_layout.addWidget(button_box)
    
    def create_general_tab(self) -> QWidget:
        """Create the General settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Theme settings
        theme_group = QWidget()
        theme_layout = QVBoxLayout(theme_group)
        theme_layout.setContentsMargins(0, 0, 0, 0)
        
        theme_layout.addWidget(QLabel("<b>Appearance</b>"))
        
        # Theme selection
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Theme:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["System", "Light", "Dark"])
        theme_row.addWidget(self.theme_combo)
        theme_row.addStretch()
        theme_layout.addLayout(theme_row)
        
        # Font size
        font_row = QHBoxLayout()
        font_row.addWidget(QLabel("Font size:"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(8, 24)
        self.font_size_spin.setSuffix(" px")
        font_row.addWidget(self.font_size_spin)
        font_row.addStretch()
        theme_layout.addLayout(font_row)
        
        layout.addWidget(theme_group)
        
        # Startup settings
        startup_group = QWidget()
        startup_layout = QVBoxLayout(startup_group)
        startup_layout.setContentsMargins(0, 0, 0, 0)
        
        startup_layout.addWidget(QLabel("<b>Startup</b>"))
        
        self.start_minimized = QCheckBox("Start minimized")
        self.auto_start = QCheckBox("Start with system")
        
        startup_layout.addWidget(self.start_minimized)
        startup_layout.addWidget(self.auto_start)
        
        layout.addWidget(startup_group)
        layout.addStretch()
        
        return tab
    
    def create_network_tab(self) -> QWidget:
        """Create the Network settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Connection settings
        conn_group = QWidget()
        conn_layout = QVBoxLayout(conn_group)
        conn_layout.setContentsMargins(0, 0, 0, 0)
        
        conn_layout.addWidget(QLabel("<b>Connection Settings</b>"))
        
        # Server address
        server_row = QHBoxLayout()
        server_row.addWidget(QLabel("Server:"))
        self.server_edit = QLineEdit()
        self.server_edit.setPlaceholderText("server.example.com")
        server_row.addWidget(self.server_edit)
        conn_layout.addLayout(server_row)
        
        # Port
        port_row = QHBoxLayout()
        port_row.addWidget(QLabel("Port:"))
        self.port_edit = QLineEdit()
        self.port_edit.setFixedWidth(80)
        self.port_edit.setPlaceholderText("443")
        port_row.addWidget(self.port_edit)
        port_row.addStretch()
        conn_layout.addLayout(port_row)
        
        # Proxy settings
        proxy_row = QHBoxLayout()
        proxy_row.addWidget(QLabel("Use proxy:"))
        self.proxy_check = QCheckBox()
        proxy_row.addWidget(self.proxy_check)
        proxy_row.addStretch()
        conn_layout.addLayout(proxy_row)
        
        self.proxy_url_edit = QLineEdit()
        self.proxy_url_edit.setPlaceholderText("socks5://proxy.example.com:1080")
        conn_layout.addWidget(self.proxy_url_edit)
        
        layout.addWidget(conn_group)
        
        # Bandwidth settings
        bw_group = QWidget()
        bw_layout = QVBoxLayout(bw_group)
        bw_layout.setContentsMargins(0, 0, 0, 0)
        
        bw_layout.addWidget(QLabel("<b>Bandwidth</b>"))
        
        # Upload limit
        ul_row = QHBoxLayout()
        ul_row.addWidget(QLabel("Upload limit (KB/s):"))
        self.ul_limit = QSpinBox()
        self.ul_limit.setRange(0, 100000)
        self.ul_limit.setSpecialValueText("Unlimited")
        ul_row.addWidget(self.ul_limit)
        ul_row.addStretch()
        bw_layout.addLayout(ul_row)
        
        # Download limit
        dl_row = QHBoxLayout()
        dl_row.addWidget(QLabel("Download limit (KB/s):"))
        self.dl_limit = QSpinBox()
        self.dl_limit.setRange(0, 100000)
        self.dl_limit.setSpecialValueText("Unlimited")
        dl_row.addWidget(self.dl_limit)
        dl_row.addStretch()
        bw_layout.addLayout(dl_row)
        
        layout.addWidget(bw_group)
        layout.addStretch()
        
        return tab
    
    def create_privacy_tab(self) -> QWidget:
        """Create the Privacy & Security settings tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Privacy settings
        privacy_group = QWidget()
        privacy_layout = QVBoxLayout(privacy_group)
        privacy_layout.setContentsMargins(0, 0, 0, 0)
        
        privacy_layout.addWidget(QLabel("<b>Privacy</b>"))
        
        self.typing_indicators = QCheckBox("Show typing indicators")
        self.read_receipts = QCheckBox("Send read receipts")
        self.online_status = QCheckBox("Show online status")
        self.last_seen = QCheckBox("Show last seen")
        
        privacy_layout.addWidget(self.typing_indicators)
        privacy_layout.addWidget(self.read_receipts)
        privacy_layout.addWidget(self.online_status)
        privacy_layout.addWidget(self.last_seen)
        
        layout.addWidget(privacy_group)
        
        # Security settings
        security_group = QWidget()
        security_layout = QVBoxLayout(security_group)
        security_layout.setContentsMargins(0, 0, 0, 0)
        
        security_layout.addWidget(QLabel("<b>Security</b>"))
        
        self.auto_lock = QCheckBox("Auto-lock after inactivity")
        self.auto_lock_time = QSpinBox()
        self.auto_lock_time.setRange(1, 60)
        self.auto_lock_time.setSuffix(" minutes")
        
        lock_row = QHBoxLayout()
        lock_row.addWidget(self.auto_lock)
        lock_row.addWidget(self.auto_lock_time)
        lock_row.addStretch()
        
        security_layout.addLayout(lock_row)
        
        # Message encryption
        enc_row = QHBoxLayout()
        enc_row.addWidget(QLabel("Encryption level:"))
        self.encryption_level = QComboBox()
        self.encryption_level.addItems(["Standard", "Enhanced", "Maximum"])
        enc_row.addWidget(self.encryption_level)
        enc_row.addStretch()
        security_layout.addLayout(enc_row)
        
        # Clear data button
        clear_btn = QPushButton("Clear All Data")
        clear_btn.clicked.connect(self.confirm_clear_data)
        security_layout.addWidget(clear_btn)
        
        layout.addWidget(security_group)
        layout.addStretch()
        
        return tab
    
    def create_about_tab(self) -> QWidget:
        """Create the About tab."""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # App info
        app_name = "Scrambled Eggs"
        version = "1.0.0"
        
        title = QLabel(f"<h1>{app_name} {version}</h1>")
        title.setAlignment(Qt.AlignCenter)
        
        desc = QLabel(
            "A secure messaging application with end-to-end encryption."
            "\n\n© 2023 Scrambled Eggs Team"
        )
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        
        # Links
        links = QWidget()
        links_layout = QHBoxLayout(links)
        
        website_btn = QPushButton("Website")
        docs_btn = QPushButton("Documentation")
        report_btn = QPushButton("Report Issue")
        
        links_layout.addWidget(website_btn)
        links_layout.addWidget(docs_btn)
        links_layout.addWidget(report_btn)
        
        # Version info
        version_info = QLabel(
            f"Version: {version}\n"
            "Build: 20230927\n"
            "© 2023 Scrambled Eggs Team. All rights reserved."
        )
        version_info.setAlignment(Qt.AlignCenter)
        version_info.setStyleSheet("color: #666; font-size: 9pt;")
        
        layout.addStretch()
        layout.addWidget(title)
        layout.addWidget(desc)
        layout.addSpacing(20)
        layout.addWidget(links, 0, Qt.AlignCenter)
        layout.addStretch()
        layout.addWidget(version_info)
        
        return tab
    
    def load_settings(self):
        """Load settings into the UI."""
        settings = self.current_settings
        
        # General tab
        self.theme_combo.setCurrentText(settings.get('theme', 'System'))
        self.font_size_spin.setValue(settings.get('font_size', 12))
        self.start_minimized.setChecked(settings.get('start_minimized', False))
        self.auto_start.setChecked(settings.get('auto_start', False))
        
        # Network tab
        self.server_edit.setText(settings.get('server', ''))
        self.port_edit.setText(str(settings.get('port', '443')))
        self.proxy_check.setChecked(settings.get('use_proxy', False))
        self.proxy_url_edit.setText(settings.get('proxy_url', ''))
        self.ul_limit.setValue(settings.get('upload_limit', 0))
        self.dl_limit.setValue(settings.get('download_limit', 0))
        
        # Privacy tab
        self.typing_indicators.setChecked(settings.get('show_typing', True))
        self.read_receipts.setChecked(settings.get('send_read_receipts', True))
        self.online_status.setChecked(settings.get('show_online_status', True))
        self.last_seen.setChecked(settings.get('show_last_seen', True))
        
        # Security tab
        self.auto_lock.setChecked(settings.get('auto_lock_enabled', True))
        self.auto_lock_time.setValue(settings.get('auto_lock_timeout', 5))
        self.encryption_level.setCurrentText(settings.get('encryption_level', 'Standard'))
    
    def get_settings(self) -> Dict[str, Any]:
        """Get settings from the UI."""
        settings = {}
        
        # General tab
        settings['theme'] = self.theme_combo.currentText()
        settings['font_size'] = self.font_size_spin.value()
        settings['start_minimized'] = self.start_minimized.isChecked()
        settings['auto_start'] = self.auto_start.isChecked()
        
        # Network tab
        settings['server'] = self.server_edit.text().strip()
        try:
            settings['port'] = int(self.port_edit.text().strip())
        except ValueError:
            settings['port'] = 443
            
        settings['use_proxy'] = self.proxy_check.isChecked()
        settings['proxy_url'] = self.proxy_url_edit.text().strip()
        settings['upload_limit'] = self.ul_limit.value()
        settings['download_limit'] = self.dl_limit.value()
        
        # Privacy tab
        settings['show_typing'] = self.typing_indicators.isChecked()
        settings['send_read_receipts'] = self.read_receipts.isChecked()
        settings['show_online_status'] = self.online_status.isChecked()
        settings['show_last_seen'] = self.last_seen.isChecked()
        
        # Security tab
        settings['auto_lock_enabled'] = self.auto_lock.isChecked()
        settings['auto_lock_timeout'] = self.auto_lock_time.value()
        settings['encryption_level'] = self.encryption_level.currentText()
        
        return settings
    
    def accept(self):
        """Handle accept (OK) button."""
        if self.apply_settings():
            super().accept()
    
    def apply_settings(self) -> bool:
        """Apply the current settings."""
        try:
            new_settings = self.get_settings()
            self.settings_manager.update_settings(new_settings)
            self.settings_saved.emit(new_settings)
            return True
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to save settings: {str(e)}",
                QMessageBox.Ok
            )
            return False
    
    def confirm_clear_data(self):
        """Show confirmation dialog before clearing all data."""
        reply = QMessageBox.question(
            self,
            "Confirm Clear Data",
            "<b>This will delete all your messages, contacts, and settings.</b><br><br>"
            "This action cannot be undone. Are you sure you want to continue?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # TODO: Implement data clearing logic
                QMessageBox.information(
                    self,
                    "Data Cleared",
                    "All application data has been cleared.",
                    QMessageBox.Ok
                )
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Error",
                    f"Failed to clear data: {str(e)}",
                    QMessageBox.Ok
                )
