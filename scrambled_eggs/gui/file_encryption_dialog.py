"""
File Encryption Dialog for Scrambled Eggs
----------------------------------------
Provides a dialog for file encryption and decryption operations.
"""

import logging
import os
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QThread, Signal
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class FileEncryptionDialog(QDialog):
    """A dialog for file encryption and decryption operations."""

    def __init__(self, parent=None, mode="encrypt"):
        """Initialize the file encryption dialog.

        Args:
            parent: Parent widget
            mode: Operation mode ('encrypt' or 'decrypt')
        """
        super().__init__(parent)
        self.mode = mode.lower()
        self.setWindowTitle("Encrypt File" if self.mode == "encrypt" else "Decrypt File")
        self.setMinimumWidth(500)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        # Store file paths
        self.input_file = ""
        self.output_file = ""

        # Initialize UI
        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        # Create tabs for different encryption options
        self.tab_widget = QTabWidget()

        # Standard encryption tab
        self.standard_tab = QWidget()
        self.init_standard_tab()

        # Advanced encryption tab
        self.advanced_tab = QWidget()
        self.init_advanced_tab()

        # Add tabs to the tab widget
        self.tab_widget.addTab(self.standard_tab, "Standard")
        self.tab_widget.addTab(self.advanced_tab, "Advanced")

        # Add tab widget to main layout
        layout.addWidget(self.tab_widget)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        # Button layout
        button_layout = QHBoxLayout()

        self.action_button = QPushButton("Encrypt" if self.mode == "encrypt" else "Decrypt")
        self.action_button.setDefault(True)
        self.action_button.clicked.connect(self.process_file)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)

        button_layout.addStretch()
        button_layout.addWidget(self.action_button)
        button_layout.addWidget(self.cancel_button)

        layout.addLayout(button_layout)

    def init_standard_tab(self):
        """Initialize the standard encryption tab."""
        layout = QVBoxLayout(self.standard_tab)

        # Input file group
        input_group = QGroupBox("Input File")
        input_layout = QVBoxLayout()

        self.input_path_edit = QLineEdit()
        self.input_path_edit.setPlaceholderText(
            "Select a file to encrypt..."
            if self.mode == "encrypt"
            else "Select a file to decrypt..."
        )
        self.input_path_edit.setReadOnly(True)

        browse_input_btn = QPushButton("Browse...")
        browse_input_btn.clicked.connect(self.browse_input_file)

        input_btn_layout = QHBoxLayout()
        input_btn_layout.addWidget(self.input_path_edit)
        input_btn_layout.addWidget(browse_input_btn)

        input_layout.addLayout(input_btn_layout)
        input_group.setLayout(input_layout)

        # Output file group
        output_group = QGroupBox("Output File")
        output_layout = QVBoxLayout()

        self.output_path_edit = QLineEdit()
        self.output_path_edit.setPlaceholderText("Select output location...")
        self.output_path_edit.textChanged.connect(self.update_output_extension)

        browse_output_btn = QPushButton("Browse...")
        browse_output_btn.clicked.connect(self.browse_output_file)

        output_btn_layout = QHBoxLayout()
        output_btn_layout.addWidget(self.output_path_edit)
        output_btn_layout.addWidget(browse_output_btn)

        output_layout.addLayout(output_btn_layout)

        # Auto-generate output filename
        self.auto_name_check = QCheckBox("Auto-generate output filename")
        self.auto_name_check.setChecked(True)
        self.auto_name_check.toggled.connect(self.toggle_auto_name)

        output_layout.addWidget(self.auto_name_check)
        output_group.setLayout(output_layout)

        # Password group
        password_group = QGroupBox("Security")
        password_layout = QFormLayout()

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Enter a strong password")

        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit.setPlaceholderText("Confirm password")

        # Only show confirm password for encryption
        if self.mode == "encrypt":
            password_layout.addRow("Password:", self.password_edit)
            password_layout.addRow("Confirm:", self.confirm_password_edit)
        else:
            password_layout.addRow("Password:", self.password_edit)

        # Show password checkbox
        self.show_password_check = QCheckBox("Show password")
        self.show_password_check.toggled.connect(self.toggle_password_visibility)
        password_layout.addRow("", self.show_password_check)

        password_group.setLayout(password_layout)

        # Add groups to layout
        layout.addWidget(input_group)
        layout.addWidget(output_group)
        layout.addWidget(password_group)
        layout.addStretch()

    def init_advanced_tab(self):
        """Initialize the advanced encryption tab."""
        layout = QVBoxLayout(self.advanced_tab)

        # Encryption settings group
        settings_group = QGroupBox("Encryption Settings")
        settings_layout = QFormLayout()

        # Algorithm selection
        self.algorithm_combo = QComboBox()
        self.algorithm_combo.addItems(["AES-256-CBC", "AES-256-GCM", "ChaCha20-Poly1305"])
        settings_layout.addRow("Algorithm:", self.algorithm_combo)

        # Key derivation iterations
        self.iterations_spin = QSpinBox()
        self.iterations_spin.setRange(1000, 1000000)
        self.iterations_spin.setValue(600000)
        self.iterations_spin.setSingleStep(10000)
        self.iterations_spin.setSuffix(" iterations")
        settings_layout.addRow("Key Derivation:", self.iterations_spin)

        # Compression
        self.compression_check = QCheckBox("Enable compression")
        self.compression_check.setChecked(True)
        settings_layout.addRow("", self.compression_check)

        # Remove metadata
        self.remove_metadata_check = QCheckBox("Remove file metadata")
        self.remove_metadata_check.setChecked(True)
        settings_layout.addRow("", self.remove_metadata_check)

        settings_group.setLayout(settings_layout)

        # Advanced options group
        options_group = QGroupBox("Advanced Options")
        options_layout = QFormLayout()

        # Chunk size
        self.chunk_size_combo = QComboBox()
        self.chunk_size_combo.addItems(["1 MB", "4 MB", "8 MB", "16 MB", "32 MB"])
        self.chunk_size_combo.setCurrentIndex(1)  # Default to 4MB
        options_layout.addRow("Chunk Size:", self.chunk_size_combo)

        # Parallel processing
        self.parallel_check = QCheckBox("Enable parallel processing")
        self.parallel_check.setChecked(True)
        options_layout.addRow("", self.parallel_check)

        # CPU priority
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["Normal", "Below Normal", "Low"])
        options_layout.addRow("CPU Priority:", self.priority_combo)

        options_group.setLayout(options_layout)

        # Add groups to layout
        layout.addWidget(settings_group)
        layout.addWidget(options_group)
        layout.addStretch()

    def browse_input_file(self):
        """Open a file dialog to select an input file."""
        file_filter = "All Files (*)"
        if self.mode == "encrypt":
            file_filter = "All Files (*);;Documents (*.txt *.doc *.docx *.pdf);;Images (*.png *.jpg *.jpeg *.bmp);;Archives (*.zip *.rar *.7z)"
        else:
            file_filter = "Encrypted Files (*.enc *.segg);;All Files (*)"

        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select File to Encrypt" if self.mode == "encrypt" else "Select File to Decrypt",
            "",
            file_filter,
        )

        if file_path:
            self.input_file = file_path
            self.input_path_edit.setText(file_path)

            # Auto-generate output filename if enabled
            if self.auto_name_check.isChecked():
                self.auto_generate_output_filename()

    def browse_output_file(self):
        """Open a file dialog to select an output file."""
        default_extension = ".enc" if self.mode == "encrypt" else ".dec"
        default_name = ""

        if self.input_file:
            base_name = os.path.splitext(os.path.basename(self.input_file))[0]
            default_name = f"{base_name}{default_extension}"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Encrypted File As" if self.mode == "encrypt" else "Save Decrypted File As",
            default_name,
            (
                f"Encrypted Files (*{default_extension});;All Files (*)"
                if self.mode == "encrypt"
                else f"Decrypted Files (*{default_extension});;All Files (*)"
            ),
        )

        if file_path:
            self.output_file = file_path
            self.output_path_edit.setText(file_path)

    def auto_generate_output_filename(self):
        """Automatically generate an output filename based on the input filename."""
        if not self.input_file:
            return

        input_path = Path(self.input_file)

        if self.mode == "encrypt":
            # For encryption, add .enc extension
            output_path = input_path.with_suffix(input_path.suffix + ".enc")
        else:
            # For decryption, remove .enc extension if present
            if input_path.suffix.lower() == ".enc":
                output_path = input_path.with_suffix("")
            else:
                output_path = input_path.with_suffix(input_path.suffix + ".dec")

        self.output_file = str(output_path)
        self.output_path_edit.setText(self.output_file)

    def toggle_auto_name(self, checked):
        """Toggle auto-generation of output filename."""
        if checked and self.input_file:
            self.auto_generate_output_filename()

    def toggle_password_visibility(self, show):
        """Toggle password visibility."""
        mode = QLineEdit.EchoMode.Normal if show else QLineEdit.EchoMode.Password
        self.password_edit.setEchoMode(mode)
        self.confirm_password_edit.setEchoMode(mode)

    def update_output_extension(self, text):
        """Update the output file extension based on the selected mode."""
        if not text or not self.auto_name_check.isChecked():
            return

        base, ext = os.path.splitext(text)
        if not ext:
            default_ext = ".enc" if self.mode == "encrypt" else ""
            self.output_path_edit.setText(f"{text}{default_ext}")

    def validate_inputs(self):
        """Validate the input fields."""
        # Check input file
        if not self.input_file:
            QMessageBox.warning(self, "Input Error", "Please select an input file.")
            return False

        if not os.path.exists(self.input_file):
            QMessageBox.warning(self, "Input Error", "The selected input file does not exist.")
            return False

        # Check output file
        if not self.output_file:
            QMessageBox.warning(self, "Output Error", "Please specify an output file.")
            return False

        # Check if output directory exists
        output_dir = os.path.dirname(self.output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                QMessageBox.critical(
                    self, "Output Error", f"Failed to create output directory: {str(e)}"
                )
                return False

        # Check password
        password = self.password_edit.text()
        if not password:
            QMessageBox.warning(self, "Password Error", "Please enter a password.")
            return False

        if self.mode == "encrypt":
            confirm_password = self.confirm_password_edit.text()
            if password != confirm_password:
                QMessageBox.warning(self, "Password Error", "Passwords do not match.")
                return False

        return True

    def process_file(self):
        """Process the file (encrypt or decrypt)."""
        if not self.validate_inputs():
            return

        # Disable UI during processing
        self.set_processing(True)

        # Get parameters
        password = self.password_edit.text()
        algorithm = self.algorithm_combo.currentText()
        iterations = self.iterations_spin.value()

        # Update status
        self.status_label.setText(
            f"{'Encrypting' if self.mode == 'encrypt' else 'Decrypting'} file. Please wait..."
        )
        self.progress_bar.setValue(0)
        self.progress_bar.show()

        # In a real implementation, you would use a background thread for processing
        # For now, we'll simulate the process with a timer
        self.simulate_processing()

    def simulate_processing(self):
        """Simulate file processing with a timer."""
        self.progress = 0
        self.timer = self.startTimer(50)  # 50ms timer

    def timerEvent(self, event):
        """Handle timer events for progress simulation."""
        self.progress += 1
        self.progress_bar.setValue(self.progress)

        if self.progress >= 100:
            self.killTimer(self.timer)
            self.processing_complete()

    def processing_complete(self):
        """Handle completion of the processing."""
        # Re-enable UI
        self.set_processing(False)

        # Show completion message
        QMessageBox.information(
            self,
            "Success" if self.mode == "encrypt" else "Success",
            f"File successfully {'encrypted' if self.mode == 'encrypt' else 'decrypted'} to:\n{self.output_file}",
        )

        # Close the dialog
        self.accept()

    def set_processing(self, processing):
        """Enable or disable UI elements during processing."""
        self.tab_widget.setEnabled(not processing)
        self.action_button.setEnabled(not processing)
        self.cancel_button.setEnabled(not processing)

        if processing:
            self.progress_bar.show()
        else:
            self.progress_bar.hide()

    def get_input_file(self):
        """Get the input file path."""
        return self.input_file

    def get_output_file(self):
        """Get the output file path."""
        return self.output_file

    def get_password(self):
        """Get the password."""
        return self.password_edit.text()


if __name__ == "__main__":
    import sys

    from PySide6.QtWidgets import QApplication

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Create and run the application
    app = QApplication(sys.argv)

    # Create and show the dialog
    dialog = FileEncryptionDialog(mode="encrypt")
    if dialog.exec() == QDialog.DialogCode.Accepted:
        print(f"Input file: {dialog.get_input_file()}")
        print(f"Output file: {dialog.get_output_file()}")

    sys.exit()
