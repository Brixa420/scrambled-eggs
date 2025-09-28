"""
Login Dialog for Scrambled Eggs
------------------------------
Provides a dialog for user authentication.
"""
import logging
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QCheckBox, QFormLayout, QMessageBox
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QPixmap

logger = logging.getLogger(__name__)

class LoginDialog(QDialog):
    """A dialog for user login."""
    
    def __init__(self, parent=None):
        """Initialize the login dialog."""
        super().__init__(parent)
        self.setWindowTitle("Login - Scrambled Eggs")
        self.setMinimumWidth(350)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        
        # Initialize UI
        self.init_ui()
        
        # Set focus to username field
        self.username_edit.setFocus()
    
    def init_ui(self):
        """Initialize the user interface."""
        # Main layout
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Logo and title
        logo_label = QLabel()
        logo_pixmap = QPixmap(":/icons/app_icon.png").scaled(64, 64, 
            Qt.AspectRatioMode.KeepAspectRatio, 
            Qt.TransformationMode.SmoothTransformation)
        logo_label.setPixmap(logo_pixmap)
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        title_label = QLabel("Scrambled Eggs")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_font = title_label.font()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        # Form layout for inputs
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        form_layout.setContentsMargins(20, 10, 20, 10)
        
        # Username field
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("Enter your username")
        form_layout.addRow("Username:", self.username_edit)
        
        # Password field
        self.password_edit = QLineEdit()
        self.password_edit.setPlaceholderText("Enter your password")
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow("Password:", self.password_edit)
        
        # Remember me checkbox
        self.remember_check = QCheckBox("Remember me")
        form_layout.addRow("", self.remember_check)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.login_button = QPushButton("Login")
        self.login_button.setDefault(True)
        self.login_button.clicked.connect(self.accept)
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.cancel_button)
        
        # Add widgets to main layout
        layout.addSpacing(10)
        layout.addWidget(logo_label)
        layout.addWidget(title_label)
        layout.addLayout(form_layout)
        layout.addLayout(button_layout)
        layout.addSpacing(10)
        
        # Set enter key to trigger login
        self.username_edit.returnPressed.connect(self.login_button.click)
        self.password_edit.returnPressed.connect(self.login_button.click)
    
    def get_username(self):
        """Get the entered username."""
        return self.username_edit.text().strip()
    
    def get_password(self):
        """Get the entered password."""
        return self.password_edit.text()
    
    def get_remember_me(self):
        """Check if 'Remember me' is selected."""
        return self.remember_check.isChecked()
    
    def accept(self):
        """Handle the login attempt."""
        username = self.get_username()
        password = self.get_password()
        
        # Validate inputs
        if not username:
            QMessageBox.warning(self, "Input Error", "Please enter a username.")
            self.username_edit.setFocus()
            return
            
        if not password:
            QMessageBox.warning(self, "Input Error", "Please enter a password.")
            self.password_edit.setFocus()
            return
        
        # In a real application, you would validate the credentials here
        # For now, we'll just accept any non-empty username/password
        logger.info(f"Login attempt for user: {username}")
        
        # Call parent's accept to close the dialog with Accepted status
        super().accept()
    
    def reject(self):
        """Handle the cancel action."""
        # In a real application, you might want to ask for confirmation
        # before closing the dialog
        super().reject()


if __name__ == "__main__":
    import sys
    from PySide6.QtWidgets import QApplication
    
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Create and run the application
    app = QApplication(sys.argv)
    
    # Create and show the login dialog
    dialog = LoginDialog()
    if dialog.exec() == QDialog.DialogCode.Accepted:
        print(f"Logged in as: {dialog.get_username()}")
    else:
        print("Login cancelled")
    
    sys.exit()
