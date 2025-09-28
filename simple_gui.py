"""
Simple GUI launcher for Scrambled Eggs that bypasses problematic components.
"""
import os
import sys
import logging
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QLabel, QPushButton, QMessageBox

# Set up basic logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('scrambled_eggs_simple.log')
    ]
)
logger = logging.getLogger(__name__)

class SimpleScrambledEggsGUI(QMainWindow):
    """A simplified version of the Scrambled Eggs GUI."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Scrambled Eggs (Simple Mode)")
        self.setGeometry(100, 100, 800, 600)
        
        # Set up the main widget and layout
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.layout = QVBoxLayout(self.main_widget)
        
        # Add a welcome message
        welcome_label = QLabel("Welcome to Scrambled Eggs (Simple Mode)")
        welcome_label.setStyleSheet("font-size: 18px; font-weight: bold; margin: 20px;")
        self.layout.addWidget(welcome_label)
        
        # Add a status message
        status_label = QLabel("The application is running in simple mode with limited functionality.")
        self.layout.addWidget(status_label)
        
        # Add a button to show a sample feature
        test_button = QPushButton("Test Button")
        test_button.clicked.connect(self.show_test_message)
        self.layout.addWidget(test_button)
        
        # Add stretch to push everything to the top
        self.layout.addStretch()
        
        logger.info("Simple GUI initialized")
    
    def show_test_message(self):
        """Show a test message box."""
        QMessageBox.information(
            self,
            "Test Message",
            "This is a test message to verify the GUI is working."
        )

def main():
    """Launch the simple GUI application."""
    try:
        # Create the application
        app = QApplication(sys.argv)
        
        # Create and show the main window
        window = SimpleScrambledEggsGUI()
        window.show()
        
        # Start the event loop
        logger.info("Starting application event loop")
        return app.exec_()
        
    except Exception as e:
        logger.exception("An unexpected error occurred:")
        return 1

if __name__ == "__main__":
    sys.exit(main())
