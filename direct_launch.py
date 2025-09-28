"""
Direct launch script for Scrambled Eggs with detailed error handling.
"""
import os
import sys
import logging
import traceback
from pathlib import Path

# Set up logging to file and console
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('direct_launch.log')
    ]
)
logger = logging.getLogger(__name__)

def check_imports():
    """Check if required packages are installed."""
    required = ['PyQt5', 'cryptography']
    missing = []
    
    for package in required:
        try:
            __import__(package)
            logger.info(f"Successfully imported {package}")
        except ImportError as e:
            logger.error(f"Failed to import {package}: {e}")
            missing.append(package)
    
    if missing:
        logger.error(f"Missing required packages: {', '.join(missing)}")
        logger.info("Try installing them with: pip install PyQt5 cryptography")
        return False
    return True

def main():
    """Main entry point for direct launch."""
    logger.info("Starting Scrambled Eggs (Direct Launch)")
    
    # Check if required packages are installed
    if not check_imports():
        logger.error("Required packages are missing. Please install them first.")
        return 1
    
    try:
        # Try to import the main application
        logger.info("Attempting to import Scrambled Eggs...")
        from scrambled_eggs.gui.main_window import MainWindow
        from PyQt5.QtWidgets import QApplication
        
        # Create application
        logger.info("Creating QApplication...")
        app = QApplication(sys.argv)
        
        # Create and show main window
        logger.info("Creating main window...")
        window = MainWindow()
        window.show()
        
        logger.info("Starting application event loop...")
        return app.exec_()
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        logger.error(traceback.format_exc())
        
        # Try to show error in a message box if possible
        try:
            from PyQt5.QtWidgets import QApplication, QMessageBox
            app = QApplication.instance() or QApplication(sys.argv)
            QMessageBox.critical(
                None,
                "Error",
                f"Failed to start Scrambled Eggs:\n\n{str(e)}\n\nCheck direct_launch.log for details."
            )
            return app.exec_()
        except:
            logger.error("Could not display error dialog")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())
