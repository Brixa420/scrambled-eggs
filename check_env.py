"""
Simple script to check the Python environment and display a message box.
"""
import sys
import platform
import os

def main():
    print("Python Environment Check")
    print("=======================")
    print(f"Python Version: {sys.version}")
    print(f"Platform: {platform.platform()}")
    print(f"Current Directory: {os.getcwd()}")
    print("\nEnvironment Variables:")
    for key, value in os.environ.items():
        if key.startswith('PYTHON') or key.startswith('PATH'):
            print(f"{key}: {value}")
    
    # Try to import PyQt5 and show a message box
    try:
        print("\nAttempting to import PyQt5...")
        from PyQt5.QtWidgets import QApplication, QMessageBox
        print("PyQt5 imported successfully!")
        
        app = QApplication(sys.argv)
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("Environment Check")
        msg.setText("Environment Check Successful!")
        msg.setInformativeText("PyQt5 is working correctly.")
        msg.setDetailedText(f"Python: {sys.version}\nPlatform: {platform.platform()}")
        msg.exec_()
        
    except ImportError as e:
        print(f"Error importing PyQt5: {e}")
        print("Try installing it with: pip install PyQt5")
        input("Press Enter to exit...")
    except Exception as e:
        print(f"Unexpected error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
