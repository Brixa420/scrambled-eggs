"""
File Transfer Dialog

Provides a dialog for sending and receiving files.
"""
import os
from typing import Optional, Dict, List

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QLabel, QPushButton, 
    QProgressBar, QFileDialog, QHBoxLayout, QListWidget,
    QListWidgetItem, QMessageBox, QDialogButtonBox
)
from PySide6.QtCore import Qt, QTimer, Signal, QThread, QObject

class FileTransferWorker(QObject):
    """Worker for handling file transfer operations."""
    progress = Signal(int)
    finished = Signal(bool, str)
    
    def __init__(self, file_path: str, recipient_id: str):
        super().__init__()
        self.file_path = file_path
        self.recipient_id = recipient_id
        self.is_running = True
    
    def run(self):
        """Simulate file transfer."""
        try:
            file_size = os.path.getsize(self.file_path)
            transferred = 0
            chunk_size = 1024 * 1024  # 1MB chunks
            
            # Simulate transfer
            while transferred < file_size and self.is_running:
                transferred += min(chunk_size, file_size - transferred)
                progress = int((transferred / file_size) * 100)
                self.progress.emit(progress)
                QThread.msleep(100)  # Simulate network delay
                
            if self.is_running:
                self.finished.emit(True, "Transfer completed successfully")
            else:
                self.finished.emit(False, "Transfer cancelled")
                
        except Exception as e:
            self.finished.emit(False, f"Error during transfer: {str(e)}")
    
    def stop(self):
        """Stop the transfer."""
        self.is_running = False

class FileTransferDialog(QDialog):
    """Dialog for managing file transfers."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Transfer")
        self.setMinimumSize(500, 400)
        
        self.current_transfer = None
        self.transfer_thread = None
        self.worker = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Initialize the dialog UI components."""
        layout = QVBoxLayout(self)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_label = QLabel("No file selected")
        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.browse_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        
        # Transfer button
        self.transfer_button = QPushButton("Start Transfer")
        self.transfer_button.clicked.connect(self.start_transfer)
        self.transfer_button.setEnabled(False)
        
        # Transfer list
        self.transfer_list = QListWidget()
        
        # Button box
        button_box = QDialogButtonBox(QDialogButtonBox.Close)
        button_box.rejected.connect(self.reject)
        
        # Add widgets to layout
        layout.addLayout(file_layout)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.transfer_button)
        layout.addWidget(QLabel("Recent Transfers:"))
        layout.addWidget(self.transfer_list)
        layout.addWidget(button_box)
    
    def browse_file(self):
        """Open file dialog to select a file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Send", "", "All Files (*)")
            
        if file_path:
            self.current_transfer = file_path
            self.file_label.setText(os.path.basename(file_path))
            self.transfer_button.setEnabled(True)
    
    def start_transfer(self):
        """Start the file transfer process."""
        if not self.current_transfer:
            return
            
        # Disable UI during transfer
        self.browse_button.setEnabled(False)
        self.transfer_button.setEnabled(False)
        self.transfer_button.setText("Transferring...")
        
        # Create worker and thread
        self.worker = FileTransferWorker(self.current_transfer, "recipient_id_here")
        self.transfer_thread = QThread()
        
        # Move worker to thread
        self.worker.moveToThread(self.transfer_thread)
        
        # Connect signals
        self.transfer_thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.transfer_finished)
        
        # Start the thread
        self.transfer_thread.start()
    
    def update_progress(self, value):
        """Update the progress bar."""
        self.progress_bar.setValue(value)
    
    def transfer_finished(self, success, message):
        """Handle transfer completion."""
        # Clean up thread
        if self.transfer_thread and self.transfer_thread.isRunning():
            self.worker.stop()
            self.transfer_thread.quit()
            self.transfer_thread.wait()
        
        # Update UI
        self.browse_button.setEnabled(True)
        self.transfer_button.setEnabled(True)
        self.transfer_button.setText("Start Transfer")
        
        # Show result
        if success:
            self.transfer_list.addItem(
                f"✓ {os.path.basename(self.current_transfer)} - {message}")
            self.progress_bar.setValue(0)
            self.current_transfer = None
            self.file_label.setText("No file selected")
        else:
            QMessageBox.warning(self, "Transfer Failed", message)
    
    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.transfer_thread and self.transfer_thread.isRunning():
            self.worker.stop()
            self.transfer_thread.quit()
            self.transfer_thread.wait()
        event.accept()
