"""
File Transfer Widget
-------------------
Provides a user interface for managing file transfers in the chat application.
"""

import os
import time
from pathlib import Path
from typing import Callable, Dict, Optional

from PySide6.QtCore import QObject, QSize, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from ..p2p.file_transfer import FileTransfer, FileTransferError, FileTransferManager


class FileTransferWidget(QWidget):
    """Widget that displays and manages a single file transfer."""

    # Signals
    transfer_complete = Signal(str, bool)  # file_id, success
    transfer_cancelled = Signal(str)  # file_id

    def __init__(self, transfer: FileTransfer, is_sender: bool, parent=None):
        """Initialize the file transfer widget.

        Args:
            transfer: The FileTransfer object
            is_sender: Whether this widget is for sending (True) or receiving (False)
            parent: Parent widget
        """
        super().__init__(parent)
        self.transfer = transfer
        self.is_sender = is_sender
        self.transfer_manager = None  # Will be set by set_transfer_manager

        self.setup_ui()
        self.update_display()

    def setup_ui(self):
        """Set up the user interface."""
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(60)

        # Main layout
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)

        # File icon
        self.icon_label = QLabel()
        self.icon_label.setFixedSize(32, 32)
        self.icon_label.setPixmap(self._get_file_icon().pixmap(32, 32))
        layout.addWidget(self.icon_label)

        # File info
        info_layout = QVBoxLayout()
        info_layout.setSpacing(2)

        self.filename_label = QLabel()
        self.filename_label.setStyleSheet("font-weight: bold;")
        info_layout.addWidget(self.filename_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        info_layout.addWidget(self.progress_bar)

        # Status and speed
        status_layout = QHBoxLayout()
        self.status_label = QLabel()
        self.speed_label = QLabel()
        self.speed_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.speed_label)
        info_layout.addLayout(status_layout)

        layout.addLayout(info_layout, 1)

        # Action buttons
        button_layout = QVBoxLayout()
        button_layout.setSpacing(2)

        # Cancel/Open buttons
        self.action_button = QPushButton()
        self.action_button.setFixedSize(80, 24)
        self.action_button.clicked.connect(self.on_action_clicked)
        button_layout.addWidget(self.action_button)

        # Menu button
        self.menu_button = QPushButton("⋮")
        self.menu_button.setFixedSize(24, 24)
        self.menu_button.setMenu(self.create_menu())
        button_layout.addWidget(self.menu_button)

        layout.addLayout(button_layout)

        # Update the display
        self.update_display()

    def create_menu(self) -> QMenu:
        """Create the context menu for the transfer."""
        menu = QMenu(self)

        if self.is_sender:
            menu.addAction("Cancel", self.cancel_transfer)
        else:
            if self.transfer.status == "completed":
                menu.addAction("Open File", self.open_file)
                menu.addAction("Open Containing Folder", self.open_containing_folder)
            menu.addAction("Cancel", self.cancel_transfer)

        menu.addSeparator()
        menu.addAction("Copy File ID", self.copy_file_id)

        return menu

    def set_transfer_manager(self, manager: "FileTransferManager"):
        """Set the file transfer manager."""
        self.transfer_manager = manager

    def update_display(self):
        """Update the display with current transfer status."""
        # Update filename
        self.filename_label.setText(self.transfer.filename)

        # Update progress
        self.progress_bar.setValue(int(self.transfer.progress))

        # Update status and button
        status_text = {
            "pending": "Pending" if self.is_sender else "Incoming",
            "transferring": "Sending..." if self.is_sender else "Receiving...",
            "completed": "Sent" if self.is_sender else "Received",
            "failed": "Failed",
            "cancelled": "Cancelled",
            "rejected": "Rejected",
            "offered": "Incoming",
        }.get(self.transfer.status, self.transfer.status.capitalize())

        self.status_label.setText(status_text)

        # Update speed/ETA if transferring
        if self.transfer.status == "transferring" and self.transfer.transferred_bytes > 0:
            elapsed = time.time() - self.transfer.start_time
            if elapsed > 0:
                speed = self.transfer.transferred_bytes / elapsed  # bytes per second
                speed_str = self._format_speed(speed)

                # Calculate ETA
                remaining_bytes = self.transfer.file_size - self.transfer.transferred_bytes
                if speed > 0:
                    eta = remaining_bytes / speed
                    eta_str = self._format_time(eta)
                    self.speed_label.setText(f"{speed_str} • {eta_str}")
                else:
                    self.speed_label.setText(speed_str)
            else:
                self.speed_label.clear()
        else:
            self.speed_label.clear()

        # Update button
        if self.transfer.status == "completed":
            self.action_button.setText("Open")
            self.action_button.setEnabled(True)
            self.menu_button.setEnabled(True)
        elif self.transfer.status in ["failed", "cancelled", "rejected"]:
            self.action_button.setText("Retry" if self.is_sender else "Dismiss")
            self.action_button.setEnabled(True)
            self.menu_button.setEnabled(True)
        else:
            self.action_button.setText("Cancel")
            self.action_button.setEnabled(True)
            self.menu_button.setEnabled(True)

    def on_action_clicked(self):
        """Handle action button click."""
        if self.transfer.status == "completed":
            self.open_file()
        elif self.transfer.status in ["failed", "cancelled", "rejected"]:
            if self.is_sender:
                self.retry_transfer()
            else:
                self.dismiss()
        else:
            self.cancel_transfer()

    def cancel_transfer(self):
        """Cancel the transfer."""
        if self.transfer_manager and self.transfer.status in ["pending", "transferring"]:
            asyncio.create_task(self.transfer_manager.cancel_transfer(self.transfer.file_id))
        self.transfer.status = "cancelled"
        self.update_display()
        self.transfer_cancelled.emit(self.transfer.file_id)

    def retry_transfer(self):
        """Retry a failed transfer."""
        if self.is_sender and self.transfer_manager and self.transfer.file_path:
            # Reset transfer state
            self.transfer.status = "pending"
            self.transfer.progress = 0.0
            self.transfer.transferred_bytes = 0
            self.transfer.start_time = time.time()
            self.update_display()

            # Start the transfer again
            asyncio.create_task(self._retry_transfer())

    async def _retry_transfer(self):
        """Internal method to retry a transfer."""
        try:
            await self.transfer_manager.send_file(
                str(self.transfer.file_path),
                on_progress=self.transfer.on_progress,
                on_complete=self.transfer.on_complete,
                on_error=self.transfer.on_error,
            )
        except Exception as e:
            logger.error(f"Failed to retry transfer: {e}")
            self.transfer.status = "failed"
            self.update_display()

    def open_file(self):
        """Open the transferred file."""
        if self.transfer.file_path and self.transfer.file_path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.transfer.file_path)))

    def open_containing_folder(self):
        """Open the folder containing the transferred file."""
        if self.transfer.file_path and self.transfer.file_path.exists():
            folder = str(self.transfer.file_path.parent)
            if os.name == "nt":  # Windows
                os.startfile(folder)
            elif os.name == "posix":  # macOS and Linux
                if os.uname().sysname == "Darwin":  # macOS
                    os.system(f'open "{folder}"')
                else:  # Linux
                    os.system(f'xdg-open "{folder}"')

    def copy_file_id(self):
        """Copy the file ID to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.transfer.file_id)

    def dismiss(self):
        """Dismiss the transfer widget."""
        self.hide()
        self.deleteLater()

    def _get_file_icon(self) -> QIcon:
        """Get an appropriate icon for the file type."""
        # This is a simplified version - in a real app, you'd want to use QFileIconProvider
        # or a proper icon theme
        ext = Path(self.transfer.filename).suffix.lower()

        # Common file type icons
        if ext in [".txt", ".md", ".log", ".csv", ".json", ".xml", ".yaml", ".yml"]:
            return QIcon.fromTheme("text-x-generic")
        elif ext in [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp"]:
            return QIcon.fromTheme("image-x-generic")
        elif ext in [".mp3", ".wav", ".ogg", ".flac", ".m4a"]:
            return QIcon.fromTheme("audio-x-generic")
        elif ext in [".mp4", ".avi", ".mov", ".mkv", ".webm"]:
            return QIcon.fromTheme("video-x-generic")
        elif ext in [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2"]:
            return QIcon.fromTheme("application-x-archive")
        elif ext in [".pdf"]:
            return QIcon.fromTheme("application-pdf")
        elif ext in [".doc", ".docx"]:
            return QIcon.fromTheme("x-office-document")
        elif ext in [".xls", ".xlsx"]:
            return QIcon.fromTheme("x-office-spreadsheet")
        elif ext in [".ppt", ".pptx"]:
            return QIcon.fromTheme("x-office-presentation")
        else:
            return QIcon.fromTheme("text-x-generic")

    @staticmethod
    def _format_speed(speed: float) -> str:
        """Format transfer speed in human-readable format."""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if speed < 1024.0:
                return f"{speed:.1f} {unit}"
            speed /= 1024.0
        return f"{speed:.1f} TB/s"

    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format time in human-readable format."""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            return f"{int(seconds // 60)}m {int(seconds % 60)}s"
        else:
            return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m"


class FileTransferDialog(QWidget):
    """Dialog for managing file transfers."""

    def __init__(self, transfer_manager: "FileTransferManager", parent=None):
        """Initialize the file transfer dialog.

        Args:
            transfer_manager: The FileTransferManager instance
            parent: Parent widget
        """
        super().__init__(parent)
        self.transfer_manager = transfer_manager
        self.transfer_widgets = {}  # file_id -> widget

        self.setup_ui()

        # Connect signals
        if hasattr(transfer_manager, "on_incoming_file"):
            transfer_manager.on_incoming_file = self.add_incoming_transfer

    def setup_ui(self):
        """Set up the user interface."""
        self.setWindowTitle("File Transfers")
        self.setMinimumSize(500, 300)

        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Toolbar
        toolbar = QHBoxLayout()

        self.send_button = QPushButton("Send File...")
        self.send_button.setIcon(self.style().standardIcon("SP_ArrowUp"))
        self.send_button.clicked.connect(self.send_file)
        toolbar.addWidget(self.send_button)

        self.clear_button = QPushButton("Clear Completed")
        self.clear_button.clicked.connect(self.clear_completed)
        toolbar.addWidget(self.clear_button)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Transfers list
        self.transfers_layout = QVBoxLayout()
        self.transfers_layout.setSpacing(5)

        # Add a scroll area for the transfers
        scroll_widget = QWidget()
        scroll_widget.setLayout(self.transfers_layout)

        from PySide6.QtWidgets import QScrollArea

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(scroll_widget)
        scroll_area.setFrameShape(QFrame.NoFrame)

        layout.addWidget(scroll_area)

        # Status bar
        self.status_bar = QLabel("No active transfers")
        self.status_bar.setStyleSheet("color: #666; font-style: italic;")
        layout.addWidget(self.status_bar)

    def add_transfer(self, transfer: FileTransfer, is_sender: bool) -> FileTransferWidget:
        """Add a new transfer to the dialog.

        Args:
            transfer: The FileTransfer object
            is_sender: Whether this is an outgoing transfer

        Returns:
            The created FileTransferWidget
        """
        # Create the widget
        widget = FileTransferWidget(transfer, is_sender, self)
        widget.set_transfer_manager(self.transfer_manager)

        # Connect signals
        widget.transfer_complete.connect(self.on_transfer_complete)
        widget.transfer_cancelled.connect(self.on_transfer_cancelled)

        # Add to layout and tracking
        self.transfers_layout.addWidget(widget)
        self.transfer_widgets[transfer.file_id] = widget

        # Update status
        self.update_status()

        return widget

    def add_incoming_transfer(self, transfer: FileTransfer):
        """Add an incoming transfer to the dialog."""
        self.add_transfer(transfer, is_sender=False)

        # Show a notification
        QMessageBox.information(
            self,
            "Incoming File Transfer",
            f"{transfer.filename} ({self._format_size(transfer.file_size)})\n\n"
            f"From: {getattr(transfer, 'sender_name', 'Unknown')}",
        )

    def send_file(self):
        """Open a file dialog to select a file to send."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File to Send", "", "All Files (*.*)"
        )

        if file_path:
            try:
                # Start the transfer
                asyncio.create_task(self._start_file_transfer(file_path))
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to start transfer: {e}")

    async def _start_file_transfer(self, file_path: str):
        """Start a file transfer."""
        try:
            file_id = await self.transfer_manager.send_file(file_path)

            # The transfer widget will be added by the transfer manager's callback
            # which is connected to add_transfer

        except FileTransferError as e:
            QMessageBox.critical(self, "Transfer Failed", str(e))

    def clear_completed(self):
        """Remove all completed transfers from the list."""
        to_remove = []

        for file_id, widget in list(self.transfer_widgets.items()):
            if widget.transfer.status in ["completed", "failed", "cancelled", "rejected"]:
                widget.hide()
                widget.deleteLater()
                to_remove.append(file_id)

        # Remove from tracking
        for file_id in to_remove:
            del self.transfer_widgets[file_id]

        self.update_status()

    def on_transfer_complete(self, file_id: str, success: bool):
        """Handle transfer completion."""
        if file_id in self.transfer_widgets:
            widget = self.transfer_widgets[file_id]
            widget.update_display()

            # Show a notification
            if success:
                QMessageBox.information(
                    self,
                    "Transfer Complete",
                    f"Successfully {'sent' if widget.is_sender else 'received'}: {widget.transfer.filename}",
                )

        self.update_status()

    def on_transfer_cancelled(self, file_id: str):
        """Handle transfer cancellation."""
        if file_id in self.transfer_widgets:
            widget = self.transfer_widgets[file_id]
            widget.update_display()

        self.update_status()

    def update_status(self):
        """Update the status bar with transfer statistics."""
        total = len(self.transfer_widgets)
        completed = sum(
            1 for w in self.transfer_widgets.values() if w.transfer.status == "completed"
        )
        failed = sum(
            1
            for w in self.transfer_widgets.values()
            if w.transfer.status in ["failed", "cancelled", "rejected"]
        )
        active = total - completed - failed

        if total == 0:
            self.status_bar.setText("No active transfers")
        else:
            status = []
            if active > 0:
                status.append(f"{active} active")
            if completed > 0:
                status.append(f"{completed} completed")
            if failed > 0:
                status.append(f"{failed} failed")

            self.status_bar.setText(" • ".join(status))

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"
