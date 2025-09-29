"""
File Transfer Manager

Handles file transfer operations including sending and receiving files.
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class FileTransferManager:
    """Manages file transfer operations for the application."""

    def __init__(self, download_dir: Optional[str] = None):
        """
        Initialize the FileTransferManager.

        Args:
            download_dir: Directory to save downloaded files (defaults to ~/Downloads/ScrambledEggs)
        """
        self.active_transfers: Dict[str, Dict[str, Any]] = {}
        self.download_dir = download_dir or os.path.join(
            str(Path.home()), "Downloads", "ScrambledEggs"
        )

        # Create download directory if it doesn't exist
        os.makedirs(self.download_dir, exist_ok=True)
        logger.info(f"FileTransferManager initialized. Download directory: {self.download_dir}")

    def start_upload(
        self,
        file_path: str,
        recipient_id: str,
        on_progress: Optional[Callable[[int, int], None]] = None,
        **metadata,
    ) -> str:
        """
        Start a file upload.

        Args:
            file_path: Path to the file to upload
            recipient_id: ID of the recipient
            on_progress: Optional callback for progress updates (bytes_sent, total_bytes)
            **metadata: Additional file metadata

        Returns:
            str: Transfer ID for this upload
        """
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            transfer_id = f"transfer_{len(self.active_transfers) + 1}"

            self.active_transfers[transfer_id] = {
                "type": "upload",
                "file_path": file_path,
                "file_name": file_name,
                "file_size": file_size,
                "recipient_id": recipient_id,
                "status": "pending",
                "progress": 0,
                "on_progress": on_progress,
                "metadata": metadata or {},
            }

            logger.info(f"Started upload {transfer_id}: {file_name} ({file_size} bytes)")
            return transfer_id

        except Exception as e:
            logger.error(f"Failed to start upload: {e}")
            raise

    def start_download(
        self,
        file_name: str,
        file_size: int,
        sender_id: str,
        on_progress: Optional[Callable[[int, int], None]] = None,
        **metadata,
    ) -> str:
        """
        Start a file download.

        Args:
            file_name: Name of the file to download
            file_size: Size of the file in bytes
            sender_id: ID of the sender
            on_progress: Optional callback for progress updates (bytes_received, total_bytes)
            **metadata: Additional file metadata

        Returns:
            str: Transfer ID for this download
        """
        try:
            transfer_id = f"transfer_{len(self.active_transfers) + 1}"
            download_path = os.path.join(self.download_dir, file_name)

            # Handle duplicate filenames
            counter = 1
            base_name, ext = os.path.splitext(file_name)
            while os.path.exists(download_path):
                new_name = f"{base_name} ({counter}){ext}"
                download_path = os.path.join(self.download_dir, new_name)
                counter += 1

            self.active_transfers[transfer_id] = {
                "type": "download",
                "file_path": download_path,
                "file_name": os.path.basename(download_path),
                "file_size": file_size,
                "sender_id": sender_id,
                "status": "pending",
                "progress": 0,
                "on_progress": on_progress,
                "metadata": metadata or {},
            }

            logger.info(f"Started download {transfer_id}: {file_name} ({file_size} bytes)")
            return transfer_id

        except Exception as e:
            logger.error(f"Failed to start download: {e}")
            raise

    def update_progress(self, transfer_id: str, bytes_transferred: int) -> None:
        """
        Update the progress of a file transfer.

        Args:
            transfer_id: ID of the transfer to update
            bytes_transferred: Number of bytes transferred so far
        """
        if transfer_id in self.active_transfers:
            transfer = self.active_transfers[transfer_id]
            transfer["progress"] = bytes_transferred

            # Update status if completed
            if bytes_transferred >= transfer["file_size"]:
                transfer["status"] = "completed"
                transfer["completed_at"] = self._get_current_timestamp()
            else:
                transfer["status"] = "in_progress"

            # Call progress callback if provided
            if callable(transfer.get("on_progress")):
                try:
                    transfer["on_progress"](bytes_transferred, transfer["file_size"])
                except Exception as e:
                    logger.error(f"Error in progress callback: {e}")

    def cancel_transfer(self, transfer_id: str) -> bool:
        """
        Cancel an active transfer.

        Args:
            transfer_id: ID of the transfer to cancel

        Returns:
            bool: True if transfer was cancelled successfully, False otherwise
        """
        if transfer_id in self.active_transfers:
            self.active_transfers[transfer_id]["status"] = "cancelled"
            logger.info(f"Cancelled transfer: {transfer_id}")

            # Clean up partially downloaded files for cancelled downloads
            transfer = self.active_transfers[transfer_id]
            if transfer["type"] == "download" and os.path.exists(transfer["file_path"]):
                try:
                    os.remove(transfer["file_path"])
                except Exception as e:
                    logger.error(f"Failed to clean up cancelled download: {e}")

            return True
        return False

    def get_transfer_status(self, transfer_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the status of a file transfer.

        Args:
            transfer_id: ID of the transfer to check

        Returns:
            dict: Transfer status information or None if not found
        """
        transfer = self.active_transfers.get(transfer_id)
        if transfer:
            return {
                "transfer_id": transfer_id,
                "type": transfer["type"],
                "file_name": transfer["file_name"],
                "file_size": transfer["file_size"],
                "progress": transfer.get("progress", 0),
                "status": transfer["status"],
                "progress_percent": (
                    min(100, int((transfer.get("progress", 0) / transfer["file_size"]) * 100))
                    if transfer["file_size"] > 0
                    else 0
                ),
                "metadata": transfer.get("metadata", {}),
            }
        return None

    def get_active_transfers(self) -> List[Dict[str, Any]]:
        """
        Get a list of all active transfers.

        Returns:
            List of transfer status dictionaries
        """
        return [
            self.get_transfer_status(transfer_id)
            for transfer_id in self.active_transfers
            if self.active_transfers[transfer_id]["status"] in ["pending", "in_progress"]
        ]

    def _get_current_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime

        return datetime.now().isoformat()

    def calculate_file_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """
        Calculate the hash of a file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use (default: sha256)

        Returns:
            str: Hexadecimal digest of the file
        """
        hash_func = getattr(hashlib, algorithm, hashlib.sha256)
        hasher = hash_func()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.hexdigest()
