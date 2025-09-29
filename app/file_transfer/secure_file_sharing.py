"""
Secure File Sharing Module for Brixa
Handles encrypted file transfers with P2P capabilities.
"""

import asyncio
import hashlib
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, Optional

from app.p2p.p2p_manager import P2PManager
from app.security.scrambled_eggs_crypto import ScrambledEggsCrypto

# File chunk size for streaming (1MB chunks)
CHUNK_SIZE = 1024 * 1024


class FileTransferStatus(Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class FileMetadata:
    """Metadata for file transfers."""

    file_id: str
    file_name: str
    file_size: int
    file_hash: str
    mime_type: str
    chunk_count: int
    transfer_status: FileTransferStatus = FileTransferStatus.PENDING
    transferred_chunks: int = 0
    error: Optional[str] = None


class SecureFileSharing:
    """Handles secure file transfers between peers."""

    def __init__(self, p2p_manager: P2PManager, storage_dir: str = None):
        """Initialize the file sharing service."""
        self.p2p = p2p_manager
        self.crypto = ScrambledEggsCrypto()
        self.storage_dir = Path(storage_dir or "./file_transfers")
        self.active_transfers: Dict[str, FileMetadata] = {}
        self.logger = logging.getLogger(__name__)

        # Ensure storage directory exists
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Register message handlers
        self.p2p.register_message_handler("file_offer", self._handle_file_offer)
        self.p2p.register_message_handler("file_chunk", self._handle_file_chunk)
        self.p2p.register_message_handler("transfer_control", self._handle_transfer_control)

    async def send_file(self, peer_id: str, file_path: str) -> str:
        """
        Initiate a file transfer to a peer.

        Args:
            peer_id: The ID of the peer to send the file to
            file_path: Path to the file to send

        Returns:
            A unique transfer ID for tracking the transfer
        """
        try:
            file_path = Path(file_path)
            if not file_path.is_file():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Generate file metadata
            file_id = self._generate_file_id()
            file_size = file_path.stat().st_size
            file_hash = self._calculate_file_hash(file_path)
            chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

            metadata = FileMetadata(
                file_id=file_id,
                file_name=file_path.name,
                file_size=file_size,
                file_hash=file_hash,
                mime_type=self._guess_mime_type(file_path),
                chunk_count=chunk_count,
            )

            # Store metadata for tracking
            self.active_transfers[file_id] = metadata

            # Send file offer to peer
            await self.p2p.send_message(
                peer_id,
                {
                    "type": "file_offer",
                    "file_id": file_id,
                    "file_name": metadata.file_name,
                    "file_size": metadata.file_size,
                    "file_hash": metadata.file_hash,
                    "mime_type": metadata.mime_type,
                    "chunk_count": metadata.chunk_count,
                },
            )

            # Start sending file chunks
            asyncio.create_task(self._send_file_chunks(peer_id, file_id, file_path))

            return file_id

        except Exception as e:
            self.logger.error(f"Failed to initiate file transfer: {str(e)}")
            raise

    async def receive_file(self, file_id: str, save_path: str) -> bool:
        """
        Prepare to receive a file and save it to the specified path.

        Args:
            file_id: The ID of the file transfer
            save_path: Where to save the received file

        Returns:
            True if the file was successfully prepared for receiving
        """
        try:
            if file_id not in self.active_transfers:
                self.active_transfers[file_id] = FileMetadata(
                    file_id=file_id,
                    file_name=os.path.basename(save_path),
                    file_size=0,  # Will be updated when we receive the file offer
                    file_hash="",
                    mime_type="application/octet-stream",
                    chunk_count=0,
                )

            metadata = self.active_transfers[file_id]
            metadata.save_path = Path(save_path)
            metadata.transfer_status = FileTransferStatus.PENDING

            # Create parent directories if they don't exist
            metadata.save_path.parent.mkdir(parents=True, exist_ok=True)

            return True

        except Exception as e:
            self.logger.error(f"Failed to prepare for file receive: {str(e)}")
            return False

    async def cancel_transfer(self, file_id: str) -> bool:
        """Cancel an ongoing file transfer."""
        if file_id in self.active_transfers:
            self.active_transfers[file_id].transfer_status = FileTransferStatus.CANCELLED
            # TODO: Notify the other peer about the cancellation
            return True
        return False

    # Internal methods

    def _generate_file_id(self) -> str:
        """Generate a unique file ID."""
        return hashlib.sha256(os.urandom(32)).hexdigest()

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _guess_mime_type(self, file_path: Path) -> str:
        """Guess the MIME type of a file based on its extension."""
        # Simple MIME type mapping - can be expanded as needed
        mime_types = {
            ".txt": "text/plain",
            ".pdf": "application/pdf",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
            ".zip": "application/zip",
        }
        return mime_types.get(file_path.suffix.lower(), "application/octet-stream")

    async def _send_file_chunks(self, peer_id: str, file_id: str, file_path: Path):
        """Send file chunks to the peer."""
        try:
            metadata = self.active_transfers[file_id]
            metadata.transfer_status = FileTransferStatus.IN_PROGRESS

            with open(file_path, "rb") as f:
                for chunk_index in range(metadata.chunk_count):
                    # Check if transfer was cancelled
                    if metadata.transfer_status == FileTransferStatus.CANCELLED:
                        break

                    # Read chunk
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break

                    # Encrypt chunk
                    ciphertext, chunk_metadata = self.crypto.encrypt(chunk)

                    # Send chunk
                    await self.p2p.send_message(
                        peer_id,
                        {
                            "type": "file_chunk",
                            "file_id": file_id,
                            "chunk_index": chunk_index,
                            "chunk_data": ciphertext.hex(),
                            "metadata": chunk_metadata,
                        },
                    )

                    # Update progress
                    metadata.transferred_chunks += 1

                    # Small delay to prevent overwhelming the network
                    await asyncio.sleep(0.01)

            # Mark transfer as completed
            if metadata.transfer_status != FileTransferStatus.CANCELLED:
                metadata.transfer_status = FileTransferStatus.COMPLETED
                self.logger.info(f"File transfer completed: {file_id}")

        except Exception as e:
            metadata.transfer_status = FileTransferStatus.FAILED
            metadata.error = str(e)
            self.logger.error(f"File transfer failed: {str(e)}")

    async def _handle_file_offer(self, data: Dict[str, Any]):
        """Handle incoming file offer from a peer."""
        try:
            file_id = data["file_id"]

            # Store file metadata
            self.active_transfers[file_id] = FileMetadata(
                file_id=file_id,
                file_name=data["file_name"],
                file_size=data["file_size"],
                file_hash=data["file_hash"],
                mime_type=data.get("mime_type", "application/octet-stream"),
                chunk_count=data["chunk_count"],
            )

            # Notify the UI about the incoming file
            # TODO: Implement UI notification system
            self.logger.info(
                f"Incoming file offer: {data['file_name']} ({data['file_size']} bytes)"
            )

        except Exception as e:
            self.logger.error(f"Failed to handle file offer: {str(e)}")

    async def _handle_file_chunk(self, data: Dict[str, Any]):
        """Handle incoming file chunk from a peer."""
        try:
            file_id = data["file_id"]
            if file_id not in self.active_transfers:
                self.logger.warning(f"Received chunk for unknown file: {file_id}")
                return

            metadata = self.active_transfers[file_id]

            # Decrypt the chunk
            ciphertext = bytes.fromhex(data["chunk_data"])
            chunk = self.crypto.decrypt(ciphertext, data["metadata"])

            # Write chunk to file
            with open(metadata.save_path, "ab") as f:
                f.write(chunk)

            # Update progress
            metadata.transferred_chunks += 1

            # If all chunks received, verify the file
            if metadata.transferred_chunks >= metadata.chunk_count:
                self._verify_completed_file(metadata)

        except Exception as e:
            self.logger.error(f"Failed to handle file chunk: {str(e)}")

    def _verify_completed_file(self, metadata: FileMetadata):
        """Verify the integrity of a received file."""
        try:
            # Calculate the file hash
            file_hash = self._calculate_file_hash(metadata.save_path)

            if file_hash == metadata.file_hash:
                metadata.transfer_status = FileTransferStatus.COMPLETED
                self.logger.info(f"File transfer completed and verified: {metadata.file_name}")
            else:
                metadata.transfer_status = FileTransferStatus.FAILED
                metadata.error = "File hash verification failed"
                self.logger.error(f"File hash verification failed for: {metadata.file_name}")

        except Exception as e:
            metadata.transfer_status = FileTransferStatus.FAILED
            metadata.error = f"Verification error: {str(e)}"
            self.logger.error(f"File verification failed: {str(e)}")

    async def _handle_transfer_control(self, data: Dict[str, Any]):
        """Handle transfer control messages (pause, resume, cancel)."""
        try:
            action = data.get("action")
            file_id = data.get("file_id")

            if file_id not in self.active_transfers:
                return

            metadata = self.active_transfers[file_id]

            if action == "cancel":
                metadata.transfer_status = FileTransferStatus.CANCELLED
                # TODO: Clean up any partial files

            # TODO: Implement pause/resume functionality

        except Exception as e:
            self.logger.error(f"Failed to handle transfer control: {str(e)}")
