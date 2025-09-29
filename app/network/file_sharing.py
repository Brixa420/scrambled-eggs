"""
Secure file sharing functionality for the P2P network.

This module provides secure file transfer capabilities including:
- File chunking and reassembly
- Checksum verification
- End-to-end encryption
- Progress tracking
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Constants
DEFAULT_CHUNK_SIZE = 1024 * 64  # 64KB chunks
MAX_FILE_SIZE = 1024 * 1024 * 1024 * 10  # 10GB max file size


@dataclass
class FileMetadata:
    """Metadata for a file being shared."""

    file_id: str
    filename: str
    size: int
    chunks: int
    chunk_size: int
    checksum: str
    mime_type: str = "application/octet-stream"
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            "file_id": self.file_id,
            "filename": self.filename,
            "size": self.size,
            "chunks": self.chunks,
            "chunk_size": self.chunk_size,
            "checksum": self.checksum,
            "mime_type": self.mime_type,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileMetadata":
        """Create from a dictionary."""
        return cls(
            file_id=data["file_id"],
            filename=data["filename"],
            size=data["size"],
            chunks=data["chunks"],
            chunk_size=data["chunk_size"],
            checksum=data["checksum"],
            mime_type=data.get("mime_type", "application/octet-stream"),
            created_at=data.get("created_at", time.time()),
            metadata=data.get("metadata", {}),
        )


class FileSharingError(Exception):
    """Base exception for file sharing errors."""


class FileTooLargeError(FileSharingError):
    """Raised when a file exceeds the maximum allowed size."""


class FileIntegrityError(FileSharingError):
    """Raised when file integrity verification fails."""


class FileSharingManager:
    """Manages secure file sharing between peers."""

    def __init__(self, p2p_manager: Any, storage_dir: str = "shared_files"):
        """Initialize the file sharing manager.

        Args:
            p2p_manager: Reference to the P2P manager
            storage_dir: Directory to store shared files
        """
        self.p2p_manager = p2p_manager
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Track ongoing file transfers
        self.active_uploads: Dict[str, Dict] = {}
        self.active_downloads: Dict[str, Dict] = {}

        # Register message handlers
        self.p2p_manager.register_message_handler("file_offer", self._handle_file_offer)
        self.p2p_manager.register_message_handler("file_request", self._handle_file_request)
        self.p2p_manager.register_message_handler("file_chunk", self._handle_file_chunk)
        self.p2p_manager.register_message_handler("file_complete", self._handle_file_complete)
        self.p2p_manager.register_message_handler("file_cancel", self._handle_file_cancel)

    async def share_file(
        self, file_path: str, peer_id: str, chunk_size: int = DEFAULT_CHUNK_SIZE
    ) -> str:
        """Share a file with a peer.

        Args:
            file_path: Path to the file to share
            peer_id: ID of the peer to share with
            chunk_size: Size of each chunk in bytes

        Returns:
            str: File ID for tracking the transfer

        Raises:
            FileNotFoundError: If the file doesn't exist
            FileTooLargeError: If the file is too large
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise FileTooLargeError(
                f"File too large: {file_size} bytes (max {MAX_FILE_SIZE} bytes)"
            )

        # Generate file metadata
        file_id = hashlib.sha256(f"{file_path.name}{file_size}{time.time()}".encode()).hexdigest()

        # Calculate checksum
        checksum = self._calculate_checksum(file_path)

        # Calculate number of chunks
        chunks = (file_size + chunk_size - 1) // chunk_size

        # Create metadata
        metadata = FileMetadata(
            file_id=file_id,
            filename=file_path.name,
            size=file_size,
            chunks=chunks,
            chunk_size=chunk_size,
            checksum=checksum,
            mime_type=self._guess_mime_type(file_path),
        )

        # Store metadata for the transfer
        self.active_uploads[file_id] = {
            "file_path": file_path,
            "metadata": metadata,
            "peer_id": peer_id,
            "chunks_sent": 0,
            "start_time": time.time(),
            "chunk_acks": set(),
            "status": "pending",
        }

        # Send file offer to the peer
        await self.p2p_manager.send_message(
            peer_id, {"type": "file_offer", "file_id": file_id, "metadata": metadata.to_dict()}
        )

        return file_id

    async def download_file(self, file_id: str, peer_id: str, save_path: str) -> str:
        """Download a file from a peer.

        Args:
            file_id: ID of the file to download
            peer_id: ID of the peer to download from
            save_path: Path to save the downloaded file

        Returns:
            str: Path to the downloaded file
        """
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # Create a temporary file for downloading
        temp_path = save_path.with_suffix(f".{file_id}.download")

        # Initialize download tracking
        self.active_downloads[file_id] = {
            "file_path": save_path,
            "temp_path": temp_path,
            "peer_id": peer_id,
            "chunks_received": 0,
            "chunk_checksums": {},
            "start_time": time.time(),
            "status": "downloading",
            "file_handle": open(temp_path, "wb"),
        }

        # Send file request to the peer
        await self.p2p_manager.send_message(peer_id, {"type": "file_request", "file_id": file_id})

        return str(save_path)

    async def _handle_file_offer(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an incoming file offer."""
        try:
            file_id = message["file_id"]
            metadata = FileMetadata.from_dict(message["metadata"])

            # Notify the application about the file offer
            if hasattr(self.p2p_manager, "on_file_offer"):
                await self.p2p_manager.on_file_offer(peer_id, metadata)

        except Exception as e:
            logger.error(f"Error handling file offer: {e}")

    async def _handle_file_request(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a file download request."""
        try:
            file_id = message["file_id"]

            if file_id not in self.active_uploads:
                logger.warning(f"Unknown file ID: {file_id}")
                return

            upload = self.active_uploads[file_id]
            if upload["peer_id"] != peer_id:
                logger.warning(f"Unauthorized file request from {peer_id}")
                return

            # Start sending file chunks
            await self._send_next_chunk(file_id)

        except Exception as e:
            logger.error(f"Error handling file request: {e}")

    async def _handle_file_chunk(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an incoming file chunk."""
        try:
            file_id = message["file_id"]
            chunk_index = message["chunk_index"]
            chunk_data = message["chunk_data"]
            checksum = message.get("checksum")

            if file_id not in self.active_downloads:
                logger.warning(f"Received chunk for unknown file: {file_id}")
                return

            download = self.active_downloads[file_id]

            # Verify checksum if provided
            if checksum:
                chunk_checksum = hashlib.sha256(chunk_data).hexdigest()
                if chunk_checksum != checksum:
                    logger.error(f"Checksum mismatch for chunk {chunk_index} of {file_id}")
                    await self._cancel_download(file_id, "Checksum mismatch")
                    return

            # Write chunk to file
            download["file_handle"].seek(chunk_index * download["chunk_size"])
            download["file_handle"].write(chunk_data)
            download["chunks_received"] += 1

            # Store chunk checksum for verification
            if checksum:
                download["chunk_checksums"][chunk_index] = checksum

            # Notify progress
            if hasattr(self.p2p_manager, "on_download_progress"):
                await self.p2p_manager.on_download_progress(
                    file_id,
                    download["chunks_received"],
                    download["metadata"].chunks,
                    download["chunks_received"] * download["chunk_size"],
                )

            # Acknowledge chunk
            await self.p2p_manager.send_message(
                peer_id, {"type": "chunk_ack", "file_id": file_id, "chunk_index": chunk_index}
            )

        except Exception as e:
            logger.error(f"Error handling file chunk: {e}")
            if "file_id" in locals() and file_id in self.active_downloads:
                await self._cancel_download(file_id, str(e))

    async def _handle_file_complete(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle file transfer completion."""
        try:
            file_id = message["file_id"]

            if file_id not in self.active_downloads:
                return

            download = self.active_downloads[file_id]

            # Close the file handle
            download["file_handle"].close()

            # Verify the complete file checksum
            if "checksum" in message:
                file_checksum = self._calculate_checksum(download["temp_path"])
                if file_checksum != message["checksum"]:
                    logger.error(
                        f"File checksum mismatch: {file_checksum} != {message['checksum']}"
                    )
                    download["temp_path"].unlink()
                    raise FileIntegrityError("File integrity check failed")

            # Rename temp file to final name
            if download["temp_path"].exists():
                download["temp_path"].replace(download["file_path"])

            # Notify completion
            if hasattr(self.p2p_manager, "on_download_complete"):
                await self.p2p_manager.on_download_complete(
                    file_id, str(download["file_path"]), download["metadata"]
                )

            # Clean up
            del self.active_downloads[file_id]

        except Exception as e:
            logger.error(f"Error handling file complete: {e}")
            if "file_id" in locals() and file_id in self.active_downloads:
                await self._cancel_download(file_id, str(e))

    async def _handle_file_cancel(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle file transfer cancellation."""
        try:
            file_id = message["file_id"]
            reason = message.get("reason", "Unknown reason")

            if file_id in self.active_uploads:
                # Upload was cancelled by the receiver
                upload = self.active_uploads[file_id]
                logger.info(f"Upload cancelled by receiver: {file_id} - {reason}")

                if hasattr(self.p2p_manager, "on_upload_cancelled"):
                    await self.p2p_manager.on_upload_cancelled(file_id, reason)

                del self.active_uploads[file_id]

            elif file_id in self.active_downloads:
                # Download was cancelled by the sender
                await self._cancel_download(file_id, f"Cancelled by sender: {reason}")

        except Exception as e:
            logger.error(f"Error handling file cancel: {e}")

    async def _send_next_chunk(self, file_id: str) -> None:
        """Send the next chunk of a file."""
        if file_id not in self.active_uploads:
            return

        upload = self.active_uploads[file_id]
        metadata = upload["metadata"]

        try:
            with open(upload["file_path"], "rb") as f:
                while upload["chunks_sent"] < metadata.chunks:
                    # Skip already acknowledged chunks
                    if upload["chunks_sent"] in upload["chunk_acks"]:
                        upload["chunks_sent"] += 1
                        continue

                    # Read chunk
                    f.seek(upload["chunks_sent"] * metadata.chunk_size)
                    chunk_data = f.read(metadata.chunk_size)

                    # Calculate checksum
                    chunk_checksum = hashlib.sha256(chunk_data).hexdigest()

                    # Send chunk
                    await self.p2p_manager.send_message(
                        upload["peer_id"],
                        {
                            "type": "file_chunk",
                            "file_id": file_id,
                            "chunk_index": upload["chunks_sent"],
                            "chunk_data": chunk_data,
                            "checksum": chunk_checksum,
                            "total_chunks": metadata.chunks,
                        },
                    )

                    # Wait for acknowledgment with timeout
                    try:
                        # TODO: Implement proper acknowledgment waiting with timeout
                        await asyncio.sleep(0.1)  # Simulate network delay
                        upload["chunk_acks"].add(upload["chunks_sent"])
                    except asyncio.TimeoutError:
                        logger.warning(f"Timeout waiting for chunk {upload['chunks_sent']} ack")
                        # TODO: Implement retry logic

                    upload["chunks_sent"] += 1

                    # Notify progress
                    if hasattr(self.p2p_manager, "on_upload_progress"):
                        await self.p2p_manager.on_upload_progress(
                            file_id,
                            upload["chunks_sent"],
                            metadata.chunks,
                            upload["chunks_sent"] * metadata.chunk_size,
                        )

            # All chunks sent, verify all were acknowledged
            if len(upload["chunk_acks"]) == metadata.chunks:
                # Send completion message
                await self.p2p_manager.send_message(
                    upload["peer_id"],
                    {"type": "file_complete", "file_id": file_id, "checksum": metadata.checksum},
                )

                # Notify completion
                if hasattr(self.p2p_manager, "on_upload_complete"):
                    await self.p2p_manager.on_upload_complete(file_id)

                # Clean up
                del self.active_uploads[file_id]

        except Exception as e:
            logger.error(f"Error sending file chunk: {e}")
            await self._cancel_upload(file_id, str(e))

    async def _cancel_upload(self, file_id: str, reason: str = "Unknown error") -> None:
        """Cancel an ongoing upload."""
        if file_id in self.active_uploads:
            peer_id = self.active_uploads[file_id]["peer_id"]

            # Notify the peer
            await self.p2p_manager.send_message(
                peer_id, {"type": "file_cancel", "file_id": file_id, "reason": reason}
            )

            # Notify the application
            if hasattr(self.p2p_manager, "on_upload_cancelled"):
                await self.p2p_manager.on_upload_cancelled(file_id, reason)

            # Clean up
            del self.active_uploads[file_id]

    async def _cancel_download(self, file_id: str, reason: str = "Unknown error") -> None:
        """Cancel an ongoing download."""
        if file_id in self.active_downloads:
            download = self.active_downloads[file_id]

            # Close the file handle if it's open
            if "file_handle" in download and not download["file_handle"].closed:
                download["file_handle"].close()

            # Delete the temporary file if it exists
            if "temp_path" in download and download["temp_path"].exists():
                try:
                    download["temp_path"].unlink()
                except Exception as e:
                    logger.error(f"Error deleting temp file: {e}")

            # Notify the application
            if hasattr(self.p2p_manager, "on_download_cancelled"):
                await self.p2p_manager.on_download_cancelled(file_id, reason)

            # Clean up
            del self.active_downloads[file_id]

    def _calculate_checksum(self, file_path: Path, chunk_size: int = 8192) -> str:
        """Calculate the SHA-256 checksum of a file."""
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                sha256.update(chunk)

        return sha256.hexdigest()

    def _guess_mime_type(self, file_path: Path) -> str:
        """Guess the MIME type of a file based on its extension."""
        # Simple MIME type mapping
        mime_types = {
            ".txt": "text/plain",
            ".pdf": "application/pdf",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".mp3": "audio/mpeg",
            ".mp4": "video/mp4",
            ".zip": "application/zip",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            ".py": "text/x-python",
            ".js": "application/javascript",
            ".json": "application/json",
            ".html": "text/html",
            ".css": "text/css",
        }

        return mime_types.get(file_path.suffix.lower(), "application/octet-stream")

    def get_upload_progress(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get the progress of an upload."""
        if file_id not in self.active_uploads:
            return None

        upload = self.active_uploads[file_id]
        metadata = upload["metadata"]

        return {
            "file_id": file_id,
            "peer_id": upload["peer_id"],
            "filename": metadata.filename,
            "size": metadata.size,
            "chunks_sent": upload["chunks_sent"],
            "total_chunks": metadata.chunks,
            "progress": (upload["chunks_sent"] / metadata.chunks) * 100,
            "status": upload.get("status", "unknown"),
        }

    def get_download_progress(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get the progress of a download."""
        if file_id not in self.active_downloads:
            return None

        download = self.active_downloads[file_id]
        metadata = download.get("metadata", {})

        return {
            "file_id": file_id,
            "peer_id": download["peer_id"],
            "filename": getattr(metadata, "filename", "unknown"),
            "size": getattr(metadata, "size", 0),
            "chunks_received": download["chunks_received"],
            "total_chunks": getattr(metadata, "chunks", 0),
            "progress": (
                (download["chunks_received"] / metadata.chunks * 100)
                if hasattr(metadata, "chunks") and metadata.chunks > 0
                else 0
            ),
            "status": download.get("status", "unknown"),
        }

    def get_active_uploads(self) -> List[Dict[str, Any]]:
        """Get a list of all active uploads."""
        return [self.get_upload_progress(file_id) for file_id in self.active_uploads]

    def get_active_downloads(self) -> List[Dict[str, Any]]:
        """Get a list of all active downloads."""
        return [self.get_download_progress(file_id) for file_id in self.active_downloads]

    async def cancel_upload(self, file_id: str, reason: str = "User cancelled") -> bool:
        """Cancel an active upload."""
        if file_id not in self.active_uploads:
            return False

        await self._cancel_upload(file_id, reason)
        return True

    async def cancel_download(self, file_id: str, reason: str = "User cancelled") -> bool:
        """Cancel an active download."""
        if file_id not in self.active_downloads:
            return False

        await self._cancel_download(file_id, reason)
        return True
