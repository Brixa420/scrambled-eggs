"""
File transfer manager for secure file sharing in Scrambled Eggs.
"""

import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple, Union

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.core.config import get_config
from app.crypto.scrambled_eggs_encryption import ScrambledEggsEncryption

logger = logging.getLogger(__name__)

# File chunk size for transfer (1MB)
CHUNK_SIZE = 1024 * 1024


@dataclass
class FileMetadata:
    """Metadata for a file being transferred."""

    file_id: str
    file_name: str
    file_size: int
    file_hash: str
    mime_type: str
    chunk_count: int
    chunk_size: int = CHUNK_SIZE
    is_encrypted: bool = True
    encryption_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    hmac_key: Optional[bytes] = None
    metadata_encrypted: bool = False
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


class FileTransferManager:
    """Manages secure file transfers between peers."""

    def __init__(self, app_manager: Any = None):
        """Initialize the file transfer manager."""
        self.app_manager = app_manager
        self.config = get_config()
        self.encryption = ScrambledEggsEncryption()

        # Active transfers (incoming and outgoing)
        self.active_transfers: Dict[str, FileTransfer] = {}

        # Temporary storage for file chunks
        self.temp_dir = Path(tempfile.gettempdir()) / "scrambled_eggs" / "transfers"
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        # Callbacks
        self.progress_callbacks: Dict[str, Callable] = {}
        self.completion_callbacks: Dict[str, Callable] = {}
        self.error_callbacks: Dict[str, Callable] = {}

    async def prepare_file_for_sending(
        self,
        file_path: Union[str, Path],
        recipient_public_key: bytes,
        custom_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[FileMetadata, bytes]:
        """
        Prepare a file for secure transfer.

        Args:
            file_path: Path to the file to send
            recipient_public_key: Recipient's public key for encryption
            custom_metadata: Additional metadata to include

        Returns:
            Tuple of (file_metadata, encrypted_metadata)
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # Generate a unique file ID
        file_id = self._generate_file_id(file_path)

        # Calculate file hash
        file_hash = self._calculate_file_hash(file_path)

        # Get file metadata
        file_size = file_path.stat().st_size
        chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        # Generate encryption keys
        encryption_key = os.urandom(32)  # AES-256
        hmac_key = os.urandom(32)  # HMAC-SHA256
        iv = os.urandom(16)  # IV for AES-GCM

        # Create file metadata
        metadata = FileMetadata(
            file_id=file_id,
            file_name=file_path.name,
            file_size=file_size,
            file_hash=file_hash.hex(),
            mime_type=self._guess_mime_type(file_path),
            chunk_count=chunk_count,
            chunk_size=CHUNK_SIZE,
            is_encrypted=True,
            encryption_key=encryption_key,
            iv=iv,
            hmac_key=hmac_key,
            custom_metadata=custom_metadata or {},
        )

        # Encrypt the metadata
        encrypted_metadata = self._encrypt_metadata(metadata, recipient_public_key)

        # Create a transfer object
        transfer = FileTransfer(
            transfer_id=file_id,
            file_path=file_path,
            metadata=metadata,
            direction="outgoing",
            status="preparing",
        )

        # Store the transfer
        self.active_transfers[file_id] = transfer

        return metadata, encrypted_metadata

    async def prepare_file_receiving(
        self, metadata: FileMetadata, save_directory: Union[str, Path]
    ) -> str:
        """
        Prepare to receive a file.

        Args:
            metadata: File metadata
            save_directory: Directory to save the received file

        Returns:
            Transfer ID
        """
        save_directory = Path(save_directory)
        save_directory.mkdir(parents=True, exist_ok=True)

        # Create a temporary file for receiving
        temp_file = self.temp_dir / f"{metadata.file_id}.part"
        temp_file.touch()

        # Create a transfer object
        transfer = FileTransfer(
            transfer_id=metadata.file_id,
            file_path=save_directory / metadata.file_name,
            temp_path=temp_file,
            metadata=metadata,
            direction="incoming",
            status="receiving",
        )

        # Store the transfer
        self.active_transfers[metadata.file_id] = transfer

        return metadata.file_id

    async def process_incoming_chunk(
        self, file_id: str, chunk_index: int, chunk_data: bytes
    ) -> bool:
        """
        Process an incoming file chunk.

        Args:
            file_id: ID of the file transfer
            chunk_index: Index of the chunk
            chunk_data: Chunk data (encrypted)

        Returns:
            True if the chunk was processed successfully
        """
        if file_id not in self.active_transfers:
            logger.error(f"Unknown file transfer: {file_id}")
            return False

        transfer = self.active_transfers[file_id]

        try:
            # Verify chunk index
            if chunk_index < 0 or chunk_index >= transfer.metadata.chunk_count:
                raise ValueError(f"Invalid chunk index: {chunk_index}")

            # Verify chunk size (except possibly the last chunk)
            if (
                chunk_index < transfer.metadata.chunk_count - 1
                and len(chunk_data) != transfer.metadata.chunk_size
            ):
                raise ValueError(f"Invalid chunk size: {len(chunk_data)} bytes")

            # Decrypt the chunk if needed
            if transfer.metadata.is_encrypted and transfer.metadata.encryption_key:
                chunk_data = self._decrypt_chunk(
                    chunk_data, transfer.metadata.encryption_key, transfer.metadata.iv, chunk_index
                )

            # Write the chunk to the temporary file
            with open(transfer.temp_path, "r+b") as f:
                f.seek(chunk_index * transfer.metadata.chunk_size)
                f.write(chunk_data)

            # Update transfer progress
            transfer.received_chunks.add(chunk_index)
            transfer.bytes_received += len(chunk_data)

            # Call progress callback if registered
            if file_id in self.progress_callbacks:
                progress = (len(transfer.received_chunks) / transfer.metadata.chunk_count) * 100
                await self.progress_callbacks[file_id](file_id, progress)

            # Check if transfer is complete
            if len(transfer.received_chunks) == transfer.metadata.chunk_count:
                await self._finalize_received_file(transfer)

            return True

        except Exception as e:
            logger.error(f"Error processing chunk {chunk_index} for {file_id}: {e}")
            if file_id in self.error_callbacks:
                await self.error_callbacks[file_id](file_id, str(e))
            return False

    async def get_next_chunk(self, file_id: str, chunk_index: int) -> Optional[bytes]:
        """
        Get the next chunk of a file for sending.

        Args:
            file_id: ID of the file transfer
            chunk_index: Index of the chunk to retrieve

        Returns:
            Chunk data (encrypted) or None if transfer is complete
        """
        if file_id not in self.active_transfers:
            logger.error(f"Unknown file transfer: {file_id}")
            return None

        transfer = self.active_transfers[file_id]

        try:
            # Check if transfer is complete
            if chunk_index >= transfer.metadata.chunk_count:
                return None

            # Read the chunk from the file
            with open(transfer.file_path, "rb") as f:
                f.seek(chunk_index * transfer.metadata.chunk_size)
                chunk_data = f.read(transfer.metadata.chunk_size)

            # Encrypt the chunk if needed
            if transfer.metadata.is_encrypted and transfer.metadata.encryption_key:
                chunk_data = self._encrypt_chunk(
                    chunk_data, transfer.metadata.encryption_key, transfer.metadata.iv, chunk_index
                )

            # Update transfer progress
            transfer.sent_chunks.add(chunk_index)
            transfer.bytes_sent += len(chunk_data)

            # Call progress callback if registered
            if file_id in self.progress_callbacks:
                progress = (len(transfer.sent_chunks) / transfer.metadata.chunk_count) * 100
                await self.progress_callbacks[file_id](file_id, progress)

            return chunk_data

        except Exception as e:
            logger.error(f"Error reading chunk {chunk_index} for {file_id}: {e}")
            if file_id in self.error_callbacks:
                await self.error_callbacks[file_id](file_id, str(e))
            return None

    def register_progress_callback(
        self, file_id: str, callback: Callable[[str, float], Awaitable[None]]
    ):
        """Register a progress callback for a file transfer."""
        self.progress_callbacks[file_id] = callback

    def register_completion_callback(
        self, file_id: str, callback: Callable[[str, Path], Awaitable[None]]
    ):
        """Register a completion callback for a file transfer."""
        self.completion_callbacks[file_id] = callback

    def register_error_callback(
        self, file_id: str, callback: Callable[[str, str], Awaitable[None]]
    ):
        """Register an error callback for a file transfer."""
        self.error_callbacks[file_id] = callback

    def cancel_transfer(self, file_id: str):
        """Cancel an active file transfer."""
        if file_id in self.active_transfers:
            transfer = self.active_transfers[file_id]

            # Clean up temporary files
            if transfer.temp_path and transfer.temp_path.exists():
                try:
                    transfer.temp_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete temporary file {transfer.temp_path}: {e}")

            # Remove from active transfers
            del self.active_transfers[file_id]

            # Remove callbacks
            self.progress_callbacks.pop(file_id, None)
            self.completion_callbacks.pop(file_id, None)
            self.error_callbacks.pop(file_id, None)

    async def _finalize_received_file(self, transfer: "FileTransfer") -> bool:
        """Finalize a received file."""
        try:
            # Verify the file hash
            file_hash = self._calculate_file_hash(transfer.temp_path)
            if file_hash.hex() != transfer.metadata.file_hash:
                raise ValueError("File hash does not match")

            # Move the temporary file to its final location
            final_path = transfer.file_path

            # Handle filename conflicts
            counter = 1
            while final_path.exists():
                name_parts = final_path.stem.split("_")
                if name_parts[-1].isdigit() and len(name_parts) > 1:
                    base_name = "_".join(name_parts[:-1])
                    counter = int(name_parts[-1]) + 1
                else:
                    base_name = final_path.stem

                final_path = final_path.with_name(f"{base_name}_{counter}{final_path.suffix}")
                counter += 1

            # Create parent directories if they don't exist
            final_path.parent.mkdir(parents=True, exist_ok=True)

            # Move the file
            transfer.temp_path.rename(final_path)

            # Update the transfer object
            transfer.file_path = final_path
            transfer.status = "completed"

            # Call completion callback if registered
            if transfer.transfer_id in self.completion_callbacks:
                await self.completion_callbacks[transfer.transfer_id](
                    transfer.transfer_id, final_path
                )

            # Clean up
            self.cancel_transfer(transfer.transfer_id)

            return True

        except Exception as e:
            logger.error(f"Error finalizing received file {transfer.transfer_id}: {e}")
            if transfer.transfer_id in self.error_callbacks:
                await self.error_callbacks[transfer.transfer_id](
                    transfer.transfer_id, f"Failed to finalize file: {e}"
                )
            return False

    def _generate_file_id(self, file_path: Path) -> str:
        """Generate a unique file ID."""
        # Use file metadata and current time to generate a unique ID
        stat = file_path.stat()
        unique_str = f"{file_path.name}_{stat.st_size}_{stat.st_mtime_ns}_{os.urandom(8).hex()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()

    def _calculate_file_hash(self, file_path: Path) -> bytes:
        """Calculate the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                data = f.read(65536)  # 64KB chunks
                if not data:
                    break
                sha256.update(data)

        return sha256.digest()

    def _guess_mime_type(self, file_path: Path) -> str:
        """Guess the MIME type of a file."""
        import mimetypes

        mime_type, _ = mimetypes.guess_type(file_path)
        return mime_type or "application/octet-stream"

    def _encrypt_metadata(self, metadata: FileMetadata, public_key: bytes) -> bytes:
        """Encrypt file metadata."""
        # Convert metadata to JSON
        metadata_dict = {
            "file_id": metadata.file_id,
            "file_name": metadata.file_name,
            "file_size": metadata.file_size,
            "file_hash": metadata.file_hash,
            "mime_type": metadata.mime_type,
            "chunk_count": metadata.chunk_count,
            "chunk_size": metadata.chunk_size,
            "is_encrypted": metadata.is_encrypted,
            "custom_metadata": metadata.custom_metadata,
        }

        metadata_json = json.dumps(metadata_dict).encode("utf-8")

        # Encrypt the metadata using the recipient's public key
        key = serialization.load_pem_public_key(public_key)
        encrypted = key.encrypt(
            metadata_json,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return encrypted

    def _decrypt_metadata(self, encrypted_metadata: bytes, private_key: bytes) -> FileMetadata:
        """Decrypt file metadata."""
        # Decrypt the metadata using the private key
        key = serialization.load_pem_private_key(private_key, password=None)

        try:
            metadata_json = key.decrypt(
                encrypted_metadata,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            metadata_dict = json.loads(metadata_json.decode("utf-8"))

            # Create a FileMetadata object
            return FileMetadata(
                file_id=metadata_dict["file_id"],
                file_name=metadata_dict["file_name"],
                file_size=metadata_dict["file_size"],
                file_hash=metadata_dict["file_hash"],
                mime_type=metadata_dict["mime_type"],
                chunk_count=metadata_dict["chunk_count"],
                chunk_size=metadata_dict["chunk_size"],
                is_encrypted=metadata_dict["is_encrypted"],
                custom_metadata=metadata_dict.get("custom_metadata", {}),
            )

        except Exception as e:
            logger.error(f"Failed to decrypt metadata: {e}")
            raise ValueError("Invalid or corrupted metadata") from e

    def _encrypt_chunk(self, data: bytes, key: bytes, iv: bytes, chunk_index: int) -> bytes:
        """Encrypt a file chunk."""
        # Use AES-GCM for authenticated encryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv + chunk_index.to_bytes(4, "big")),
            backend=default_backend(),
        )

        encryptor = cipher.encryptor()

        # Pad the data if needed
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return the ciphertext with the authentication tag
        return ciphertext + encryptor.tag

    def _decrypt_chunk(self, data: bytes, key: bytes, iv: bytes, chunk_index: int) -> bytes:
        """Decrypt a file chunk."""
        # Extract the authentication tag (last 16 bytes)
        if len(data) < 16:
            raise ValueError("Chunk is too short to contain authentication tag")

        ciphertext = data[:-16]
        tag = data[-16:]

        # Use AES-GCM for authenticated decryption
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv + chunk_index.to_bytes(4, "big"), tag=tag),
            backend=default_backend(),
        )

        decryptor = cipher.decryptor()

        try:
            # Decrypt the data
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad the data
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption failed: invalid or corrupted data") from e


@dataclass
class FileTransfer:
    """Represents an active file transfer."""

    transfer_id: str
    file_path: Path
    metadata: FileMetadata
    direction: str  # 'incoming' or 'outgoing'
    status: str  # 'preparing', 'transferring', 'paused', 'completed', 'error'
    temp_path: Optional[Path] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    sent_chunks: set = field(default_factory=set)
    received_chunks: set = field(default_factory=set)
    error: Optional[str] = None
    start_time: float = field(default_factory=lambda: time.time())
    end_time: Optional[float] = None

    def __post_init__(self):
        """Initialize the transfer."""
        if self.temp_path is None and self.direction == "incoming":
            self.temp_path = Path(tempfile.mktemp(prefix=f"scrambled_eggs_{self.transfer_id}_"))

    @property
    def progress(self) -> float:
        """Get the transfer progress as a percentage."""
        if self.direction == "outgoing":
            total = self.metadata.file_size
            current = self.bytes_sent
        else:
            total = self.metadata.file_size
            current = self.bytes_received

        if total == 0:
            return 0.0

        return min(100.0, (current / total) * 100)

    @property
    def speed(self) -> float:
        """Get the current transfer speed in bytes per second."""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0

        if self.direction == "outgoing":
            return self.bytes_sent / elapsed
        else:
            return self.bytes_received / elapsed

    @property
    def time_remaining(self) -> Optional[float]:
        """Get the estimated time remaining in seconds."""
        if self.progress >= 100:
            return 0.0

        speed = self.speed
        if speed == 0:
            return None

        if self.direction == "outgoing":
            remaining_bytes = self.metadata.file_size - self.bytes_sent
        else:
            remaining_bytes = self.metadata.file_size - self.bytes_received

        return remaining_bytes / speed

    def pause(self):
        """Pause the transfer."""
        self.status = "paused"

    def resume(self):
        """Resume the transfer."""
        if self.status == "paused":
            self.status = "transferring"

    def cancel(self):
        """Cancel the transfer."""
        self.status = "cancelled"
        self.end_time = time.time()

        # Clean up temporary files
        if self.temp_path and self.temp_path.exists():
            try:
                self.temp_path.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete temporary file {self.temp_path}: {e}")

    def complete(self):
        """Mark the transfer as complete."""
        self.status = "completed"
        self.end_time = time.time()

        # Finalize the file if this was an incoming transfer
        if self.direction == "incoming" and self.temp_path and self.temp_path.exists():
            try:
                # Ensure the target directory exists
                self.file_path.parent.mkdir(parents=True, exist_ok=True)

                # Move the temporary file to its final location
                self.temp_path.rename(self.file_path)
            except Exception as e:
                logger.error(f"Failed to finalize file {self.file_path}: {e}")
                self.status = "error"
                self.error = f"Failed to finalize file: {e}"

    def fail(self, error: str):
        """Mark the transfer as failed."""
        self.status = "error"
        self.error = error
        self.end_time = time.time()

        # Clean up temporary files
        if self.temp_path and self.temp_path.exists():
            try:
                self.temp_path.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete temporary file {self.temp_path}: {e}")


# Helper function to format file size
def format_file_size(size_bytes: int) -> str:
    """Format a file size in a human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


# Helper function to format transfer speed
def format_speed(speed: float) -> str:
    """Format a transfer speed in a human-readable format."""
    for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
        if speed < 1024.0:
            return f"{speed:.1f} {unit}"
        speed /= 1024.0
    return f"{speed:.1f} TB/s"


# Helper function to format time
def format_time(seconds: float) -> str:
    """Format a time duration in a human-readable format."""
    if seconds is None:
        return "Calculating..."

    seconds = int(seconds)
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60

    if hours > 0:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    elif minutes > 0:
        return f"{minutes}m {seconds:02d}s"
    else:
        return f"{seconds}s"
