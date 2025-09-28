"""
P2P File Transfer Module
-----------------------
Handles secure file transfers between peers using WebRTC data channels.
"""
import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Callable, BinaryIO, List, Union, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .data_channel import DataChannel
from .exceptions import FileTransferError, TransferCancelled

logger = logging.getLogger(__name__)

# File transfer protocol constants
CHUNK_SIZE = 16 * 1024  # 16KB chunks for file transfer
PROTOCOL_VERSION = "1.0"

@dataclass
class FileTransfer:
    """Represents an active file transfer."""
    file_id: str
    filename: str
    file_size: int
    mime_type: str
    file_path: Optional[Path] = None
    file_handle: Optional[BinaryIO] = None
    total_chunks: int = 0
    received_chunks: int = 0
    transferred_bytes: int = 0
    progress: float = 0.0
    status: str = "pending"  # pending, transferring, completed, failed, cancelled
    checksum: Optional[bytes] = None
    encryption_key: Optional[bytes] = None
    hmac_key: Optional[bytes] = None
    on_progress: Optional[Callable[[float], None]] = None
    on_complete: Optional[Callable[[bool], None]] = None
    on_error: Optional[Callable[[str], None]] = None
    start_time: float = field(default_factory=lambda: asyncio.get_event_loop().time())
    end_time: Optional[float] = None

    def update_progress(self, chunk_size: int) -> None:
        """Update transfer progress."""
        self.received_chunks += 1
        self.transferred_bytes += chunk_size
        self.progress = min(100.0, (self.transferred_bytes / self.file_size) * 100)
        if self.on_progress:
            self.on_progress(self.progress)
    
    def complete(self, success: bool = True) -> None:
        """Mark transfer as complete."""
        self.status = "completed" if success else "failed"
        self.end_time = asyncio.get_event_loop().time()
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
        if self.on_complete:
            self.on_complete(success)
    
    def cancel(self) -> None:
        """Cancel the transfer."""
        self.status = "cancelled"
        self.end_time = asyncio.get_event_loop().time()
        if self.file_handle:
            self.file_handle.close()
            if self.file_path and self.file_path.exists():
                try:
                    self.file_path.unlink()
                except OSError as e:
                    logger.warning(f"Error cleaning up cancelled transfer: {e}")
        if self.on_complete:
            self.on_complete(False)


class FileTransferManager:
    """Manages P2P file transfers between peers."""
    
    def __init__(self, data_channel: DataChannel, temp_dir: Optional[Path] = None):
        """Initialize the file transfer manager.
        
        Args:
            data_channel: WebRTC data channel for communication
            temp_dir: Directory to store temporary files (default: system temp)
        """
        self.data_channel = data_channel
        self.temp_dir = temp_dir or Path(os.getenv('TEMP', '/tmp')) / 'scrambled_eggs' / 'transfers'
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Active transfers (file_id -> FileTransfer)
        self.active_transfers: Dict[str, FileTransfer] = {}
        self.outgoing_transfers: Dict[str, asyncio.Future] = {}
        
        # Register message handlers
        self.data_channel.on("file_offer", self._handle_file_offer)
        self.data_channel.on("file_accept", self._handle_file_accept)
        self.data_channel.on("file_reject", self._handle_file_reject)
        self.data_channel.on("file_chunk", self._handle_file_chunk)
        self.data_channel.on("file_complete", self._handle_file_complete)
        self.data_channel.on("file_cancel", self._handle_file_cancel)
    
    # Public API
    
    async def send_file(
        self,
        file_path: Union[str, Path],
        on_progress: Optional[Callable[[float], None]] = None,
        on_complete: Optional[Callable[[bool], None]] = None,
        on_error: Optional[Callable[[str], None]] = None
    ) -> str:
        """Initiate a file transfer to the remote peer.
        
        Args:
            file_path: Path to the file to send
            on_progress: Callback for progress updates (0-100%)
            on_complete: Callback when transfer completes (success: bool)
            on_error: Callback for error messages
            
        Returns:
            File transfer ID
            
        Raises:
            FileTransferError: If the file cannot be read or transfer cannot be started
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileTransferError(f"File not found: {path}")
        
        file_id = self._generate_file_id()
        transfer = FileTransfer(
            file_id=file_id,
            filename=path.name,
            file_size=path.stat().st_size,
            mime_type=self._guess_mime_type(path),
            file_path=path,
            total_chunks=(path.stat().st_size + CHUNK_SIZE - 1) // CHUNK_SIZE,
            on_progress=on_progress,
            on_complete=on_complete,
            on_error=on_error,
            status="pending"
        )
        
        # Generate encryption keys
        transfer.encryption_key = os.urandom(32)  # AES-256
        transfer.hmac_key = os.urandom(32)  # For message authentication
        
        # Store the transfer
        self.active_transfers[file_id] = transfer
        
        # Send file offer
        try:
            await self.data_channel.send("file_offer", {
                "file_id": file_id,
                "filename": transfer.filename,
                "file_size": transfer.file_size,
                "mime_type": transfer.mime_type,
                "protocol_version": PROTOCOL_VERSION
            })
            
            # Wait for response
            future = asyncio.get_event_loop().create_future()
            self.outgoing_transfers[file_id] = future
            
            # Set a timeout for the transfer
            try:
                await asyncio.wait_for(future, timeout=60)  # 60 second timeout
                transfer.status = "transferring"
                
                # Start sending chunks
                await self._send_file_chunks(transfer)
                
            except asyncio.TimeoutError:
                raise FileTransferError("Transfer timed out waiting for response")
                
        except Exception as e:
            transfer.status = "failed"
            if file_id in self.outgoing_transfers:
                del self.outgoing_transfers[file_id]
            if file_id in self.active_transfers:
                del self.active_transfers[file_id]
            raise FileTransferError(f"Failed to initiate transfer: {e}")
        
        return file_id
    
    async def receive_file(
        self,
        file_id: str,
        save_path: Optional[Union[str, Path]] = None,
        on_progress: Optional[Callable[[float], None]] = None,
        on_complete: Optional[Callable[[bool], None]] = None,
        on_error: Optional[Callable[[str], None]] = None
    ) -> Path:
        """Accept an incoming file transfer.
        
        Args:
            file_id: ID of the file transfer to accept
            save_path: Where to save the file (default: temp directory)
            on_progress: Callback for progress updates (0-100%)
            on_complete: Callback when transfer completes (success: bool)
            on_error: Callback for error messages
            
        Returns:
            Path where the file will be saved
            
        Raises:
            FileTransferError: If the transfer cannot be accepted
        """
        if file_id not in self.active_transfers:
            raise FileTransferError(f"No active transfer with ID: {file_id}")
        
        transfer = self.active_transfers[file_id]
        
        # Determine save path
        if save_path is None:
            save_dir = self.temp_dir / "downloads"
            save_dir.mkdir(exist_ok=True)
            save_path = save_dir / transfer.filename
        
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Update transfer info
        transfer.file_path = save_path
        transfer.file_handle = open(save_path, 'wb')
        transfer.on_progress = on_progress
        transfer.on_complete = on_complete
        transfer.on_error = on_error
        transfer.status = "transferring"
        
        # Send accept message
        try:
            await self.data_channel.send("file_accept", {
                "file_id": file_id,
                "protocol_version": PROTOCOL_VERSION
            })
            
            # Create a future that will be set when transfer completes
            future = asyncio.get_event_loop().create_future()
            self.outgoing_transfers[file_id] = future
            
            # Wait for transfer to complete or fail
            try:
                await future
                return save_path
                
            except Exception as e:
                raise FileTransferError(f"Transfer failed: {e}")
                
        except Exception as e:
            transfer.status = "failed"
            if transfer.file_handle:
                transfer.file_handle.close()
                if save_path.exists():
                    try:
                        save_path.unlink()
                    except OSError:
                        pass
            raise FileTransferError(f"Failed to accept transfer: {e}")
    
    async def reject_file(self, file_id: str, reason: str = "") -> None:
        """Reject an incoming file transfer."""
        try:
            await self.data_channel.send("file_reject", {
                "file_id": file_id,
                "reason": reason
            })
        except Exception as e:
            logger.warning(f"Failed to send file rejection: {e}")
        
        # Clean up
        if file_id in self.active_transfers:
            del self.active_transfers[file_id]
    
    async def cancel_transfer(self, file_id: str) -> None:
        """Cancel an active transfer."""
        if file_id in self.active_transfers:
            transfer = self.active_transfers[file_id]
            if transfer.status in ["transferring", "pending"]:
                try:
                    await self.data_channel.send("file_cancel", {
                        "file_id": file_id
                    })
                except Exception as e:
                    logger.warning(f"Failed to send cancel message: {e}")
                
                # Clean up
                transfer.cancel()
                if file_id in self.active_transfers:
                    del self.active_transfers[file_id]
                if file_id in self.outgoing_transfers:
                    if not self.outgoing_transfers[file_id].done():
                        self.outgoing_transfers[file_id].set_exception(TransferCancelled())
                    del self.outgoing_transfers[file_id]
    
    # Internal methods
    
    async def _send_file_chunks(self, transfer: FileTransfer) -> None:
        """Send file chunks to the remote peer."""
        try:
            with open(transfer.file_path, 'rb') as f:
                chunk_index = 0
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Encrypt the chunk
                    nonce = os.urandom(12)
                    cipher = AESGCM(transfer.encryption_key)
                    encrypted_chunk = cipher.encrypt(nonce, chunk, None)
                    
                    # Add HMAC for integrity
                    h = hmac.HMAC(transfer.hmac_key, hashes.SHA256())
                    h.update(encrypted_chunk)
                    hmac_digest = h.finalize()
                    
                    # Send the chunk
                    await self.data_channel.send("file_chunk", {
                        "file_id": transfer.file_id,
                        "chunk_index": chunk_index,
                        "data": encrypted_chunk.hex(),
                        "nonce": nonce.hex(),
                        "hmac": hmac_digest.hex()
                    })
                    
                    chunk_index += 1
                    
                    # Update progress
                    transfer.update_progress(len(chunk))
                    
                    # Small delay to prevent overwhelming the channel
                    await asyncio.sleep(0.001)
            
            # Send completion message
            await self.data_channel.send("file_complete", {
                "file_id": transfer.file_id,
                "checksum": self._calculate_checksum(transfer.file_path).hex()
            })
            
            # Clean up
            transfer.complete(True)
            if transfer.file_id in self.active_transfers:
                del self.active_transfers[transfer.file_id]
            if transfer.file_id in self.outgoing_transfers:
                if not self.outgoing_transfers[transfer.file_id].done():
                    self.outgoing_transfers[transfer.file_id].set_result(True)
                del self.outgoing_transfers[transfer.file_id]
            
        except Exception as e:
            logger.error(f"Error sending file chunks: {e}", exc_info=True)
            transfer.status = "failed"
            if transfer.file_id in self.outgoing_transfers:
                if not self.outgoing_transfers[transfer.file_id].done():
                    self.outgoing_transfers[transfer.file_id].set_exception(e)
            if transfer.on_error:
                transfer.on_error(str(e))
    
    # Message handlers
    
    async def _handle_file_offer(self, data: dict, peer_id: str) -> None:
        """Handle incoming file offer."""
        file_id = data.get("file_id")
        if not file_id:
            logger.warning("Received file offer without file_id")
            return
        
        # Check if we already have a transfer with this ID
        if file_id in self.active_transfers:
            logger.warning(f"Duplicate file transfer ID: {file_id}")
            await self.reject_file(file_id, "Duplicate transfer ID")
            return
        
        # Create a new transfer record
        transfer = FileTransfer(
            file_id=file_id,
            filename=data.get("filename", "file.bin"),
            file_size=data.get("file_size", 0),
            mime_type=data.get("mime_type", "application/octet-stream"),
            status="offered"
        )
        
        self.active_transfers[file_id] = transfer
        
        # Notify the UI about the incoming file
        if hasattr(self, 'on_incoming_file'):
            await self.on_incoming_file(transfer)
    
    async def _handle_file_accept(self, data: dict, peer_id: str) -> None:
        """Handle file accept message."""
        file_id = data.get("file_id")
        if not file_id or file_id not in self.active_transfers:
            logger.warning(f"Received accept for unknown transfer: {file_id}")
            return
        
        transfer = self.active_transfers[file_id]
        if transfer.status != "pending":
            logger.warning(f"Received accept for transfer in wrong state: {transfer.status}")
            return
        
        # Start sending chunks
        asyncio.create_task(self._send_file_chunks(transfer))
    
    async def _handle_file_reject(self, data: dict, peer_id: str) -> None:
        """Handle file reject message."""
        file_id = data.get("file_id")
        reason = data.get("reason", "No reason given")
        
        if file_id in self.active_transfers:
            transfer = self.active_transfers[file_id]
            transfer.status = "rejected"
            if transfer.on_error:
                transfer.on_error(f"Transfer rejected: {reason}")
            del self.active_transfers[file_id]
        
        if file_id in self.outgoing_transfers:
            if not self.outgoing_transfers[file_id].done():
                self.outgoing_transfers[file_id].set_exception(
                    FileTransferError(f"Transfer rejected: {reason}")
                )
            del self.outgoing_transfers[file_id]
    
    async def _handle_file_chunk(self, data: dict, peer_id: str) -> None:
        """Handle incoming file chunk."""
        file_id = data.get("file_id")
        if not file_id or file_id not in self.active_transfers:
            logger.warning(f"Received chunk for unknown transfer: {file_id}")
            return
        
        transfer = self.active_transfers[file_id]
        if transfer.status != "transferring" or not transfer.file_handle:
            logger.warning(f"Received chunk for transfer in wrong state: {transfer.status}")
            return
        
        try:
            # Verify HMAC
            chunk_data = bytes.fromhex(data["data"])
            nonce = bytes.fromhex(data["nonce"])
            received_hmac = bytes.fromhex(data["hmac"])
            
            h = hmac.HMAC(transfer.hmac_key, hashes.SHA256())
            h.update(chunk_data)
            try:
                h.verify(received_hmac)
            except Exception as e:
                raise FileTransferError("HMAC verification failed") from e
            
            # Decrypt the chunk
            cipher = AESGCM(transfer.encryption_key)
            try:
                decrypted_chunk = cipher.decrypt(nonce, chunk_data, None)
            except Exception as e:
                raise FileTransferError("Decryption failed") from e
            
            # Write the chunk
            transfer.file_handle.write(decrypted_chunk)
            
            # Update progress
            transfer.update_progress(len(decrypted_chunk))
            
        except Exception as e:
            logger.error(f"Error processing file chunk: {e}", exc_info=True)
            await self.cancel_transfer(file_id)
            if transfer.on_error:
                transfer.on_error(f"Transfer failed: {e}")
    
    async def _handle_file_complete(self, data: dict, peer_id: str) -> None:
        """Handle file transfer completion."""
        file_id = data.get("file_id")
        if not file_id or file_id not in self.active_transfers:
            return
        
        transfer = self.active_transfers[file_id]
        if transfer.status != "transferring" or not transfer.file_handle:
            return
        
        # Close the file
        transfer.file_handle.close()
        transfer.file_handle = None
        
        # Verify checksum if provided
        if "checksum" in data and transfer.file_path:
            expected_checksum = bytes.fromhex(data["checksum"])
            actual_checksum = self._calculate_checksum(transfer.file_path)
            if expected_checksum != actual_checksum:
                transfer.status = "failed"
                if transfer.on_error:
                    transfer.on_error("Checksum verification failed")
                if transfer.file_path.exists():
                    try:
                        transfer.file_path.unlink()
                    except OSError:
                        pass
                return
        
        # Mark as complete
        transfer.complete(True)
        
        # Clean up
        if file_id in self.active_transfers:
            del self.active_transfers[file_id]
        if file_id in self.outgoing_transfers:
            if not self.outgoing_transfers[file_id].done():
                self.outgoing_transfers[file_id].set_result(True)
            del self.outgoing_transfers[file_id]
    
    async def _handle_file_cancel(self, data: dict, peer_id: str) -> None:
        """Handle transfer cancellation."""
        file_id = data.get("file_id")
        if not file_id:
            return
        
        if file_id in self.active_transfers:
            transfer = self.active_transfers[file_id]
            transfer.cancel()
            del self.active_transfers[file_id]
        
        if file_id in self.outgoing_transfers:
            if not self.outgoing_transfers[file_id].done():
                self.outgoing_transfers[file_id].set_exception(TransferCancelled())
            del self.outgoing_transfers[file_id]
    
    # Utility methods
    
    @staticmethod
    def _generate_file_id() -> str:
        """Generate a unique file transfer ID."""
        return hashlib.sha256(os.urandom(32)).hexdigest()
    
    @staticmethod
    def _guess_mime_type(file_path: Path) -> str:
        """Guess the MIME type of a file based on its extension."""
        # Simple MIME type mapping
        mime_types = {
            '.txt': 'text/plain',
            '.pdf': 'application/pdf',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.zip': 'application/zip',
            '.mp3': 'audio/mpeg',
            '.mp4': 'video/mp4',
            '.mov': 'video/quicktime',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            '.xls': 'application/vnd.ms-excel',
            '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            '.ppt': 'application/vnd.ms-powerpoint',
            '.pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        }
        
        ext = file_path.suffix.lower()
        return mime_types.get(ext, 'application/octet-stream')
    
    @staticmethod
    def _calculate_checksum(file_path: Path) -> bytes:
        """Calculate SHA-256 checksum of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.digest()


# Example usage:
# 
# # Sender side
# async def send_file():
#     data_channel = ...  # Get WebRTC data channel
#     ft_manager = FileTransferManager(data_channel)
#     
#     def on_progress(progress):
#         print(f"Transfer progress: {progress:.1f}%")
#     
#     def on_complete(success):
#         print(f"Transfer {'completed' if success else 'failed'}")
#     
#     try:
#         file_id = await ft_manager.send_file(
#             "/path/to/file.txt",
#             on_progress=on_progress,
#             on_complete=on_complete
#         )
#         print(f"Started transfer with ID: {file_id}")
#     except FileTransferError as e:
#         print(f"Transfer failed: {e}")
# 
# # Receiver side
# async def on_incoming_file(transfer):
#     print(f"Incoming file: {transfer.filename} ({transfer.file_size} bytes)")
#     
#     def on_progress(progress):
#         print(f"Download progress: {progress:.1f}%")
#     
#     def on_complete(success):
#         print(f"Download {'completed' if success else 'failed'}")
#     
#     try:
#         save_path = await ft_manager.receive_file(
#             transfer.file_id,
#             save_path="/downloads/" + transfer.filename,
#             on_progress=on_progress,
#             on_complete=on_complete
#         )
#         print(f"File saved to: {save_path}")
#     except FileTransferError as e:
#         print(f"Download failed: {e}")
