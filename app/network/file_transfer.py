"""
File transfer utilities for P2P communication.

This module provides functionality for transferring files over P2P connections
using chunking, checksums, and resumable transfers.
"""

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Set, Tuple, Union

from ..core.crypto import CryptoEngine
from .data_channels import ChannelType, DataChannelManager, Message

logger = logging.getLogger(__name__)

# Default chunk size (64KB)
DEFAULT_CHUNK_SIZE = 64 * 1024

# File transfer protocol message types
class FileTransferMessageType(str, Enum):
    """Types of file transfer control messages."""
    # Client -> Server
    REQUEST = "request"          # Request to start a file transfer
    CHUNK_REQUEST = "chunk_req"  # Request a specific chunk
    CANCEL = "cancel"            # Cancel an in-progress transfer
    
    # Server -> Client
    METADATA = "metadata"        # File metadata (size, name, etc.)
    CHUNK = "chunk"              # A chunk of file data
    COMPLETE = "complete"        # Transfer complete
    ERROR = "error"              # Error occurred


@dataclass
class FileMetadata:
    """Metadata for a file being transferred."""
    file_id: str
    filename: str
    size: int
    mime_type: str = "application/octet-stream"
    chunks: int = 0
    chunk_size: int = DEFAULT_CHUNK_SIZE
    checksum: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a dictionary."""
        return {
            "file_id": self.file_id,
            "filename": self.filename,
            "size": self.size,
            "mime_type": self.mime_type,
            "chunks": self.chunks,
            "chunk_size": self.chunk_size,
            "checksum": self.checksum,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileMetadata':
        """Create metadata from a dictionary."""
        return cls(
            file_id=data["file_id"],
            filename=data["filename"],
            size=data["size"],
            mime_type=data.get("mime_type", "application/octet-stream"),
            chunks=data["chunks"],
            chunk_size=data.get("chunk_size", DEFAULT_CHUNK_SIZE),
            checksum=data.get("checksum", ""),
            metadata=data.get("metadata", {}),
        )


@dataclass
class TransferProgress:
    """Tracks the progress of a file transfer."""
    file_id: str
    total_chunks: int
    received_chunks: Set[int] = field(default_factory=set)
    start_time: float = field(default_factory=time.time)
    
    @property
    def is_complete(self) -> bool:
        """Check if the transfer is complete."""
        return len(self.received_chunks) >= self.total_chunks
    
    @property
    def progress(self) -> float:
        """Get the transfer progress as a percentage."""
        if self.total_chunks == 0:
            return 0.0
        return (len(self.received_chunks) / self.total_chunks) * 100
    
    @property
    def transfer_rate(self) -> float:
        """Get the transfer rate in bytes per second."""
        elapsed = time.time() - self.start_time
        if elapsed == 0:
            return 0.0
        return (len(self.received_chunks) * DEFAULT_CHUNK_SIZE) / elapsed


class FileTransferError(Exception):
    """Base class for file transfer errors."""
    pass


class FileTransferManager:
    """Manages file transfers over P2P connections."""
    
    def __init__(
        self,
        data_manager: DataChannelManager,
        crypto_engine: Optional[CryptoEngine] = None,
        download_dir: Union[str, Path] = "downloads",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        """Initialize the file transfer manager.
        
        Args:
            data_manager: DataChannelManager instance for sending/receiving data
            crypto_engine: Optional CryptoEngine for encrypting/decrypting file data
            download_dir: Directory to save downloaded files
            chunk_size: Size of each file chunk in bytes
        """
        self.data_manager = data_manager
        self.crypto = crypto_engine or CryptoEngine()
        self.download_dir = Path(download_dir)
        self.chunk_size = chunk_size
        
        # Ensure download directory exists
        self.download_dir.mkdir(parents=True, exist_ok=True)
        
        # Active transfers
        self.active_transfers: Dict[str, TransferProgress] = {}
        self.file_metadata: Dict[str, FileMetadata] = {}
        
        # Buffer for incoming chunks
        self.chunk_buffers: Dict[str, Dict[int, bytes]] = {}
        
        # Register message handlers
        self.data_manager.register_message_handler(
            "file_transfer",
            self._handle_file_transfer_message,
        )
    
    async def send_file(
        self,
        file_path: Union[str, Path],
        peer_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send a file to a peer.
        
        Args:
            file_path: Path to the file to send
            peer_id: ID of the peer to send the file to
            metadata: Optional metadata to include with the file
            
        Returns:
            str: ID of the file transfer
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileTransferError(f"File not found: {file_path}")
        
        # Generate a unique file ID
        file_id = hashlib.sha256(
            f"{file_path.name}{file_path.stat().st_size}{time.time()}".encode()
        ).hexdigest()
        
        # Calculate file checksum
        checksum = self._calculate_file_checksum(file_path)
        
        # Create file metadata
        file_metadata = FileMetadata(
            file_id=file_id,
            filename=file_path.name,
            size=file_path.stat().st_size,
            chunks=(file_path.stat().st_size + self.chunk_size - 1) // self.chunk_size,
            chunk_size=self.chunk_size,
            checksum=checksum,
            metadata=metadata or {},
        )
        
        # Store metadata
        self.file_metadata[file_id] = file_metadata
        
        # Send file metadata to the peer
        await self._send_metadata(peer_id, file_metadata)
        
        return file_id
    
    async def _send_metadata(self, peer_id: str, metadata: FileMetadata) -> None:
        """Send file metadata to a peer."""
        await self.data_manager.send_message(
            peer_id,
            {
                "type": FileTransferMessageType.METADATA,
                "metadata": metadata.to_dict(),
            },
            channel_type=ChannelType.FILE_TRANSFER,
        )
    
    async def _send_chunk(
        self,
        peer_id: str,
        file_id: str,
        chunk_index: int,
        data: bytes,
    ) -> None:
        """Send a chunk of file data to a peer."""
        await self.data_manager.send_message(
            peer_id,
            {
                "type": FileTransferMessageType.CHUNK,
                "file_id": file_id,
                "chunk_index": chunk_index,
                "data": data.hex(),
            },
            channel_type=ChannelType.FILE_TRANSFER,
        )
    
    async def _handle_file_transfer_message(
        self,
        peer_id: str,
        data: bytes,
        metadata: Dict[str, Any],
    ) -> None:
        """Handle an incoming file transfer message."""
        try:
            message = json.loads(data.decode())
            message_type = message.get("type")
            
            if message_type == FileTransferMessageType.REQUEST:
                await self._handle_file_request(peer_id, message)
            elif message_type == FileTransferMessageType.METADATA:
                await self._handle_metadata(peer_id, message["metadata"])
            elif message_type == FileTransferMessageType.CHUNK_REQUEST:
                await self._handle_chunk_request(peer_id, message)
            elif message_type == FileTransferMessageType.CHUNK:
                await self._handle_chunk(peer_id, message)
            elif message_type == FileTransferMessageType.COMPLETE:
                await self._handle_transfer_complete(peer_id, message)
            elif message_type == FileTransferMessageType.CANCEL:
                await self._handle_cancel(peer_id, message)
            elif message_type == FileTransferMessageType.ERROR:
                await self._handle_error(peer_id, message)
                
        except Exception as e:
            logger.error(f"Error handling file transfer message: {e}")
            await self._send_error(peer_id, str(e))
    
    async def _handle_file_request(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a file request from a peer."""
        file_id = message["file_id"]
        if file_id not in self.file_metadata:
            raise FileTransferError(f"Unknown file ID: {file_id}")
        
        # Send the file metadata
        await self._send_metadata(peer_id, self.file_metadata[file_id])
    
    async def _handle_metadata(self, peer_id: str, metadata_dict: Dict[str, Any]) -> None:
        """Handle incoming file metadata."""
        metadata = FileMetadata.from_dict(metadata_dict)
        self.file_metadata[metadata.file_id] = metadata
        
        # Initialize transfer progress
        self.active_transfers[metadata.file_id] = TransferProgress(
            file_id=metadata.file_id,
            total_chunks=metadata.chunks,
        )
        
        # Request the first chunk
        await self._request_chunk(peer_id, metadata.file_id, 0)
    
    async def _request_chunk(
        self,
        peer_id: str,
        file_id: str,
        chunk_index: int,
    ) -> None:
        """Request a specific chunk of a file."""
        await self.data_manager.send_message(
            peer_id,
            {
                "type": FileTransferMessageType.CHUNK_REQUEST,
                "file_id": file_id,
                "chunk_index": chunk_index,
            },
            channel_type=ChannelType.FILE_TRANSFER,
        )
    
    async def _handle_chunk_request(
        self,
        peer_id: str,
        message: Dict[str, Any],
    ) -> None:
        """Handle a request for a specific chunk of a file."""
        file_id = message["file_id"]
        chunk_index = message["chunk_index"]
        
        if file_id not in self.file_metadata:
            raise FileTransferError(f"Unknown file ID: {file_id}")
        
        metadata = self.file_metadata[file_id]
        file_path = self.download_dir / metadata.filename
        
        # Read the requested chunk from the file
        with open(file_path, "rb") as f:
            f.seek(chunk_index * metadata.chunk_size)
            chunk_data = f.read(metadata.chunk_size)
        
        # Send the chunk
        await self._send_chunk(peer_id, file_id, chunk_index, chunk_data)
    
    async def _handle_chunk(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an incoming chunk of file data."""
        file_id = message["file_id"]
        chunk_index = message["chunk_index"]
        chunk_data = bytes.fromhex(message["data"])
        
        if file_id not in self.active_transfers:
            raise FileTransferError(f"No active transfer for file ID: {file_id}")
        
        # Add chunk to buffer
        if file_id not in self.chunk_buffers:
            self.chunk_buffers[file_id] = {}
        
        self.chunk_buffers[file_id][chunk_index] = chunk_data
        
        # Update transfer progress
        transfer = self.active_transfers[file_id]
        transfer.received_chunks.add(chunk_index)
        
        # Request next chunk if not complete
        if not transfer.is_complete:
            next_chunk = len(transfer.received_chunks)
            await self._request_chunk(peer_id, file_id, next_chunk)
        else:
            # All chunks received, assemble the file
            await self._assemble_file(file_id)
            
            # Notify the sender that the transfer is complete
            await self.data_manager.send_message(
                peer_id,
                {
                    "type": FileTransferMessageType.COMPLETE,
                    "file_id": file_id,
                },
                channel_type=ChannelType.FILE_TRANSFER,
            )
    
    async def _assemble_file(self, file_id: str) -> None:
        """Assemble a file from received chunks."""
        if file_id not in self.file_metadata or file_id not in self.chunk_buffers:
            raise FileTransferError(f"Cannot assemble file: {file_id}")
        
        metadata = self.file_metadata[file_id]
        chunk_buffer = self.chunk_buffers[file_id]
        
        # Ensure all chunks are present
        if len(chunk_buffer) != metadata.chunks:
            raise FileTransferError(
                f"Incomplete file: {len(chunk_buffer)}/{metadata.chunks} chunks received"
            )
        
        # Create the output file
        output_path = self.download_dir / metadata.filename
        with open(output_path, "wb") as f:
            for i in range(metadata.chunks):
                f.write(chunk_buffer[i])
        
        # Verify the file checksum
        if metadata.checksum:
            actual_checksum = self._calculate_file_checksum(output_path)
            if actual_checksum != metadata.checksum:
                os.remove(output_path)
                raise FileTransferError("Checksum verification failed")
        
        # Clean up
        del self.chunk_buffers[file_id]
        del self.active_transfers[file_id]
        
        logger.info(f"File transfer complete: {metadata.filename}")
    
    async def _handle_transfer_complete(
        self,
        peer_id: str,
        message: Dict[str, Any],
    ) -> None:
        """Handle a transfer complete notification."""
        file_id = message["file_id"]
        if file_id in self.active_transfers:
            del self.active_transfers[file_id]
        logger.info(f"File transfer complete: {file_id}")
    
    async def _handle_cancel(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle a transfer cancellation."""
        file_id = message["file_id"]
        if file_id in self.active_transfers:
            del self.active_transfers[file_id]
        if file_id in self.chunk_buffers:
            del self.chunk_buffers[file_id]
        logger.info(f"File transfer cancelled: {file_id}")
    
    async def _handle_error(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle an error message."""
        file_id = message.get("file_id", "unknown")
        error = message.get("error", "Unknown error")
        logger.error(f"File transfer error ({file_id}): {error}")
    
    async def _send_error(self, peer_id: str, error: str) -> None:
        """Send an error message to a peer."""
        await self.data_manager.send_message(
            peer_id,
            {
                "type": FileTransferMessageType.ERROR,
                "error": error,
            },
            channel_type=ChannelType.FILE_TRANSFER,
        )
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate the SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash in chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def get_transfer_progress(self, file_id: str) -> Optional[TransferProgress]:
        """Get the progress of a file transfer."""
        return self.active_transfers.get(file_id)
    
    async def cancel_transfer(self, file_id: str) -> None:
        """Cancel an in-progress file transfer."""
        if file_id in self.active_transfers:
            del self.active_transfers[file_id]
        if file_id in self.chunk_buffers:
            del self.chunk_buffers[file_id]
