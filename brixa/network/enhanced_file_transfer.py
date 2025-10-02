"""
Enhanced P2P File Transfer Protocol for Brixa Network.

This module implements a robust, high-performance file transfer system with:
- File preview generation
- Resumable transfers
- Transfer speed optimization
- File chunking for large files
- Bandwidth management
- Network condition adaptation
"""
import os
import hashlib
import asyncio
import json
import time
import math
import imghdr
import mimetypes
import zlib
import io
import logging
import aiofiles
from typing import Dict, Optional, Tuple, BinaryIO, AsyncGenerator, Union, List, Any, Set, Deque
from pathlib import Path
from dataclasses import dataclass, field, asdict
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
import statistics
import hmac

# For file preview generation
try:
    from PIL import Image, ImageOps
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False
    
# For video/audio previews
try:
    import cv2
    import numpy as np
    HAS_OPENCV = True
except ImportError:
    HAS_OPENCV = False

logger = logging.getLogger(__name__)

# Constants
DEFAULT_CHUNK_SIZE = 256 * 1024  # 256KB initial chunk size
MIN_CHUNK_SIZE = 16 * 1024      # 16KB minimum chunk size
MAX_CHUNK_SIZE = 4 * 1024 * 1024  # 4MB maximum chunk size
MAX_FILE_SIZE = 10 * 1024 * 1024 * 1024  # 10GB max file size
MAX_PREVIEW_SIZE = 10 * 1024 * 1024  # 10MB max for preview generation
PREVIEW_IMAGE_SIZE = (320, 240)  # Default preview dimensions
CHUNK_QUEUE_SIZE = 100  # Max chunks to buffer
MAX_PARALLEL_CHUNKS = 8  # Max parallel chunk requests
COMPRESSION_THRESHOLD = 1024  # Min size for compression (bytes)
COMPRESSION_LEVEL = 6  # zlib compression level (1-9)

# Transfer priorities
PRIORITY_LOW = 0
PRIORITY_NORMAL = 1
PRIORITY_HIGH = 2

# Bandwidth measurement window (seconds)
BW_WINDOW_SIZE = 10

@dataclass
class FilePreview:
    """Represents a preview of a file."""
    mime_type: str
    size: int
    width: Optional[int] = None
    height: Optional[int] = None
    duration: Optional[float] = None  # For audio/video
    thumbnail: Optional[bytes] = None  # Base64 encoded thumbnail
    text_preview: Optional[str] = None  # For text files
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TransferChunk:
    """Represents a chunk of data being transferred."""
    chunk_index: int
    data: bytes
    sent_time: float = 0
    ack_received: bool = False
    retry_count: int = 0
    checksum: Optional[str] = None
    compressed: bool = False
    original_size: int = 0

@dataclass
class TransferStats:
    """Tracks transfer statistics and performance metrics."""
    start_time: float = field(default_factory=time.monotonic)
    bytes_transferred: int = 0
    chunks_sent: int = 0
    chunks_received: int = 0
    retry_count: int = 0
    last_chunk_time: float = field(default_factory=time.monotonic)
    chunk_times: Deque[float] = field(default_factory=lambda: deque(maxlen=100))
    
    @property
    def average_speed(self) -> float:
        """Calculate average transfer speed in bytes per second."""
        if not self.chunk_times:
            return 0.0
        total_time = sum(self.chunk_times)
        if total_time <= 0:
            return 0.0
        return (len(self.chunk_times) * self.chunk_times[0]) / total_time
    
    def update_chunk_time(self, chunk_size: int, chunk_time: float):
        """Update statistics for a chunk transfer."""
        if chunk_time > 0:
            self.chunk_times.append(chunk_time)
            self.bytes_transferred += chunk_size
            self.last_chunk_time = time.monotonic()

@dataclass
class FileTransfer:
    """Represents an active file transfer with enhanced features."""
    file_id: str
    file_path: str
    file_size: int
    total_chunks: int
    peer_id: str
    chunk_size: int = DEFAULT_CHUNK_SIZE
    priority: int = PRIORITY_NORMAL
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    sent_chunks: Dict[int, TransferChunk] = field(default_factory=dict)
    received_size: int = 0
    transferred_size: int = 0
    is_complete: bool = False
    encryption_key: Optional[bytes] = None
    iv: Optional[bytes] = None
    start_time: float = field(default_factory=time.monotonic)
    last_activity: float = field(default_factory=time.monotonic)
    transfer_speed: float = 0
    error_count: int = 0
    max_retries: int = 3
    checksums: Dict[int, str] = field(default_factory=dict)
    preview: Optional[FilePreview] = None
    compression: bool = True
    compressed_size: Optional[int] = None
    transfer_stats: TransferStats = field(default_factory=TransferStats)
    pending_chunks: Set[int] = field(default_factory=set)
    last_chunk_time: float = 0
    adaptive_chunk_size: bool = True
    file_hash: Optional[str] = None
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = time.monotonic()
    
    def get_progress(self) -> float:
        """Get transfer progress as a percentage."""
        if self.file_size == 0:
            return 0.0
        return (self.received_size / self.file_size) * 100
    
    def get_elapsed_time(self) -> float:
        """Get the elapsed time since transfer started in seconds."""
        return time.monotonic() - self.start_time
    
    def get_remaining_time(self) -> float:
        """Get estimated remaining time in seconds."""
        if self.transfer_speed <= 0 or self.file_size <= 0:
            return float('inf')
        remaining_bytes = self.file_size - self.received_size
        return remaining_bytes / self.transfer_speed
    
    def adjust_chunk_size(self, network_conditions: Dict):
        """Dynamically adjust chunk size based on network conditions."""
        if not self.adaptive_chunk_size:
            return
            
        latency = network_conditions.get('latency', 0.1)
        packet_loss = network_conditions.get('packet_loss', 0.0)
        
        # Reduce chunk size if high latency or packet loss
        if latency > 0.5 or packet_loss > 0.1:
            new_size = max(
                int(self.chunk_size * 0.8),
                MIN_CHUNK_SIZE
            )
        # Increase chunk size if conditions are good
        else:
            new_size = min(
                int(self.chunk_size * 1.5),
                MAX_CHUNK_SIZE,
                self.file_size // 100  # Max 1% of file size
            )
        
        # Apply bounds
        new_size = max(MIN_CHUNK_SIZE, min(new_size, MAX_CHUNK_SIZE))
        
        if new_size != self.chunk_size:
            logger.debug(f"Adjusting chunk size from {self.chunk_size} to {new_size} bytes")
            self.chunk_size = new_size

class EnhancedFileTransferManager:
    """Manages enhanced P2P file transfers with optimization features."""
    
    def __init__(self, p2p_node, storage_dir: str = "data/files", max_bandwidth: Optional[int] = None):
        """Initialize the enhanced file transfer manager.
        
        Args:
            p2p_node: Reference to the P2P node
            storage_dir: Base directory for storing received files
            max_bandwidth: Maximum bandwidth in bytes per second (None for unlimited)
        """
        self.p2p_node = p2p_node
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # State directory for resumable transfers
        self.state_dir = self.storage_dir / '.transfer_states'
        self.state_dir.mkdir(exist_ok=True)
        
        # Active file transfers
        self.active_transfers: Dict[str, FileTransfer] = {}
        self.file_hashes: Dict[str, str] = {}
        
        # Bandwidth management
        self.max_bandwidth = max_bandwidth
        self.current_bandwidth = 0
        self.bandwidth_history = deque(maxlen=10)
        
        # Thread pool for CPU-intensive operations
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        # Network conditions
        self.network_conditions = {
            'latency': 0.1,  # seconds
            'packet_loss': 0.0,  # 0-1
            'bandwidth': 1_000_000,  # 1Mbps initial estimate
            'last_updated': 0
        }
        
        # Transfer queue (priority-based)
        self.transfer_queue: List[Tuple[int, float, str]] = []  # (priority, timestamp, file_id)
        
        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_inactive_transfers())
        self.monitor_task = asyncio.create_task(self._monitor_network_conditions())
        self.process_queue_task = asyncio.create_task(self._process_transfer_queue())
        
        # Register message handlers
        self._register_message_handlers()
    
    def _register_message_handlers(self):
        """Register all message handlers with the P2P node."""
        handlers = {
            "file_offer": self._handle_file_offer,
            "file_request": self._handle_file_request,
            "file_chunk": self._handle_file_chunk,
            "file_ack": self._handle_file_ack,
            "transfer_resume": self._handle_transfer_resume,
            "transfer_cancel": self._handle_transfer_cancel
        }
        
        for msg_type, handler in handlers.items():
            self.p2p_node.register_message_handler(msg_type, handler)
    
    async def generate_file_preview(self, file_path: Union[str, Path]) -> Optional[FilePreview]:
        """Generate a preview for a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            FilePreview object or None if preview cannot be generated
        """
        file_path = Path(file_path)
        if not file_path.exists() or not file_path.is_file():
            return None
            
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type is None:
            mime_type = 'application/octet-stream'
            
        file_size = file_path.stat().st_size
        preview = FilePreview(mime_type=mime_type, size=file_size)
        
        # Don't generate previews for very large files
        if file_size > MAX_PREVIEW_SIZE:
            return preview
            
        try:
            # Handle image previews
            if mime_type.startswith('image/') and HAS_PILLOW:
                with Image.open(file_path) as img:
                    preview.width, preview.height = img.size
                    
                    # Generate thumbnail
                    img.thumbnail(PREVIEW_IMAGE_SIZE)
                    with io.BytesIO() as output:
                        img.save(output, format='JPEG', quality=85)
                        preview.thumbnail = output.getvalue()
                        
            # Handle video previews
            elif mime_type.startswith('video/') and HAS_OPENCV:
                cap = cv2.VideoCapture(str(file_path))
                if cap.isOpened():
                    preview.width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                    preview.height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                    preview.duration = cap.get(cv2.CAP_PROP_FRAME_COUNT) / max(1, cap.get(cv2.CAP_PROP_FPS))
                    
                    # Get a frame from the middle of the video
                    middle_frame = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) / 2)
                    cap.set(cv2.CAP_PROP_POS_FRAMES, middle_frame)
                    ret, frame = cap.read()
                    if ret:
                        # Convert BGR to RGB
                        frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                        img = Image.fromarray(frame)
                        img.thumbnail(PREVIEW_IMAGE_SIZE)
                        with io.BytesIO() as output:
                            img.save(output, format='JPEG', quality=85)
                            preview.thumbnail = output.getvalue()
                cap.release()
                
            # Handle text files
            elif mime_type.startswith('text/') or mime_type in [
                'application/json', 
                'application/xml', 
                'application/x-yaml'
            ]:
                try:
                    async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                        preview.text_preview = (await f.read(2048))  # First 2KB of text
                except (UnicodeDecodeError, OSError):
                    pass
                    
            # Handle audio files
            elif mime_type.startswith('audio/'):
                # Extract basic metadata
                preview.metadata['type'] = 'audio'
                
        except Exception as e:
            logger.warning(f"Failed to generate preview for {file_path}: {e}")
            
        return preview
    
    async def send_file(
        self,
        peer_id: str,
        file_path: Union[str, Path],
        priority: int = PRIORITY_NORMAL,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        generate_preview: bool = True,
        compress: bool = True,
        encrypt: bool = True
    ) -> str:
        """Initiate sending a file to a peer.
        
        Args:
            peer_id: ID of the peer to send the file to
            file_path: Path to the file to send
            priority: Transfer priority (PRIORITY_LOW, PRIORITY_NORMAL, PRIORITY_HIGH)
            chunk_size: Initial chunk size in bytes
            generate_preview: Whether to generate a file preview
            compress: Whether to enable compression
            encrypt: Whether to encrypt the file
            
        Returns:
            Transfer ID for tracking progress
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} bytes (max {MAX_FILE_SIZE} bytes)")
        
        # Generate a unique transfer ID
        transfer_id = self._generate_transfer_id(peer_id, file_path)
        
        # Calculate total chunks
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        
        # Generate file hash
        file_hash = await self._calculate_file_hash(file_path)
        
        # Generate preview if requested
        preview = None
        if generate_preview and file_size <= MAX_PREVIEW_SIZE:
            preview = await self.generate_file_preview(file_path)
        
        # Create transfer object
        transfer = FileTransfer(
            file_id=transfer_id,
            file_path=str(file_path),
            file_size=file_size,
            total_chunks=total_chunks,
            peer_id=peer_id,
            chunk_size=chunk_size,
            priority=priority,
            compression=compress,
            file_hash=file_hash,
            preview=preview
        )
        
        # Add to active transfers
        self.active_transfers[transfer_id] = transfer
        
        # Add to transfer queue
        self._add_to_transfer_queue(transfer_id, priority)
        
        logger.info(f"Started file transfer {transfer_id} for {file_path} to {peer_id}")
        
        return transfer_id
    
    async def _process_chunk_request(self, transfer: FileTransfer, chunk_index: int):
        """Process a request for a specific chunk of a file."""
        try:
            start_pos = chunk_index * transfer.chunk_size
            chunk_size = min(transfer.chunk_size, transfer.file_size - start_pos)
            
            # Read chunk from file
            async with aiofiles.open(transfer.file_path, 'rb') as f:
                await f.seek(start_pos)
                chunk_data = await f.read(chunk_size)
            
            # Calculate checksum
            checksum = hashlib.sha256(chunk_data).hexdigest()
            
            # Compress if enabled and beneficial
            original_size = len(chunk_data)
            compressed = False
            
            if transfer.compression and original_size > COMPRESSION_THRESHOLD:
                compressed_data = await asyncio.get_running_loop().run_in_executor(
                    self.thread_pool,
                    lambda: zlib.compress(chunk_data, level=COMPRESSION_LEVEL)
                )
                
                # Only use compressed version if it's smaller
                if len(compressed_data) < original_size * 0.9:  # At least 10% reduction
                    chunk_data = compressed_data
                    compressed = True
            
            # Create chunk object
            chunk = TransferChunk(
                chunk_index=chunk_index,
                data=chunk_data,
                checksum=checksum,
                compressed=compressed,
                original_size=original_size
            )
            
            # Store in sent chunks
            transfer.sent_chunks[chunk_index] = chunk
            
            # Send chunk to peer
            await self._send_chunk(transfer, chunk)
            
        except Exception as e:
            logger.error(f"Error processing chunk {chunk_index}: {e}")
            transfer.error_count += 1
            
            if transfer.error_count > transfer.max_retries:
                logger.error(f"Too many errors for transfer {transfer.file_id}, giving up")
                await self._cancel_transfer(transfer, f"Too many errors: {e}")
    
    async def _send_chunk(self, transfer: FileTransfer, chunk: TransferChunk):
        """Send a chunk of data to the peer."""
        try:
            # Prepare chunk message
            message = {
                'file_id': transfer.file_id,
                'chunk_index': chunk.chunk_index,
                'total_chunks': transfer.total_chunks,
                'data': chunk.data,
                'is_last': (chunk.chunk_index == transfer.total_chunks - 1),
                'checksum': chunk.checksum,
                'compressed': chunk.compressed,
                'original_size': chunk.original_size
            }
            
            # Send the chunk
            await self.p2p_node.send_message(transfer.peer_id, 'file_chunk', message)
            
            # Update stats
            chunk.sent_time = time.monotonic()
            transfer.transfer_stats.chunks_sent += 1
            transfer.transfer_stats.bytes_transferred += len(chunk.data)
            
            logger.debug(f"Sent chunk {chunk.chunk_index} of {transfer.file_id} to {transfer.peer_id}")
            
        except Exception as e:
            logger.error(f"Error sending chunk {chunk.chunk_index}: {e}")
            raise
    
    async def _handle_file_chunk(self, sender_id: str, message: Dict):
        """Handle an incoming file chunk."""
        file_id = message.get('file_id')
        chunk_index = message.get('chunk_index')
        chunk_data = message.get('data')
        is_last = message.get('is_last', False)
        checksum = message.get('checksum')
        is_compressed = message.get('compressed', False)
        original_size = message.get('original_size', len(chunk_data) if chunk_data else 0)
        
        if not all([file_id, chunk_data is not None, chunk_index is not None]):
            logger.warning(f"Invalid file chunk received from {sender_id}")
            return
            
        transfer = self.active_transfers.get(file_id)
        if not transfer or transfer.peer_id != sender_id:
            logger.warning(f"Received chunk for unknown transfer: {file_id}")
            return
            
        # Update activity
        transfer.update_activity()
        transfer.last_chunk_time = time.monotonic()
        
        try:
            start_time = time.monotonic()
            
            # Verify checksum
            if checksum:
                actual_checksum = hashlib.sha256(chunk_data).hexdigest()
                if not hmac.compare_digest(checksum, actual_checksum):
                    raise ValueError(f"Checksum mismatch for chunk {chunk_index}")
            
            # Decompress if needed
            if is_compressed:
                chunk_data = await asyncio.get_running_loop().run_in_executor(
                    self.thread_pool,
                    lambda: zlib.decompress(chunk_data)
                )
                
                # Verify decompressed size
                if len(chunk_data) != original_size:
                    raise ValueError(f"Decompressed size mismatch for chunk {chunk_index}")
            
            # Store the chunk
            transfer.received_chunks[chunk_index] = chunk_data
            transfer.received_size += len(chunk_data)
            
            # Update transfer stats
            chunk_time = time.monotonic() - start_time
            transfer.transfer_stats.update_chunk_time(len(chunk_data), chunk_time)
            
            # Update bandwidth usage
            self._update_bandwidth_usage(len(chunk_data))
            
            # Calculate current transfer speed (exponential moving average)
            current_speed = len(chunk_data) / max(0.001, chunk_time)
            alpha = 0.2  # Smoothing factor
            transfer.transfer_speed = (
                alpha * current_speed + 
                (1 - alpha) * transfer.transfer_speed
                if transfer.transfer_speed > 0 else current_speed
            )
            
            # Send ACK
            ack = {
                'file_id': file_id,
                'chunk_index': chunk_index,
                'received_size': transfer.received_size,
                'total_size': transfer.file_size,
                'chunk_size': len(chunk_data),
                'transfer_time': chunk_time,
                'current_speed': current_speed
            }
            await self.p2p_node.send_message(sender_id, 'file_ack', ack)
            
            # Remove from pending chunks
            transfer.pending_chunks.discard(chunk_index)
            
            # Request next chunks
            await self._request_next_chunks(transfer)
            
            # Check if transfer is complete
            if is_last or len(transfer.received_chunks) >= transfer.total_chunks:
                transfer.is_complete = True
                await self._assemble_file(transfer)
                
        except Exception as e:
            logger.error(f"Error processing file chunk: {e}")
            transfer.error_count += 1
            transfer.transfer_stats.retry_count += 1
            
            if transfer.error_count > transfer.max_retries:
                logger.error(f"Too many errors for {file_id}, giving up")
                await self._cancel_transfer(transfer, str(e))
            else:
                # Request the failed chunk again
                await self._request_chunk(sender_id, file_id, chunk_index)
    
    async def _assemble_file(self, transfer: FileTransfer) -> bool:
        """Assemble received chunks into a complete file."""
        temp_path = None
        
        try:
            # Sort chunk indices
            chunk_indices = sorted(transfer.received_chunks.keys())
            
            # Check if we have all chunks
            if len(chunk_indices) < transfer.total_chunks:
                # Save transfer state for resumption
                await self._save_transfer_state(transfer)
                logger.info(f"Incomplete transfer saved, {len(chunk_indices)}/{transfer.total_chunks} chunks received")
                return False
            
            # Create output directory if it doesn't exist
            output_path = self.storage_dir / Path(transfer.file_path).name
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Use a temporary file during assembly
            temp_path = output_path.with_suffix(f".part_{transfer.file_id}")
            
            # Write chunks to temporary file
            async with aiofiles.open(temp_path, 'wb') as temp_file:
                for chunk_idx in range(transfer.total_chunks):
                    if chunk_idx in transfer.received_chunks:
                        await temp_file.write(transfer.received_chunks[chunk_idx])
                    else:
                        # This shouldn't happen if we checked above
                        raise ValueError(f"Missing chunk {chunk_idx} in transfer {transfer.file_id}")
            
            # Verify file size
            actual_size = os.path.getsize(temp_path)
            if actual_size != transfer.file_size:
                raise ValueError(f"File size mismatch: expected {transfer.file_size}, got {actual_size}")
            
            # Verify file hash if available
            if transfer.file_hash:
                file_hash = await self._calculate_file_hash(temp_path)
                if file_hash != transfer.file_hash:
                    raise ValueError(f"File hash mismatch: expected {transfer.file_hash}, got {file_hash}")
            
            # Atomically rename the temporary file to the final name
            if os.path.exists(output_path):
                backup_path = output_path.with_suffix(f".bak_{int(time.time())}")
                os.rename(output_path, backup_path)
                
            os.rename(temp_path, output_path)
            
            logger.info(f"Successfully received file: {output_path}")
            
            # Clean up
            await self._cleanup_transfer(transfer)
            
            return True
            
        except Exception as e:
            logger.error(f"Error assembling file: {e}")
            
            # Clean up temporary file if it exists
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to clean up temporary file: {e}")
            
            transfer.error_count += 1
            
            if transfer.error_count > transfer.max_retries:
                await self._cancel_transfer(transfer, str(e))
            else:
                # Save state for resumption
                await self._save_transfer_state(transfer)
            
            return False
    
    async def _request_next_chunks(self, transfer: FileTransfer, count: int = 3):
        """Request the next chunks in parallel for better throughput."""
        if transfer.is_complete or len(transfer.pending_chunks) >= MAX_PARALLEL_CHUNKS:
            return
            
        # Find the next chunks to request
        chunks_to_request = []
        while len(chunks_to_request) < count and len(transfer.pending_chunks) < MAX_PARALLEL_CHUNKS:
            next_chunk = self._find_next_chunk_to_request(transfer)
            if next_chunk is None:
                break
            chunks_to_request.append(next_chunk)
            transfer.pending_chunks.add(next_chunk)
        
        # Request chunks in parallel
        if chunks_to_request:
            await asyncio.gather(*[
                self._request_chunk(transfer.peer_id, transfer.file_id, chunk_idx)
                for chunk_idx in chunks_to_request
            ])
    
    def _find_next_chunk_to_request(self, transfer: FileTransfer) -> Optional[int]:
        """Find the next chunk to request based on transfer strategy."""
        # Simple strategy: request chunks in order, skipping already requested ones
        for i in range(transfer.total_chunks):
            if i not in transfer.received_chunks and i not in transfer.pending_chunks:
                return i
        return None
    
    async def _request_chunk(self, peer_id: str, file_id: str, chunk_index: int):
        """Request a specific chunk from a peer."""
        message = {
            'file_id': file_id,
            'chunk_index': chunk_index,
            'requested_chunk_size': DEFAULT_CHUNK_SIZE  # Can be adjusted based on network conditions
        }
        
        await self.p2p_node.send_message(peer_id, 'file_request', message)
    
    async def _handle_transfer_resume(self, sender_id: str, message: Dict):
        """Handle a request to resume a previously interrupted transfer."""
        file_id = message.get('file_id')
        if not file_id:
            return
            
        transfer = self.active_transfers.get(file_id)
        if not transfer or transfer.peer_id != sender_id:
            return
            
        # Send information about which chunks we already have
        response = {
            'file_id': file_id,
            'received_chunks': list(transfer.received_chunks.keys()),
            'total_chunks': transfer.total_chunks,
            'chunk_size': transfer.chunk_size,
            'file_size': transfer.file_size
        }
        
        await self.p2p_node.send_message(sender_id, 'transfer_resume_ack', response)
        
        # Continue with the transfer
        await self._request_next_chunks(transfer)
    
    async def _handle_file_ack(self, sender_id: str, message: Dict):
        """Handle an acknowledgment for a sent chunk."""
        file_id = message.get('file_id')
        chunk_index = message.get('chunk_index')
        
        if not file_id or chunk_index is None:
            return
            
        transfer = self.active_transfers.get(file_id)
        if not transfer or transfer.peer_id != sender_id:
            return
            
        # Update the chunk status
        if chunk_index in transfer.sent_chunks:
            transfer.sent_chunks[chunk_index].ack_received = True
            
        # Update transfer stats
        transfer.transferred_size = message.get('received_size', transfer.transferred_size)
        
        # Request next chunks if needed
        if not transfer.is_complete:
            await self._request_next_chunks(transfer)
    
    async def _cleanup_transfer(self, transfer: FileTransfer):
        """Clean up resources for a completed or failed transfer."""
        if transfer.file_id in self.active_transfers:
            del self.active_transfers[transfer.file_id]
        
        # Clean up state file
        state_file = self._get_state_file_path(transfer.file_id)
        if state_file.exists():
            try:
                state_file.unlink()
            except Exception as e:
                logger.warning(f"Failed to remove state file {state_file}: {e}")
    
    async def _cancel_transfer(self, transfer: FileTransfer, reason: str = ""):
        """Cancel an active transfer."""
        logger.warning(f"Cancelling transfer {transfer.file_id}: {reason}")
        
        # Notify the peer
        await self.p2p_node.send_message(transfer.peer_id, 'transfer_cancel', {
            'file_id': transfer.file_id,
            'reason': reason
        })
        
        # Clean up
        await self._cleanup_transfer(transfer)
    
    async def _monitor_network_conditions(self):
        """Monitor network conditions and adjust transfer parameters."""
        last_stats_time = time.monotonic()
        last_bytes = 0
        
        while True:
            try:
                now = time.monotonic()
                time_diff = now - last_stats_time
                
                if time_diff >= 1.0:  # Update stats at most once per second
                    # Calculate current bandwidth usage
                    current_bytes = sum(
                        sum(len(chunk.data) for chunk in t.sent_chunks.values())
                        for t in self.active_transfers.values()
                    )
                    
                    bytes_diff = current_bytes - last_bytes
                    current_bw = bytes_diff / time_diff  # bytes per second
                    
                    # Update network conditions
                    self.network_conditions.update({
                        'bandwidth': current_bw,
                        'last_updated': now
                    })
                    
                    # Update stats for adaptive transfers
                    for transfer in list(self.active_transfers.values()):
                        self._update_transfer_metrics(transfer)
                    
                    last_stats_time = now
                    last_bytes = current_bytes
                
                # Check for stalled transfers
                await self._check_stalled_transfers()
                
            except Exception as e:
                logger.error(f"Error in network monitor: {e}")
                
            await asyncio.sleep(1)  # Check every second
    
    def _update_transfer_metrics(self, transfer: FileTransfer):
        """Update transfer metrics and adjust parameters."""
        stats = transfer.transfer_stats
        
        # Calculate average speed over the last window
        if stats.chunk_times:
            avg_chunk_time = sum(stats.chunk_times) / len(stats.chunk_times)
            if avg_chunk_time > 0:
                current_speed = transfer.chunk_size / avg_chunk_time
                
                # Update network conditions
                self.network_conditions['bandwidth'] = (
                    0.8 * self.network_conditions.get('bandwidth', current_speed) + 
                    0.2 * current_speed
                )
        
        # Adjust chunk size based on network conditions
        self._adjust_chunk_size(transfer)
    
    def _adjust_chunk_size(self, transfer: FileTransfer):
        """Dynamically adjust chunk size based on network conditions."""
        if not transfer.adaptive_chunk_size:
            return
            
        stats = transfer.transfer_stats
        
        # Need at least some data to make decisions
        if len(stats.chunk_times) < 5:
            return
            
        # Calculate average chunk time and speed
        avg_chunk_time = sum(stats.chunk_times) / len(stats.chunk_times)
        if avg_chunk_time <= 0:
            return
            
        current_speed = transfer.chunk_size / avg_chunk_time
        
        # Adjust chunk size based on performance
        if avg_chunk_time < 0.1:  # Chunks transferring too quickly
            # Increase chunk size, but not beyond max
            new_size = min(
                int(transfer.chunk_size * 1.5),
                MAX_CHUNK_SIZE,
                transfer.file_size // 100  # Don't use chunks larger than 1% of file
            )
            if new_size > transfer.chunk_size:
                transfer.chunk_size = new_size
                logger.debug(f"Increased chunk size to {new_size} bytes")
                
        elif avg_chunk_time > 1.0:  # Chunks taking too long
            # Decrease chunk size, but not below minimum
            new_size = max(
                int(transfer.chunk_size * 0.8),
                MIN_CHUNK_SIZE
            )
            if new_size < transfer.chunk_size:
                transfer.chunk_size = new_size
                logger.debug(f"Decreased chunk size to {new_size} bytes")
    
    async def _check_stalled_transfers(self):
        """Check for and handle stalled transfers."""
        current_time = time.monotonic()
        
        for transfer in list(self.active_transfers.values()):
            # Skip if transfer is complete or recently active
            if transfer.is_complete or (current_time - transfer.last_chunk_time) < 30:
                continue
                
            # If no progress in the last 30 seconds, consider it stalled
            logger.warning(f"Transfer {transfer.file_id} appears to be stalled")
            
            # Try to resume by re-requesting missing chunks
            if not transfer.is_complete and transfer.pending_chunks:
                logger.info(f"Re-requesting {len(transfer.pending_chunks)} pending chunks for {transfer.file_id}")
                for chunk_idx in list(transfer.pending_chunks):
                    await self._request_chunk(transfer.peer_id, transfer.file_id, chunk_idx)
    
    async def _cleanup_inactive_transfers(self):
        """Clean up inactive or completed transfers."""
        while True:
            try:
                current_time = time.monotonic()
                
                # Check for transfers that have been inactive for too long
                for transfer in list(self.active_transfers.values()):
                    if transfer.is_complete or (current_time - transfer.last_activity) > 3600:  # 1 hour timeout
                        await self._cleanup_transfer(transfer)
                
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                
            await asyncio.sleep(60)  # Check every minute
    
    def _update_bandwidth_usage(self, bytes_transferred: int):
        """Update bandwidth usage statistics."""
        self.bandwidth_history.append((time.time(), bytes_transferred))
        
        # Remove old entries (older than BW_WINDOW_SIZE seconds)
        current_time = time.time()
        while self.bandwidth_history and (current_time - self.bandwidth_history[0][0]) > BW_WINDOW_SIZE:
            self.bandwidth_history.popleft()
        
        # Calculate current bandwidth (bytes per second)
        if self.bandwidth_history:
            time_span = self.bandwidth_history[-1][0] - self.bandwidth_history[0][0]
            if time_span > 0:
                total_bytes = sum(b for _, b in self.bandwidth_history)
                self.current_bandwidth = total_bytes / time_span
    
    def _add_to_transfer_queue(self, file_id: str, priority: int):
        """Add a transfer to the priority queue."""
        timestamp = time.time()
        self.transfer_queue.append((priority, timestamp, file_id))
        self.transfer_queue.sort(reverse=True)  # Higher priority first
    
    async def _process_transfer_queue(self):
        """Process the transfer queue and manage concurrent transfers."""
        while True:
            try:
                # Count active transfers
                active_count = sum(
                    1 for t in self.active_transfers.values() 
                    if not t.is_complete
                )
                
                # Start new transfers if we're under the limit
                while (self.transfer_queue and 
                       active_count < self.max_concurrent_transfers):
                    _, _, file_id = self.transfer_queue.pop(0)
                    transfer = self.active_transfers.get(file_id)
                    
                    if transfer and not transfer.is_complete:
                        # Request initial chunks
                        await self._request_next_chunks(transfer)
                        active_count += 1
                
            except Exception as e:
                logger.error(f"Error in transfer queue processing: {e}")
                
            await asyncio.sleep(1)  # Don't spin too fast
    
    def _get_state_file_path(self, file_id: str) -> Path:
        """Get the path to the state file for a transfer."""
        return self.state_dir / f"{file_id}.state"
    
    async def _save_transfer_state(self, transfer: FileTransfer):
        """Save the state of a transfer to disk for resumption."""
        try:
            state = {
                'file_id': transfer.file_id,
                'file_path': transfer.file_path,
                'file_size': transfer.file_size,
                'file_hash': transfer.file_hash,
                'total_chunks': transfer.total_chunks,
                'chunk_size': transfer.chunk_size,
                'received_chunks': list(transfer.received_chunks.keys()),
                'compression': transfer.compression,
                'peer_id': transfer.peer_id,
                'priority': transfer.priority,
                'start_time': transfer.start_time,
                'last_activity': transfer.last_activity,
                'preview': asdict(transfer.preview) if transfer.preview else None
            }
            
            state_file = self._get_state_file_path(transfer.file_id)
            async with aiofiles.open(state_file, 'w') as f:
                await f.write(json.dumps(state))
                
        except Exception as e:
            logger.error(f"Failed to save transfer state: {e}")
    
    async def _load_transfer_state(self, file_id: str) -> Optional[Dict]:
        """Load the state of a transfer from disk."""
        try:
            state_file = self._get_state_file_path(file_id)
            if not state_file.exists():
                return None
                
            async with aiofiles.open(state_file, 'r') as f:
                return json.loads(await f.read())
                
        except Exception as e:
            logger.error(f"Failed to load transfer state: {e}")
            return None
    
    async def _calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate the SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        
        async with aiofiles.open(file_path, 'rb') as f:
            # Read and update hash in chunks
            chunk_size = 65536  # 64KB chunks
            while True:
                chunk = await f.read(chunk_size)
                if not chunk:
                    break
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _generate_transfer_id(self, peer_id: str, file_path: Union[str, Path]) -> str:
        """Generate a unique transfer ID."""
        timestamp = int(time.time() * 1000)
        unique_str = f"{peer_id}:{file_path}:{timestamp}:{os.urandom(4).hex()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()

# Example usage
async def example_usage():
    # Create a mock P2P node
    class MockP2PNode:
        def __init__(self):
            self.message_handlers = {}
            
        def register_message_handler(self, msg_type, handler):
            self.message_handlers[msg_type] = handler
            
        async def send_message(self, peer_id, msg_type, message):
            print(f"Sending {msg_type} to {peer_id}: {message}")
    
    # Initialize the file transfer manager
    p2p_node = MockP2PNode()
    transfer_manager = EnhancedFileTransferManager(p2p_node)
    
    # Example: Send a file
    peer_id = "peer123"
    file_path = "/path/to/example.txt"
    
    try:
        # Start a file transfer
        transfer_id = await transfer_manager.send_file(
            peer_id=peer_id,
            file_path=file_path,
            priority=PRIORITY_NORMAL,
            generate_preview=True,
            compress=True
        )
        
        print(f"Started transfer with ID: {transfer_id}")
        
        # In a real application, you would monitor the transfer progress
        # and handle the completion asynchronously
        
    except Exception as e:
        print(f"Error starting transfer: {e}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
