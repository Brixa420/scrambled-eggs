"""
P2P File Transfer Protocol for Brixa Network.

This module implements secure, resumable file transfers between peers.
"""
import os
import hashlib
import asyncio
import json
import time
import math
from typing import Dict, Optional, Tuple, BinaryIO, AsyncGenerator, Union, List
from pathlib import Path
from dataclasses import dataclass, field
import logging
import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from collections import deque
import statistics
import pickle
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Constants
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64KB initial chunk size
MIN_CHUNK_SIZE = 16 * 1024     # 16KB minimum chunk size
MAX_CHUNK_SIZE = 1024 * 1024   # 1MB maximum chunk size
MAX_FILE_SIZE = 1024 * 1024 * 1024 * 10  # 10GB max file size

# Transfer priority levels
PRIORITY_LOW = 0
PRIORITY_NORMAL = 1
PRIORITY_HIGH = 2

# Bandwidth measurement window (seconds)
BW_WINDOW_SIZE = 10

class BandwidthMonitor:
    """Monitors and manages bandwidth usage for file transfers."""
    
    def __init__(self, max_bandwidth: Optional[int] = None):
        """Initialize the bandwidth monitor.
        
        Args:
            max_bandwidth: Maximum bandwidth in bytes per second (None for unlimited)
        """
        self.max_bandwidth = max_bandwidth  # bytes per second
        self.transfer_start_time = 0
        self.bytes_transferred = 0
        self.samples = deque(maxlen=BW_WINDOW_SIZE)
        self.last_update = time.monotonic()
    
    def update(self, bytes_sent: int) -> None:
        """Update the bandwidth usage.
        
        Args:
            bytes_sent: Number of bytes transferred in the last operation
        """
        now = time.monotonic()
        self.bytes_transferred += bytes_sent
        
        # Record transfer rate samples
        if now > self.last_update:
            elapsed = now - self.last_update
            rate = bytes_sent / elapsed if elapsed > 0 else 0
            self.samples.append(rate)
            self.last_update = now
    
    def get_current_rate(self) -> float:
        """Get the current transfer rate in bytes per second."""
        if not self.samples:
            return 0
        return statistics.mean(self.samples)
    
    def get_remaining_bandwidth(self) -> Optional[float]:
        """Get the remaining available bandwidth in bytes per second."""
        if self.max_bandwidth is None:
            return float('inf')
        return max(0, self.max_bandwidth - self.get_current_rate())
    
    def get_throttle_delay(self, chunk_size: int) -> float:
        """Calculate the required delay to maintain bandwidth limits.
        
        Args:
            chunk_size: Size of the next chunk to be sent in bytes
            
        Returns:
            float: Delay in seconds before sending the next chunk
        """
        if self.max_bandwidth is None or not self.samples:
            return 0
            
        current_rate = self.get_current_rate()
        if current_rate <= 0:
            return 0
            
        # Calculate time to send one chunk at current rate
        time_per_chunk = chunk_size / current_rate
        
        # Calculate desired time per chunk based on max bandwidth
        desired_time_per_chunk = chunk_size / self.max_bandwidth if self.max_bandwidth > 0 else 0
        
        # Return the additional delay needed
        return max(0, desired_time_per_chunk - time_per_chunk)

@dataclass
class TransferChunk:
    """Represents a chunk of data being transferred."""
    chunk_index: int
    data: bytes
    sent_time: float = 0
    ack_received: bool = False
    retry_count: int = 0

@dataclass
class FileTransfer:
    """Represents an active file transfer."""
    file_id: str
    file_path: str
    file_size: int
    total_chunks: int
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
    transfer_speed: float = 0  # bytes per second
    error_count: int = 0
    max_retries: int = 3
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = time.monotonic()
    
    def get_progress(self) -> float:
        """Get transfer progress as a percentage."""
        if self.file_size == 0:
            return 0
        return (self.received_size / self.file_size) * 100
    
    def get_elapsed_time(self) -> float:
        """Get the elapsed time since transfer started in seconds."""
        return time.monotonic() - self.start_time
    
    def get_remaining_time(self) -> Optional[float]:
        """Get estimated remaining time in seconds."""
        if self.transfer_speed <= 0 or self.file_size <= 0:
            return None
        remaining_bytes = self.file_size - self.received_size
        return remaining_bytes / self.transfer_speed
    
    def adjust_chunk_size(self, network_conditions: Dict) -> None:
        """Dynamically adjust chunk size based on network conditions.
        
        Args:
            network_conditions: Dictionary containing network metrics like latency, packet loss
        """
        latency = network_conditions.get('latency', 0)  # in seconds
        packet_loss = network_conditions.get('packet_loss', 0)  # 0-1
        
        # Base adjustment on latency and packet loss
        if latency > 0.5:  # High latency
            # Increase chunk size to reduce overhead
            new_size = min(self.chunk_size * 2, MAX_CHUNK_SIZE)
        elif packet_loss > 0.1:  # High packet loss
            # Decrease chunk size to reduce retransmission overhead
            new_size = max(self.chunk_size // 2, MIN_CHUNK_SIZE)
        else:
            # Gradual increase if conditions are good
            new_size = min(int(self.chunk_size * 1.5), MAX_CHUNK_SIZE)
        
        # Apply bounds
        new_size = max(MIN_CHUNK_SIZE, min(new_size, MAX_CHUNK_SIZE))
        
        if new_size != self.chunk_size:
            logger.debug(f"Adjusting chunk size from {self.chunk_size} to {new_size} bytes")
            self.chunk_size = new_size

class FileTransferManager:
    """Manages file transfers between peers with optimization features."""
    
    def __init__(self, p2p_node, storage_dir: str = "data/files", max_bandwidth: Optional[int] = None):
        """Initialize the file transfer manager.
        
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
        
        # Active file transfers: file_id -> FileTransfer
        self.active_transfers: Dict[str, FileTransfer] = {}
        # File hashes for deduplication
        self.file_hashes: Dict[str, str] = {}
        
        # Bandwidth management
        self.bandwidth_monitor = BandwidthMonitor(max_bandwidth)
        self.max_concurrent_transfers = 3
        self.active_transfer_count = 0
        
        # Network conditions monitoring
        self.network_conditions = {
            'latency': 0.1,  # seconds
            'packet_loss': 0.0,  # 0-1
            'last_updated': 0
        }
        
        # Transfer queue (priority-based)
        self.transfer_queue: List[Tuple[int, float, str]] = []  # (priority, timestamp, file_id)
        
        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_inactive_transfers())
        self.monitor_task = asyncio.create_task(self._monitor_network_conditions())
        self.process_queue_task = asyncio.create_task(self._process_transfer_queue())
        
        # Register message handlers
        self.p2p_node.register_message_handler("file_offer", self._handle_file_offer)
        self.p2p_node.register_message_handler("file_request", self._handle_file_request)
        self.p2p_node.register_message_handler("file_chunk", self._handle_file_chunk)
        self.p2p_node.register_message_handler("file_ack", self._handle_file_ack)
    
    async def send_file(self, 
                      peer_id: str, 
                      file_path: Union[str, Path], 
                      encrypt: bool = True,
                      priority: int = PRIORITY_NORMAL,
                      chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
        """Initiate sending a file to a peer with transfer optimization.
        
        Args:
            peer_id: ID of the peer to send the file to
            file_path: Path to the file to send
            encrypt: Whether to encrypt the file
            priority: Transfer priority (PRIORITY_LOW, PRIORITY_NORMAL, PRIORITY_HIGH)
            chunk_size: Initial chunk size in bytes (will be adjusted dynamically)
            
        Returns:
            str: Transfer ID for tracking progress
        """
        file_path = Path(file_path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        file_size = file_path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise ValueError(f"File too large. Max size: {MAX_FILE_SIZE/1e9:.1f}GB")
        
        # Generate file ID and encryption key if needed
        file_id = self._generate_file_id(peer_id, file_path)
        encryption_key = os.urandom(32) if encrypt else None
        iv = os.urandom(16) if encrypt else None
        
        # Calculate file hash for deduplication
        file_hash = await self._calculate_file_hash(file_path)
        
        # Create transfer object
        transfer = FileTransfer(
            file_id=file_id,
            file_path=str(file_path),
            file_size=file_size,
            total_chunks=math.ceil(file_size / chunk_size),
            chunk_size=chunk_size,
            priority=priority,
            encryption_key=encryption_key,
            iv=iv
        )
        
        # Add to active transfers
        self.active_transfers[file_id] = transfer
        
        # Add to transfer queue with priority
        timestamp = time.monotonic()
        self.transfer_queue.append((priority, timestamp, file_id))
        self.transfer_queue.sort()  # Sort by priority (and timestamp for same priority)
        
        # Send file offer
        await self.p2p_node.send_message(peer_id, {
            "type": "file_offer",
            "file_id": file_id,
            "file_name": file_path.name,
            "file_size": file_size,
            "file_hash": file_hash,
            "chunk_size": chunk_size,
            "encrypted": encrypt,
            "encryption_key": base64.b64encode(encryption_key).decode('ascii') if encrypt else None,
            "iv": base64.b64encode(iv).decode('ascii') if iv else None,
            "priority": priority
        })
        
        logger.info(f"Started file transfer {file_id} to {peer_id} (priority: {priority})")
        return file_id
    
    async def _verify_chunk_checksum(self, chunk_data: bytes, expected_checksum: str) -> bool:
        """Verify the checksum of a received chunk.
        
        Args:
            chunk_data: The received chunk data
            expected_checksum: The expected checksum as a hex string
            
        Returns:
            bool: True if checksum matches, False otherwise
        """
        actual_checksum = hashlib.sha256(chunk_data).hexdigest()
        return actual_checksum == expected_checksum
            
    async def _handle_file_offer(self, sender_id: str, message: Dict) -> None:
        """Handle incoming file offer from a peer with transfer optimization."""
        try:
            file_id = message["file_id"]
            file_name = message["file_name"]
            file_size = message["file_size"]
            file_hash = message["file_hash"]
            chunk_size = message.get("chunk_size", DEFAULT_CHUNK_SIZE)
            priority = message.get("priority", PRIORITY_NORMAL)
            encrypted = message.get("encrypted", False)
            verify_checksums = message.get("verify_checksums", True)
            
            # Check if we already have this file
            if file_hash in self.file_hashes:
                logger.info(f"Already have file with hash {file_hash}, skipping download")
                await self.p2p_node.send_message(sender_id, {
                    "type": "file_ack",
                    "file_id": file_id,
                    "status": "duplicate",
                    "file_path": str(self.file_hashes[file_hash])
                })
                return
            
            # Create a new file transfer
            save_path = self.storage_dir / f"{file_id}_{file_name}"
            transfer = FileTransfer(
                file_id=file_id,
                file_path=str(save_path),
                file_size=file_size,
                total_chunks=math.ceil(file_size / chunk_size),
                chunk_size=chunk_size,
                priority=priority,
                encryption_key=base64.b64decode(message["encryption_key"]) if encrypted else None,
                iv=base64.b64decode(message["iv"]) if encrypted else None,
                expected_hash=file_hash if verify_checksums else None
            )
            
            self.active_transfers[file_id] = transfer
            
            # Add to transfer queue with priority
            timestamp = time.monotonic()
            self.transfer_queue.append((priority, timestamp, file_id))
            self.transfer_queue.sort()  # Sort by priority (and timestamp for same priority)
            
            logger.info(f"Receiving file {file_name} ({file_size/1e6:.1f}MB) from {sender_id}")
            
        except Exception as e:
            logger.error(f"Error handling file offer: {e}", exc_info=True)
            # Notify sender of failure
            await self.p2p_node.send_message(sender_id, {
                "type": "transfer_error",
                "file_id": file_id,
                "error": str(e)
            })
    
    async def _request_chunk(self, peer_id: str, file_id: str, chunk_index: int) -> None:
        """Request a specific chunk of a file with bandwidth management."""
        if file_id not in self.active_transfers:
            logger.warning(f"Cannot request chunk for unknown transfer: {file_id}")
            return
            
        transfer = self.active_transfers[file_id]
        
        # Check if we've already requested this chunk
        if chunk_index in transfer.sent_chunks:
            chunk = transfer.sent_chunks[chunk_index]
            if time.monotonic() - chunk.sent_time < 5:  # Wait at least 5 seconds before retrying
                return
            chunk.retry_count += 1
            if chunk.retry_count > transfer.max_retries:
                logger.error(f"Max retries exceeded for chunk {chunk_index} of {file_id}")
                return
        else:
            # Create a new chunk request
            chunk = TransferChunk(chunk_index=chunk_index, data=b"")
            transfer.sent_chunks[chunk_index] = chunk
        
        # Update chunk metadata
        chunk.sent_time = time.monotonic()
        transfer.last_activity = time.monotonic()
        
        # Apply bandwidth throttling
        remaining_bw = self.bandwidth_monitor.get_remaining_bandwidth()
        if remaining_bw is not None and remaining_bw < transfer.chunk_size:
            # Calculate delay based on available bandwidth
            delay = (transfer.chunk_size - remaining_bw) / self.bandwidth_monitor.max_bandwidth
            await asyncio.sleep(delay)
        
        # Send the request
        await self.p2p_node.send_message(peer_id, {
            "type": "file_request",
            "file_id": file_id,
            "chunk_index": chunk_index,
            "requested_chunk_size": transfer.chunk_size,
            "priority": transfer.priority
        })
    
    async def _handle_file_request(self, sender_id: str, message: Dict) -> None:
        """Handle a request for a file chunk by reading it from disk.
        
        Args:
            sender_id: ID of the peer requesting the chunk
            message: Dictionary containing:
                - file_id: ID of the file being transferred
                - chunk_index: Index of the requested chunk
                - requested_chunk_size: Size of the chunk to read (optional)
        """
        try:
            file_id = message["file_id"]
            chunk_index = message["chunk_index"]
            requested_chunk_size = message.get("requested_chunk_size", DEFAULT_CHUNK_SIZE)
            
            if file_id not in self.active_transfers:
                logger.warning(f"Received chunk request for unknown transfer: {file_id}")
                return
                
            transfer = self.active_transfers[file_id]
            file_path = Path(transfer.file_path)
            
            if not file_path.exists() or not file_path.is_file():
                logger.error(f"Requested file not found: {file_path}")
                await self.p2p_node.send_message(sender_id, {
                    "type": "transfer_error",
                    "file_id": file_id,
                    "error": f"File not found: {file_path}",
                    "chunk_index": chunk_index
                })
                return
                
            # Calculate chunk boundaries
            chunk_size = min(transfer.chunk_size, requested_chunk_size)
            chunk_start = chunk_index * chunk_size
            chunk_end = min(chunk_start + chunk_size, transfer.file_size)
            actual_chunk_size = chunk_end - chunk_start
            is_last = chunk_end >= transfer.file_size
            
            # Read the chunk from disk
            try:
                with open(file_path, 'rb') as f:
                    f.seek(chunk_start)
                    chunk_data = f.read(actual_chunk_size)
                    
                    # Verify we read the expected amount of data
                    if len(chunk_data) != actual_chunk_size:
                        raise IOError(f"Failed to read full chunk. Expected {actual_chunk_size} bytes, got {len(chunk_data)}")
                    
                    # Calculate checksum before encryption
                    chunk_checksum = await self._calculate_chunk_checksum(chunk_data)
                    
                    # Encrypt the chunk if needed
                    if transfer.encryption_key and transfer.iv:
                        chunk_data = self._encrypt_chunk(chunk_data, transfer.encryption_key, transfer.iv)
                    
                    # Prepare chunk message
                    chunk_message = {
                        "type": "file_chunk",
                        "file_id": file_id,
                        "chunk_index": chunk_index,
                        "data": base64.b64encode(chunk_data).decode('ascii'),
                        "is_last": is_last,
                        "chunk_size": len(chunk_data)
                    }
                    
                    # Add checksum if verification is enabled
                    if hasattr(transfer, 'expected_hash') and transfer.expected_hash:
                        chunk_message["checksum"] = chunk_checksum
                    
                    # Send the chunk
                    await self.p2p_node.send_message(sender_id, chunk_message)
                    
                    logger.debug(f"Sent chunk {chunk_index} of {file_id} ({len(chunk_data)} bytes)")
                    
            except (IOError, OSError) as e:
                logger.error(f"Error reading file chunk {chunk_index} from {file_path}: {e}")
                await self.p2p_node.send_message(sender_id, {
                    "type": "transfer_error",
                    "file_id": file_id,
                    "error": f"Error reading file: {e}",
                    "chunk_index": chunk_index
                })
            
        except Exception as e:
            logger.error(f"Error handling file request: {e}", exc_info=True)
    
    async def _handle_file_chunk(self, sender_id: str, message: Dict) -> None:
        """Handle an incoming file chunk with transfer optimization and checksum verification."""
        try:
            file_id = message["file_id"]
            chunk_index = message["chunk_index"]
            chunk_data = base64.b64decode(message["data"])
            is_last = message.get("is_last", False)
            chunk_size = len(chunk_data)
            chunk_checksum = message.get("checksum")
            
            if file_id not in self.active_transfers:
                logger.warning(f"Received chunk for unknown transfer: {file_id}")
                return
                
            transfer = self.active_transfers[file_id]
            transfer.last_activity = time.monotonic()
            
            # Verify chunk checksum if enabled
            if hasattr(transfer, 'expected_hash') and transfer.expected_hash and chunk_checksum:
                if not await self._verify_chunk_checksum(chunk_data, chunk_checksum):
                    logger.warning(f"Checksum verification failed for chunk {chunk_index} of {file_id}")
                    # Request the chunk again
                    await self._request_chunk(sender_id, file_id, chunk_index)
                    return
            
            # Update bandwidth usage
            self.bandwidth_monitor.update(chunk_size)
            
            # Calculate transfer speed (exponential moving average)
            now = time.monotonic()
            time_diff = now - transfer.last_activity
            if time_diff > 0:
                chunk_speed = chunk_size / time_diff
                # Apply EMA (Exponential Moving Average)
                alpha = 0.2  # Smoothing factor
                transfer.transfer_speed = (
                    alpha * chunk_speed + 
                    (1 - alpha) * transfer.transfer_speed
                )
            
            # Store the chunk
            transfer.received_chunks[chunk_index] = chunk_data
            transfer.received_size += chunk_size
            transfer.transferred_size += chunk_size
            
            # If this was a retransmission, mark the original as acknowledged
            if chunk_index in transfer.sent_chunks:
                chunk = transfer.sent_chunks[chunk_index]
                chunk.ack_received = True
                chunk.retry_count = 0
                
                # Calculate RTT and update network conditions
                rtt = now - chunk.sent_time
                self._update_network_conditions(rtt)
                
                # Adjust chunk size based on network conditions
                transfer.adjust_chunk_size(self.network_conditions)
            
            # Request next chunks using sliding window
            if not is_last:
                # Calculate how many chunks we can have in flight
                window_size = min(10, max(3, int((transfer.transfer_speed * 0.1) / transfer.chunk_size)))
                
                # Find the next chunks to request
                next_chunk = chunk_index + 1
                chunks_to_request = []
                
                # Count how many chunks are already in flight
                in_flight = sum(1 for c in transfer.sent_chunks.values() if not c.ack_received)
                
                # Request more chunks if we have room in the window
                while in_flight < window_size and next_chunk < transfer.total_chunks:
                    if next_chunk not in transfer.received_chunks and next_chunk not in transfer.sent_chunks:
                        chunks_to_request.append(next_chunk)
                        in_flight += 1
                    next_chunk += 1
                
                # Request the chunks
                for chunk_idx in chunks_to_request:
                    await self._request_chunk(sender_id, file_id, chunk_idx)
            else:
                # All chunks received, assemble the file
                if len(transfer.received_chunks) == transfer.total_chunks:
                    await self._assemble_file(transfer)
                    
                    # Send acknowledgment
                    await self.p2p_node.send_message(sender_id, {
                        "type": "file_ack",
                        "file_id": file_id,
                        "status": "completed",
                        "file_path": transfer.file_path,
                        "transfer_stats": {
                            "total_time": transfer.get_elapsed_time(),
                            "avg_speed": transfer.transfer_speed,
                            "chunk_size_avg": transfer.transferred_size / transfer.total_chunks
                        }
                    })
                    
                    # Clean up
                    if file_id in self.active_transfers:
                        del self.active_transfers[file_id]
                    
                    logger.info(f"File transfer {file_id} completed successfully")
                
        except Exception as e:
            logger.error(f"Error handling file chunk: {e}", exc_info=True)
            # Notify sender of failure
            if 'file_id' in locals():
                await self.p2p_node.send_message(sender_id, {
                    "type": "transfer_error",
                    "file_id": file_id,
                    "error": str(e)
                })
    
    def _get_state_file_path(self, file_id: str) -> Path:
        """Get the path to the state file for a given transfer."""
        return self.state_dir / f"{file_id}.state"

    def _save_transfer_state(self, transfer: FileTransfer) -> None:
        """Save the current state of a transfer to disk."""
        try:
            state = {
                'file_id': transfer.file_id,
                'file_path': transfer.file_path,
                'file_size': transfer.file_size,
                'total_chunks': transfer.total_chunks,
                'chunk_size': transfer.chunk_size,
                'received_chunks': list(transfer.received_chunks.keys()),
                'received_size': transfer.received_size,
                'encryption_key': transfer.encryption_key.hex() if transfer.encryption_key else None,
                'iv': transfer.iv.hex() if transfer.iv else None,
                'start_time': transfer.start_time,
                'last_activity': time.time(),
                'priority': transfer.priority,
                'expected_hash': getattr(transfer, 'expected_hash', None)
            }
            state_file = self._get_state_file_path(transfer.file_id)
            with open(state_file, 'wb') as f:
                pickle.dump(state, f)
        except Exception as e:
            logger.error(f"Error saving transfer state: {e}", exc_info=True)

    def _load_transfer_state(self, file_id: str) -> Optional[Dict]:
        """Load the state of a transfer from disk."""
        try:
            state_file = self._get_state_file_path(file_id)
            if not state_file.exists():
                return None
                
            with open(state_file, 'rb') as f:
                state = pickle.load(f)
                
            # Check if the state is too old (older than 7 days)
            last_activity = state.get('last_activity', 0)
            if time.time() - last_activity > 7 * 24 * 3600:  # 7 days
                state_file.unlink()
                return None
                
            return state
        except Exception as e:
            logger.error(f"Error loading transfer state: {e}", exc_info=True)
            return None

    def _delete_transfer_state(self, file_id: str) -> None:
        """Delete the state file for a transfer."""
        try:
            state_file = self._get_state_file_path(file_id)
            if state_file.exists():
                state_file.unlink()
        except Exception as e:
            logger.error(f"Error deleting transfer state: {e}", exc_info=True)

    async def _assemble_file(self, transfer: FileTransfer) -> None:
        """Assemble received chunks into a complete file with support for resumable transfers.
        
        This method will:
        1. Create a temporary file for assembly
        2. Write all received chunks in order
        3. Verify the file hash matches the expected value
        4. On success, rename to final path and clean up
        5. On failure, preserve the partial transfer for resumption
        """
        temp_path = f"{transfer.file_path}.tmp"
        temp_dir = os.path.dirname(temp_path)
        
        # Ensure the directory exists
        if temp_dir:
            os.makedirs(temp_dir, exist_ok=True)
        
        try:
            # Check if we have a partial transfer
            partial_transfer = os.path.exists(temp_path)
            if partial_transfer:
                logger.info(f"Resuming partial transfer for {transfer.file_id}")
                
                # Verify the existing temp file size makes sense
                current_size = os.path.getsize(temp_path)
                expected_size = transfer.chunk_size * len(transfer.received_chunks)
                
                if current_size > expected_size:
                    logger.warning(f"Partial transfer file is larger than expected. Truncating.")
                    with open(temp_path, 'r+b') as f:
                        f.truncate(expected_size)
                
                # Open in append mode to continue writing
                file_mode = 'r+b'
            else:
                file_mode = 'wb'
            
            with open(temp_path, file_mode) as f:
                # If this is a new transfer, ensure we start from the beginning
                if not partial_transfer:
                    f.seek(0)
                
                # Write all chunks in order
                for i in range(transfer.total_chunks):
                    if i in transfer.received_chunks:
                        # Skip if we already have this chunk written (for resuming)
                        current_pos = f.tell()
                        chunk_start = i * transfer.chunk_size
                        
                        if current_pos <= chunk_start:
                            # Seek to the correct position (in case of gaps)
                            f.seek(chunk_start)
                            
                            # Get and process the chunk
                            chunk = transfer.received_chunks[i]
                            if transfer.encryption_key:
                                try:
                                    chunk = self._decrypt_chunk(chunk, transfer.encryption_key, transfer.iv)
                                except Exception as e:
                                    logger.error(f"Error decrypting chunk {i}: {e}")
                                    raise
                            
                            # Write the chunk
                            f.write(chunk)
                            
                            # Ensure data is written to disk
                            f.flush()
                            os.fsync(f.fileno())
                            
                            # Periodically save transfer state during assembly
                            if i % 10 == 0:
                                self._save_transfer_state(transfer)
            
            # Verify file size matches expected
            actual_size = os.path.getsize(temp_path)
            if actual_size != transfer.file_size:
                raise ValueError(f"File size mismatch: expected {transfer.file_size}, got {actual_size}")
            
            # Calculate and verify file hash
            file_hash = await self._calculate_file_hash(temp_path)
            
            # If we have an expected hash in the transfer, verify it
            if hasattr(transfer, 'expected_hash') and transfer.expected_hash:
                if file_hash != transfer.expected_hash:
                    logger.error(f"File hash verification failed. Expected {transfer.expected_hash}, got {file_hash}")
                    raise ValueError(f"File hash verification failed for {transfer.file_path}")
                logger.info(f"File hash verification successful for {transfer.file_path}")
            
            # Create the parent directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(transfer.file_path)), exist_ok=True)
            
            # On Windows, we need to handle file replacement carefully
            if os.path.exists(transfer.file_path):
                if os.path.isfile(transfer.file_path):
                    os.unlink(transfer.file_path)
                else:
                    shutil.rmtree(transfer.file_path)
            
            # Atomically rename the temporary file to the final name
            os.replace(temp_path, transfer.file_path)
            
            # Update file hashes for deduplication
            self.file_hashes[file_hash] = transfer.file_path
            
            # Clean up the transfer state
            self._delete_transfer_state(transfer.file_id)
            
            logger.info(f"Successfully received and saved file: {transfer.file_path} ({transfer.file_size} bytes)")
            
        except Exception as e:
            logger.error(f"Error assembling file {transfer.file_path}: {str(e)}", exc_info=True)
            
            # Clean up the temporary file if it's corrupted
            if os.path.exists(temp_path):
                try:
                    # Only delete if it's smaller than expected (likely corrupted)
                    if os.path.getsize(temp_path) < transfer.file_size:
                        os.unlink(temp_path)
                except Exception as cleanup_error:
                    logger.error(f"Error cleaning up temporary file: {cleanup_error}")
            
            # Save the transfer state for resumption
            self._save_transfer_state(transfer)
            raise
    
    def _encrypt_chunk(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt a chunk of data using AES-256-CBC with PKCS7 padding.
        
        Args:
            data: The data to encrypt
            key: Encryption key (32 bytes for AES-256)
            iv: Initialization vector (16 bytes for AES)
            
        Returns:
            Encrypted data
        """
        # Create a padder for PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # Create cipher and encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Encrypt the data
        return encryptor.update(padded_data) + encryptor.finalize()
        
    def _decrypt_chunk(self, chunk: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt a chunk of data using AES-256-CBC with PKCS7 padding.
        
        Args:
            chunk: The encrypted data
            key: Decryption key (32 bytes for AES-256)
            iv: Initialization vector (16 bytes for AES)
            
        Returns:
            Decrypted data with padding removed
        """
        try:
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Decrypt and unpad the data
            padded_data = decryptor.update(chunk) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError(f"Failed to decrypt chunk: {e}")
    
    async def _calculate_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            # Read and update hash in chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    async def _process_transfer_queue(self) -> None:
        """Process the transfer queue and manage concurrent transfers."""
        while True:
            try:
                # Check if we can start more transfers
                while (self.active_transfer_count < self.max_concurrent_transfers and 
                       self.transfer_queue):
                    # Get the highest priority transfer
                    _, _, file_id = self.transfer_queue.pop(0)
                    
                    if file_id in self.active_transfers:
                        transfer = self.active_transfers[file_id]
                        
                        # Find the next chunk to request
                        next_chunk = self._find_next_chunk_to_request(transfer)
                        if next_chunk is not None:
                            self.active_transfer_count += 1
                            # Request the chunk in a separate task
                            asyncio.create_task(self._process_chunk_request(file_id, next_chunk))
                
                # Sleep briefly to prevent busy waiting
                await asyncio.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Error in transfer queue processing: {e}", exc_info=True)
                await asyncio.sleep(1)  # Prevent tight loop on error
    
    async def _process_chunk_request(self, file_id: str, chunk_index: int) -> None:
        """Process a single chunk request and update transfer state."""
        try:
            if file_id not in self.active_transfers:
                return
                
            transfer = self.active_transfers[file_id]
            peer_id = file_id.split('_')[0]  # Extract peer ID from file_id
            
            # Request the chunk
            await self._request_chunk(peer_id, file_id, chunk_index)
            
            # Wait for acknowledgment with timeout
            chunk = transfer.sent_chunks.get(chunk_index)
            if chunk:
                # Wait for ack or timeout
                timeout = 30  # seconds
                start_time = time.monotonic()
                
                while not chunk.ack_received:
                    if time.monotonic() - start_time > timeout:
                        logger.warning(f"Timeout waiting for chunk {chunk_index} of {file_id}")
                        break
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.error(f"Error processing chunk request: {e}", exc_info=True)
        finally:
            self.active_transfer_count -= 1
    
    def _find_next_chunk_to_request(self, transfer: FileTransfer) -> Optional[int]:
        """Find the next chunk to request based on transfer strategy."""
        # Simple sequential strategy - can be enhanced with rarest-first, etc.
        for i in range(transfer.total_chunks):
            if i not in transfer.received_chunks and i not in transfer.sent_chunks:
                return i
        return None
    
    async def _monitor_network_conditions(self) -> None:
        """Monitor network conditions and adjust transfer parameters."""
        while True:
            try:
                # Sample network conditions periodically
                # In a real implementation, this would measure actual network metrics
                
                # Update network conditions (simplified)
                now = time.monotonic()
                if now - self.network_conditions['last_updated'] > 10:  # Update every 10 seconds
                    # Simulate network condition changes
                    self.network_conditions.update({
                        'latency': max(0.05, min(1.0, 0.1 + (time.time() % 10) * 0.1)),
                        'packet_loss': max(0, min(0.2, 0.01 * (time.time() % 20))),
                        'last_updated': now
                    })
                
                await asyncio.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in network monitoring: {e}", exc_info=True)
                await asyncio.sleep(10)  # Recover from errors
    
    async def _cleanup_inactive_transfers(self) -> None:
        """Clean up inactive or stalled transfers."""
        while True:
            try:
                now = time.monotonic()
                inactive_timeout = 300  # 5 minutes
                
                for file_id in list(self.active_transfers.keys()):
                    transfer = self.active_transfers[file_id]
                    
                    # Check for stalled transfers
                    if now - transfer.last_activity > inactive_timeout:
                        logger.warning(f"Removing inactive transfer: {file_id}")
                        del self.active_transfers[file_id]
                        
                        # Also remove from queue if present
                        self.transfer_queue = [
                            (p, t, fid) for p, t, fid in self.transfer_queue 
                            if fid != file_id
                        ]
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in transfer cleanup: {e}", exc_info=True)
                await asyncio.sleep(60)  # Recover from errors
    
    def _update_network_conditions(self, rtt: float) -> None:
        """Update network conditions based on observed RTT."""
        # Simple RTT-based network condition updates
        alpha = 0.1  # Smoothing factor
        current_latency = self.network_conditions.get('latency', 0.1)
        
        # Update latency with exponential moving average
        new_latency = alpha * rtt + (1 - alpha) * current_latency
        
        # Update packet loss estimation (simplified)
        packet_loss = self.network_conditions.get('packet_loss', 0.0)
        
        self.network_conditions.update({
            'latency': new_latency,
            'packet_loss': packet_loss,
            'last_updated': time.monotonic()
        })
    
    def _generate_file_id(self, peer_id: str, file_path: Union[str, Path]) -> str:
        """Generate a unique ID for a file transfer."""
        timestamp = int(time.time() * 1000)
        random_str = os.urandom(4).hex()  # Add some randomness
        return f"{peer_id}_{os.path.basename(file_path)}_{timestamp}_{random_str}"

# Example usage:
# file_transfer = FileTransferManager(p2p_node)
# await file_transfer.send_file("peer123", "/path/to/file.txt")
