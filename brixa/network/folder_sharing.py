"""
Advanced Folder Sharing for Brixa Network.

This module extends the file transfer functionality to support folder sharing with:
- Transfer progress tracking
- Bandwidth throttling
- Transfer scheduling
- File versioning
- File deduplication
"""
import os
import asyncio
import time
import json
import hashlib
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, Deque
from dataclasses import dataclass, field
from datetime import datetime, time as dt_time, timedelta
from collections import defaultdict, deque
import logging
import aiofiles
import aiofiles.os

# Import the enhanced file transfer module
from .enhanced_file_transfer import (
    EnhancedFileTransferManager,
    FileTransfer,
    TransferStats,
    PRIORITY_LOW,
    PRIORITY_NORMAL,
    PRIORITY_HIGH
)

logger = logging.getLogger(__name__)

# Constants
DEFAULT_CHUNK_SIZE = 256 * 1024  # 256KB
MIN_CHUNK_SIZE = 16 * 1024  # 16KB
MAX_CHUNK_SIZE = 4 * 1024 * 1024  # 4MB
MAX_FOLDER_SIZE = 100 * 1024 * 1024 * 1024  # 100GB max folder size
VERSION_HISTORY_LIMIT = 10  # Max number of versions to keep

@dataclass
class FileMetadata:
    """Metadata for a file in the shared folder."""
    path: str
    size: int
    modified: float
    checksum: str
    version: int = 1
    versions: List[Dict] = field(default_factory=list)
    is_directory: bool = False
    parent_id: Optional[str] = None
    file_id: str = field(init=False)

    def __post_init__(self):
        # Generate a unique ID for the file based on its path and modification time
        self.file_id = hashlib.sha256(
            f"{self.path}:{self.modified}".encode()
        ).hexdigest()

@dataclass
class FolderTransferProgress:
    """Tracks progress of a folder transfer."""
    total_files: int = 0
    total_size: int = 0
    transferred_files: int = 0
    transferred_size: int = 0
    current_file: Optional[str] = None
    current_file_size: int = 0
    current_file_transferred: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    transfer_speed: float = 0.0
    status: str = "pending"  # pending, transferring, paused, completed, failed
    
    @property
    def progress_percent(self) -> float:
        """Get overall transfer progress as a percentage."""
        if self.total_size == 0:
            return 0.0
        return (self.transferred_size / self.total_size) * 100
    
    @property
    def elapsed_time(self) -> float:
        """Get elapsed time in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time
    
    @property
    def remaining_time(self) -> float:
        """Get estimated remaining time in seconds."""
        if self.transferred_size == 0 or self.transfer_speed == 0:
            return float('inf')
        remaining_bytes = self.total_size - self.transferred_size
        return remaining_bytes / self.transfer_speed

class FolderSharingManager:
    """Manages folder sharing with advanced features."""
    
    def __init__(
        self,
        p2p_node,
        storage_dir: str = "data/shared_folders",
        max_bandwidth: Optional[int] = None,
        max_concurrent_transfers: int = 3
    ):
        """Initialize the folder sharing manager.
        
        Args:
            p2p_node: Reference to the P2P node
            storage_dir: Base directory for shared folders
            max_bandwidth: Maximum bandwidth in bytes per second (None for unlimited)
            max_concurrent_transfers: Maximum number of concurrent file transfers
        """
        self.p2p_node = p2p_node
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize file transfer manager
        self.transfer_manager = EnhancedFileTransferManager(
            p2p_node=p2p_node,
            storage_dir=str(self.storage_dir),
            max_bandwidth=max_bandwidth
        )
        
        # Track shared folders and their metadata
        self.shared_folders: Dict[str, Dict] = {}
        self.folder_metadata: Dict[str, Dict[str, FileMetadata]] = defaultdict(dict)
        self.transfer_progress: Dict[str, FolderTransferProgress] = {}
        
        # Bandwidth management
        self.max_bandwidth = max_bandwidth
        self.current_bandwidth = 0
        self.bandwidth_history: Deque[Tuple[float, int]] = deque(maxlen=60)  # (timestamp, bytes)
        
        # Transfer scheduling
        self.scheduled_transfers: Dict[str, asyncio.Task] = {}
        self.transfer_queue: asyncio.Queue = asyncio.Queue()
        
        # File deduplication
        self.file_checksums: Dict[str, Set[str]] = defaultdict(set)  # checksum -> set of file_ids
        
        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_old_versions())
        self.monitor_task = asyncio.create_task(self._monitor_bandwidth())
        self.process_queue_task = asyncio.create_task(self._process_transfer_queue())
    
    # --- Folder Management ---
    
    async def share_folder(
        self,
        folder_path: Union[str, Path],
        folder_name: Optional[str] = None,
        read_only: bool = False,
        max_versions: int = VERSION_HISTORY_LIMIT
    ) -> str:
        """Share a folder with the network.
        
        Args:
            folder_path: Path to the folder to share
            folder_name: Optional name for the shared folder (defaults to folder basename)
            read_only: Whether the folder is read-only
            max_versions: Maximum number of versions to keep for each file
            
        Returns:
            str: Folder ID for the shared folder
        """
        folder_path = Path(folder_path).absolute()
        
        if not folder_path.is_dir():
            raise ValueError(f"Not a directory: {folder_path}")
        
        # Generate a unique folder ID
        folder_id = hashlib.sha256(
            f"{folder_path}:{time.time()}".encode()
        ).hexdigest()
        
        # Create folder metadata
        folder_name = folder_name or folder_path.name
        
        # Scan the folder and create metadata for all files
        await self._scan_folder(folder_path, folder_id)
        
        # Store folder information
        self.shared_folders[folder_id] = {
            'path': str(folder_path),
            'name': folder_name,
            'read_only': read_only,
            'max_versions': max_versions,
            'created_at': time.time(),
            'updated_at': time.time(),
            'owner_id': self.p2p_node.node_id
        }
        
        # Save folder metadata
        await self._save_folder_metadata(folder_id)
        
        logger.info(f"Shared folder '{folder_name}' with ID: {folder_id}")
        return folder_id
    
    async def _scan_folder(self, folder_path: Path, folder_id: str, parent_id: Optional[str] = None):
        """Recursively scan a folder and create metadata for all files."""
        try:
            # Process all entries in the folder
            for entry in folder_path.iterdir():
                try:
                    if entry.is_dir():
                        # Recursively scan subdirectories
                        await self._scan_folder(entry, folder_id, parent_id)
                    else:
                        # Process file
                        stat = entry.stat()
                        rel_path = str(entry.relative_to(folder_path))
                        
                        # Calculate file checksum (in a separate thread to avoid blocking)
                        checksum = await asyncio.get_running_loop().run_in_executor(
                            None,
                            self._calculate_file_checksum,
                            entry
                        )
                        
                        # Create file metadata
                        file_meta = FileMetadata(
                            path=rel_path,
                            size=stat.st_size,
                            modified=stat.st_mtime,
                            checksum=checksum,
                            parent_id=parent_id
                        )
                        
                        # Store metadata
                        self.folder_metadata[folder_id][file_meta.file_id] = file_meta
                        
                        # Update checksum index for deduplication
                        self.file_checksums[checksum].add(file_meta.file_id)
                        
                except Exception as e:
                    logger.error(f"Error processing {entry}: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Error scanning folder {folder_path}: {e}")
            raise
    
    # --- File Versioning ---
    
    async def create_file_version(self, folder_id: str, file_path: Union[str, Path]) -> bool:
        """Create a new version of a file.
        
        Args:
            folder_id: ID of the shared folder
            file_path: Path to the file within the shared folder
            
        Returns:
            bool: True if version was created, False otherwise
        """
        file_path = str(file_path)
        folder_meta = self.shared_folders.get(folder_id)
        
        if not folder_meta:
            logger.error(f"Unknown folder ID: {folder_id}")
            return False
        
        # Find the file in the folder metadata
        file_meta = next(
            (f for f in self.folder_metadata[folder_id].values() 
             if f.path == file_path and not f.is_directory),
            None
        )
        
        if not file_meta:
            logger.error(f"File not found in folder {folder_id}: {file_path}")
            return False
        
        # Create a version entry
        version_entry = {
            'version': file_meta.version,
            'modified': time.time(),
            'size': file_meta.size,
            'checksum': file_meta.checksum
        }
        
        # Add to version history
        file_meta.versions.append(version_entry)
        
        # Limit the number of versions
        max_versions = folder_meta.get('max_versions', VERSION_HISTORY_LIMIT)
        if len(file_meta.versions) > max_versions:
            # Remove oldest versions (keeping the most recent ones)
            file_meta.versions = file_meta.versions[-max_versions:]
        
        # Increment version number
        file_meta.version += 1
        
        # Update file metadata
        stat = (Path(folder_meta['path']) / file_path).stat()
        file_meta.size = stat.st_size
        file_meta.modified = stat.st_mtime
        
        # Update checksum
        file_meta.checksum = await asyncio.get_running_loop().run_in_executor(
            None,
            self._calculate_file_checksum,
            Path(folder_meta['path']) / file_path
        )
        
        # Save updated metadata
        await self._save_folder_metadata(folder_id)
        
        logger.info(f"Created version {file_meta.version - 1} of {file_path} in folder {folder_id}")
        return True
    
    async def get_file_version(self, folder_id: str, file_path: str, version: int) -> Optional[bytes]:
        """Retrieve a specific version of a file.
        
        Args:
            folder_id: ID of the shared folder
            file_path: Path to the file within the shared folder
            version: Version number to retrieve
            
        Returns:
            Optional[bytes]: File content if found, None otherwise
        """
        folder_meta = self.shared_folders.get(folder_id)
        if not folder_meta:
            logger.error(f"Unknown folder ID: {folder_id}")
            return None
        
        # Find the file in the folder metadata
        file_meta = next(
            (f for f in self.folder_metadata[folder_id].values() 
             if f.path == file_path and not f.is_directory),
            None
        )
        
        if not file_meta:
            logger.error(f"File not found in folder {folder_id}: {file_path}")
            return None
        
        # Check if the requested version exists
        version_entry = next(
            (v for v in file_meta.versions if v['version'] == version),
            None
        )
        
        if not version_entry:
            logger.error(f"Version {version} not found for file {file_path}")
            return None
        
        # In a real implementation, you would retrieve the file content from storage
        # For now, we'll just return None as a placeholder
        # You would typically have a versioned storage system to retrieve old versions
        
        return None
    
    # --- File Deduplication ---
    
    async def deduplicate_files(self, folder_id: str) -> int:
        """Remove duplicate files in a shared folder.
        
        Args:
            folder_id: ID of the shared folder
            
        Returns:
            int: Number of duplicate files removed
        """
        if folder_id not in self.shared_folders:
            logger.error(f"Unknown folder ID: {folder_id}")
            return 0
        
        # Track checksums we've seen
        checksum_map = {}
        duplicates_removed = 0
        
        # Check all files in the folder
        for file_id, file_meta in list(self.folder_metadata[folder_id].items()):
            if file_meta.is_directory:
                continue
                
            if file_meta.checksum in checksum_map:
                # Found a duplicate
                original_file = checksum_map[file_meta.checksum]
                
                # Skip if this is the original file
                if file_id == original_file.file_id:
                    continue
                
                # Create a hard link to the original file
                try:
                    folder_path = Path(self.shared_folders[folder_id]['path'])
                    file_path = folder_path / file_meta.path
                    original_path = folder_path / original_file.path
                    
                    # Only proceed if the file exists and is different from the original
                    if file_path.exists() and original_path.exists() and file_path != original_path:
                        # Create a hard link to the original file
                        await aiofiles.os.link(original_path, file_path)
                        duplicates_removed += 1
                        
                        logger.info(f"Deduplicated {file_meta.path} -> {original_file.path}")
                        
                except Exception as e:
                    logger.error(f"Error deduplicating {file_meta.path}: {e}")
                    continue
            else:
                # First time seeing this checksum, store the file metadata
                checksum_map[file_meta.checksum] = file_meta
        
        if duplicates_removed > 0:
            # Rescan the folder to update metadata
            await self._scan_folder(
                Path(self.shared_folders[folder_id]['path']),
                folder_id
            )
            
            # Save updated metadata
            await self._save_folder_metadata(folder_id)
        
        return duplicates_removed
    
    # --- Transfer Scheduling ---
    
    async def schedule_folder_sync(
        self,
        folder_id: str,
        peer_id: str,
        schedule: str = "daily",  # "hourly", "daily", "weekly", or cron expression
        start_time: Optional[dt_time] = None,
        priority: int = PRIORITY_NORMAL
    ) -> str:
        """Schedule regular synchronization of a folder with a peer.
        
        Args:
            folder_id: ID of the shared folder
            peer_id: ID of the peer to sync with
            schedule: Schedule frequency or cron expression
            start_time: Optional start time for daily/weekly schedules
            priority: Transfer priority
            
        Returns:
            str: Schedule ID
        """
        if folder_id not in self.shared_folders:
            raise ValueError(f"Unknown folder ID: {folder_id}")
        
        # Generate a unique schedule ID
        schedule_id = hashlib.sha256(
            f"{folder_id}:{peer_id}:{time.time()}".encode()
        ).hexdigest()
        
        # Create a task for the scheduled sync
        async def sync_task():
            try:
                while True:
                    # Calculate next run time
                    now = datetime.now()
                    
                    if schedule == "hourly":
                        next_run = now + timedelta(hours=1)
                        next_run = next_run.replace(minute=0, second=0, microsecond=0)
                    elif schedule == "daily":
                        next_run = now.replace(
                            hour=start_time.hour if start_time else 0,
                            minute=start_time.minute if start_time else 0,
                            second=0,
                            microsecond=0
                        )
                        if next_run <= now:
                            next_run += timedelta(days=1)
                    elif schedule == "weekly":
                        next_run = now.replace(
                            hour=start_time.hour if start_time else 0,
                            minute=start_time.minute if start_time else 0,
                            second=0,
                            microsecond=0
                        )
                        # Next week's same day
                        next_run += timedelta(days=7)
                    else:
                        # For cron expressions, you would use a cron parser
                        # This is a simplified example
                        logger.warning("Cron expressions are not fully implemented")
                        next_run = now + timedelta(days=1)
                    
                    # Calculate sleep time
                    sleep_time = (next_run - now).total_seconds()
                    if sleep_time > 0:
                        await asyncio.sleep(sleep_time)
                    
                    # Perform the sync
                    try:
                        await self.sync_folder_with_peer(folder_id, peer_id, priority=priority)
                    except Exception as e:
                        logger.error(f"Error during scheduled sync: {e}")
                        # Add some delay before retrying on error
                        await asyncio.sleep(60)
                    
            except asyncio.CancelledError:
                # Task was cancelled
                logger.info(f"Scheduled sync {schedule_id} was cancelled")
            except Exception as e:
                logger.error(f"Scheduled sync task failed: {e}")
        
        # Start the scheduled task
        self.scheduled_transfers[schedule_id] = asyncio.create_task(sync_task())
        
        logger.info(f"Scheduled {schedule} sync of folder {folder_id} with peer {peer_id}")
        return schedule_id
    
    async def cancel_scheduled_sync(self, schedule_id: str) -> bool:
        """Cancel a scheduled folder sync.
        
        Args:
            schedule_id: ID of the schedule to cancel
            
        Returns:
            bool: True if the schedule was cancelled, False otherwise
        """
        task = self.scheduled_transfers.pop(schedule_id, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return True
        return False
    
    # --- Transfer Management ---
    
    async def sync_folder_with_peer(
        self,
        folder_id: str,
        peer_id: str,
        priority: int = PRIORITY_NORMAL
    ) -> str:
        """Synchronize a folder with a peer.
        
        Args:
            folder_id: ID of the shared folder
            peer_id: ID of the peer to sync with
            priority: Transfer priority
            
        Returns:
            str: Transfer ID for tracking progress
        """
        if folder_id not in self.shared_folders:
            raise ValueError(f"Unknown folder ID: {folder_id}")
        
        # Generate a unique transfer ID
        transfer_id = hashlib.sha256(
            f"{folder_id}:{peer_id}:{time.time()}".encode()
        ).hexdigest()
        
        # Initialize transfer progress
        self.transfer_progress[transfer_id] = FolderTransferProgress()
        
        # Add to transfer queue
        await self.transfer_queue.put((transfer_id, folder_id, peer_id, priority))
        
        logger.info(f"Started folder sync {transfer_id} for folder {folder_id} with peer {peer_id}")
        return transfer_id
    
    async def get_transfer_progress(self, transfer_id: str) -> Optional[FolderTransferProgress]:
        """Get the current progress of a folder transfer.
        
        Args:
            transfer_id: ID of the transfer
            
        Returns:
            Optional[FolderTransferProgress]: Transfer progress, or None if not found
        """
        return self.transfer_progress.get(transfer_id)
    
    async def pause_transfer(self, transfer_id: str) -> bool:
        """Pause an active transfer.
        
        Args:
            transfer_id: ID of the transfer to pause
            
        Returns:
            bool: True if the transfer was paused, False otherwise
        """
        # In a real implementation, you would need to track and pause individual file transfers
        # This is a simplified example
        if transfer_id in self.transfer_progress:
            self.transfer_progress[transfer_id].status = "paused"
            return True
        return False
    
    async def resume_transfer(self, transfer_id: str) -> bool:
        """Resume a paused transfer.
        
        Args:
            transfer_id: ID of the transfer to resume
            
        Returns:
            bool: True if the transfer was resumed, False otherwise
        """
        if transfer_id in self.transfer_progress:
            self.transfer_progress[transfer_id].status = "transferring"
            # In a real implementation, you would resume the actual transfer
            return True
        return False
    
    async def cancel_transfer(self, transfer_id: str) -> bool:
        """Cancel an active or queued transfer.
        
        Args:
            transfer_id: ID of the transfer to cancel
            
        Returns:
            bool: True if the transfer was cancelled, False otherwise
        """
        if transfer_id in self.transfer_progress:
            self.transfer_progress[transfer_id].status = "cancelled"
            # In a real implementation, you would cancel the actual transfer
            return True
        return False
    
    # --- Bandwidth Management ---
    
    async def set_bandwidth_limit(self, max_bandwidth: Optional[int]):
        """Set the maximum bandwidth usage in bytes per second.
        
        Args:
            max_bandwidth: Maximum bandwidth in bytes per second, or None for unlimited
        """
        self.max_bandwidth = max_bandwidth
        self.transfer_manager.max_bandwidth = max_bandwidth
    
    async def get_current_bandwidth_usage(self) -> float:
        """Get the current bandwidth usage in bytes per second.
        
        Returns:
            float: Current bandwidth usage in bytes per second
        """
        return self.current_bandwidth
    
    async def _monitor_bandwidth(self):
        """Background task to monitor and control bandwidth usage."""
        while True:
            try:
                # Calculate current bandwidth usage
                now = time.time()
                
                # Remove old entries (older than 1 second)
                while self.bandwidth_history and (now - self.bandwidth_history[0][0]) > 1.0:
                    self.bandwidth_history.popleft()
                
                # Calculate current bandwidth (bytes per second)
                if len(self.bandwidth_history) >= 2:
                    time_span = self.bandwidth_history[-1][0] - self.bandwidth_history[0][0]
                    if time_span > 0:
                        bytes_transferred = sum(b for _, b in self.bandwidth_history)
                        self.current_bandwidth = bytes_transferred / time_span
                
                # Apply bandwidth limiting if needed
                if self.max_bandwidth is not None and self.current_bandwidth > self.max_bandwidth:
                    # Calculate how much to sleep to stay under the limit
                    over_by = self.current_bandwidth - self.max_bandwidth
                    sleep_time = over_by / self.max_bandwidth  # Proportional sleep time
                    
                    # Sleep to throttle the transfer rate
                    await asyncio.sleep(min(sleep_time, 1.0))  # Don't sleep too long
                else:
                    # No need to throttle, just yield control
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Error in bandwidth monitor: {e}")
                await asyncio.sleep(1)
    
    # --- Background Tasks ---
    
    async def _process_transfer_queue(self):
        """Background task to process the transfer queue."""
        while True:
            try:
                # Get the next transfer from the queue
                transfer_id, folder_id, peer_id, priority = await self.transfer_queue.get()
                
                # Get the transfer progress
                progress = self.transfer_progress.get(transfer_id)
                if not progress:
                    logger.error(f"No progress tracker found for transfer {transfer_id}")
                    continue
                
                # Update status
                progress.status = "transferring"
                
                # Get the folder metadata
                if folder_id not in self.shared_folders:
                    logger.error(f"Unknown folder ID: {folder_id}")
                    progress.status = "failed"
                    continue
                
                folder_meta = self.shared_folders[folder_id]
                folder_path = Path(folder_meta['path'])
                
                # Scan the folder to get current file list
                await self._scan_folder(folder_path, folder_id)
                
                # Get list of files to transfer
                files_to_transfer = [
                    (f.path, f.size) 
                    for f in self.folder_metadata[folder_id].values() 
                    if not f.is_directory
                ]
                
                # Update progress
                progress.total_files = len(files_to_transfer)
                progress.total_size = sum(size for _, size in files_to_transfer)
                
                # Transfer each file
                for file_path, file_size in files_to_transfer:
                    # Check if transfer was cancelled
                    if progress.status == "cancelled":
                        break
                    
                    # Skip if paused
                    while progress.status == "paused":
                        await asyncio.sleep(1)
                    
                    # Update current file
                    progress.current_file = file_path
                    progress.current_file_size = file_size
                    progress.current_file_transferred = 0
                    
                    try:
                        # Start file transfer
                        file_transfer_id = await self.transfer_manager.send_file(
                            peer_id=peer_id,
                            file_path=str(folder_path / file_path),
                            priority=priority,
                            generate_preview=True,
                            compress=True
                        )
                        
                        # Monitor file transfer progress
                        while True:
                            await asyncio.sleep(0.5)  # Update interval
                            
                            # Get file transfer progress
                            file_transfer = self.transfer_manager.active_transfers.get(file_transfer_id)
                            if not file_transfer:
                                break
                                
                            # Update progress
                            if file_transfer.is_complete:
                                progress.transferred_files += 1
                                progress.transferred_size += file_size
                                progress.current_file = None
                                progress.current_file_size = 0
                                progress.current_file_transferred = 0
                                break
                            
                            # Update current file progress
                            if file_transfer.received_size > 0:
                                progress.current_file_transferred = file_transfer.received_size
                            
                            # Update transfer speed
                            progress.transfer_speed = file_transfer.transfer_speed
                            
                    except Exception as e:
                        logger.error(f"Error transferring file {file_path}: {e}")
                        progress.error_count += 1
                        
                        # Retry logic could be added here
                        
                # Update status
                if progress.status != "cancelled":
                    progress.status = "completed"
                
                progress.end_time = time.time()
                
            except Exception as e:
                logger.error(f"Error in transfer queue processing: {e}")
                if transfer_id in self.transfer_progress:
                    self.transfer_progress[transfer_id].status = "failed"
                
            finally:
                # Mark the task as done
                self.transfer_queue.task_done()
    
    async def _cleanup_old_versions(self):
        """Background task to clean up old file versions."""
        while True:
            try:
                for folder_id, folder_meta in list(self.shared_folders.items()):
                    max_versions = folder_meta.get('max_versions', VERSION_HISTORY_LIMIT)
                    
                    # In a real implementation, you would clean up old versions from storage
                    # This is a simplified example that just updates the metadata
                    for file_meta in self.folder_metadata[folder_id].values():
                        if len(file_meta.versions) > max_versions:
                            # Remove oldest versions
                            file_meta.versions = file_meta.versions[-max_versions:]
                
                # Save updated metadata
                for folder_id in self.shared_folders:
                    await self._save_folder_metadata(folder_id)
                
                # Wait before next cleanup (e.g., once per day)
                await asyncio.sleep(24 * 60 * 60)
                
            except Exception as e:
                logger.error(f"Error in version cleanup task: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    # --- Helper Methods ---
    
    async def _save_folder_metadata(self, folder_id: str):
        """Save folder metadata to disk."""
        if folder_id not in self.shared_folders:
            return
        
        try:
            metadata_dir = self.storage_dir / "metadata"
            metadata_dir.mkdir(exist_ok=True)
            
            # Prepare metadata for serialization
            metadata = {
                'folder': self.shared_folders[folder_id],
                'files': {
                    file_id: {
                        'path': meta.path,
                        'size': meta.size,
                        'modified': meta.modified,
                        'checksum': meta.checksum,
                        'version': meta.version,
                        'versions': meta.versions,
                        'is_directory': meta.is_directory,
                        'parent_id': meta.parent_id,
                        'file_id': meta.file_id
                    }
                    for file_id, meta in self.folder_metadata[folder_id].items()
                }
            }
            
            # Save to file
            async with aiofiles.open(metadata_dir / f"{folder_id}.json", 'w') as f:
                await f.write(json.dumps(metadata, indent=2))
                
        except Exception as e:
            logger.error(f"Error saving folder metadata: {e}")
    
    async def _load_folder_metadata(self, folder_id: str) -> bool:
        """Load folder metadata from disk.
        
        Returns:
            bool: True if metadata was loaded successfully, False otherwise
        """
        try:
            metadata_dir = self.storage_dir / "metadata"
            metadata_file = metadata_dir / f"{folder_id}.json"
            
            if not metadata_file.exists():
                return False
            
            # Load metadata from file
            async with aiofiles.open(metadata_file, 'r') as f:
                data = json.loads(await f.read())
            
            # Update in-memory data
            self.shared_folders[folder_id] = data['folder']
            
            self.folder_metadata[folder_id] = {}
            for file_id, meta_data in data['files'].items():
                file_meta = FileMetadata(
                    path=meta_data['path'],
                    size=meta_data['size'],
                    modified=meta_data['modified'],
                    checksum=meta_data['checksum'],
                    version=meta_data.get('version', 1),
                    versions=meta_data.get('versions', []),
                    is_directory=meta_data.get('is_directory', False),
                    parent_id=meta_data.get('parent_id')
                )
                self.folder_metadata[folder_id][file_id] = file_meta
                
                # Update checksum index for deduplication
                self.file_checksums[file_meta.checksum].add(file_meta.file_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading folder metadata: {e}")
            return False
    
    def _calculate_file_checksum(self, file_path: Path) -> str:
        """Calculate the SHA-256 checksum of a file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            # Read and update hash in chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        
        return sha256_hash.hexdigest()
    
    async def close(self):
        """Clean up resources."""
        # Cancel all scheduled transfers
        for task in self.scheduled_transfers.values():
            task.cancel()
        
        # Cancel background tasks
        self.cleanup_task.cancel()
        self.monitor_task.cancel()
        self.process_queue_task.cancel()
        
        # Wait for tasks to complete
        try:
            await asyncio.gather(
                self.cleanup_task,
                self.monitor_task,
                self.process_queue_task,
                return_exceptions=True
            )
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")
        
        # Close the transfer manager
        await self.transfer_manager.close()

# Example usage
async def example_usage():
    # Create a mock P2P node
    class MockP2PNode:
        def __init__(self):
            self.node_id = "node_123"
            self.message_handlers = {}
            
        def register_message_handler(self, msg_type, handler):
            self.message_handlers[msg_type] = handler
            
        async def send_message(self, peer_id, msg_type, message):
            print(f"Sending {msg_type} to {peer_id}: {message}")
    
    # Initialize the folder sharing manager
    p2p_node = MockP2PNode()
    folder_manager = FolderSharingManager(p2p_node)
    
    try:
        # Share a folder
        folder_path = "/path/to/shared/folder"
        folder_id = await folder_manager.share_folder(
            folder_path=folder_path,
            folder_name="My Shared Folder",
            read_only=False
        )
        
        print(f"Shared folder with ID: {folder_id}")
        
        # Schedule a daily sync with a peer
        schedule_id = await folder_manager.schedule_folder_sync(
            folder_id=folder_id,
            peer_id="peer_456",
            schedule="daily",
            start_time=dt_time(hour=2, minute=30)  # 2:30 AM
        )
        
        print(f"Scheduled daily sync with ID: {schedule_id}")
        
        # Manually sync with a peer
        transfer_id = await folder_manager.sync_folder_with_peer(
            folder_id=folder_id,
            peer_id="peer_456"
        )
        
        print(f"Started folder sync with ID: {transfer_id}")
        
        # Monitor progress
        while True:
            progress = await folder_manager.get_transfer_progress(transfer_id)
            if not progress:
                break
                
            print(f"Progress: {progress.progress_percent:.1f}% "
                  f"({progress.transferred_size}/{progress.total_size} bytes)")
            
            if progress.status in ["completed", "failed", "cancelled"]:
                print(f"Transfer {progress.status} after {progress.elapsed_time:.1f} seconds")
                break
                
            await asyncio.sleep(1)
        
    finally:
        # Clean up
        await folder_manager.close()

if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
