"""
Decentralized video storage module for the Scrambled Eggs platform.
Handles distributed storage of video content using IPFS and blockchain.
"""

import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, BinaryIO, AsyncIterator

import aioipfs
from web3 import Web3

from ..core.config import settings
from ..network.p2p import P2PNetwork

logger = logging.getLogger(__name__)

@dataclass
class VideoChunk:
    """Represents a chunk of video data."""
    chunk_id: str
    data: bytes
    index: int
    total_chunks: int
    content_hash: str
    metadata: Dict = field(default_factory=dict)

@dataclass
class VideoMetadata:
    """Metadata for a video file."""
    video_id: str
    title: str
    description: str
    duration: float  # in seconds
    width: int
    height: int
    format: str
    size: int  # in bytes
    created_at: float
    updated_at: float
    owner: str
    storage_nodes: List[str] = field(default_factory=list)
    chunks: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert metadata to dictionary."""
        return {
            "video_id": self.video_id,
            "title": self.title,
            "description": self.description,
            "duration": self.duration,
            "width": self.width,
            "height": self.height,
            "format": self.format,
            "size": self.size,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "owner": self.owner,
            "storage_nodes": self.storage_nodes,
            "chunks": self.chunks
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'VideoMetadata':
        """Create VideoMetadata from dictionary."""
        return cls(**data)

class VideoStorage:
    """Manages decentralized video storage using IPFS and blockchain."""
    
    def __init__(
        self,
        p2p_network: P2PNetwork,
        ipfs_host: str = 'localhost',
        ipfs_port: int = 5001,
        chunk_size: int = 1024 * 1024  # 1MB chunks
    ):
        self.p2p_network = p2p_network
        self.chunk_size = chunk_size
        self._ipfs_client = aioipfs.AsyncIPFS(host=ipfs_host, port=ipfs_port)
        self._videos: Dict[str, VideoMetadata] = {}
        self._chunk_cache: Dict[str, bytes] = {}
        
        # Initialize storage directory
        self.storage_dir = Path(settings.STORAGE_DIR) / "videos"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> None:
        """Initialize the storage system."""
        try:
            # Check if IPFS is running
            await self._ipfs_client.id()
            logger.info("Connected to IPFS node")
        except Exception as e:
            logger.error(f"Failed to connect to IPFS: {e}")
            raise
    
    async def store_video(
        self,
        file_path: str,
        title: str,
        description: str = "",
        owner: str = ""
    ) -> str:
        """
        Store a video file in the decentralized storage.
        
        Args:
            file_path: Path to the video file
            title: Title of the video
            description: Optional description
            owner: Owner's address or identifier
            
        Returns:
            str: Video ID
        """
        video_id = self._generate_video_id(file_path)
        
        # Get file info
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"Video file not found: {file_path}")
        
        # Create video metadata
        metadata = VideoMetadata(
            video_id=video_id,
            title=title,
            description=description,
            duration=0,  # Will be updated after processing
            width=0,
            height=0,
            format=file_path.suffix.lstrip('.').lower(),
            size=file_path.stat().st_size,
            created_at=time.time(),
            updated_at=time.time(),
            owner=owner or self.p2p_network.node_id
        )
        
        # Process video in chunks
        chunk_paths = []
        try:
            with open(file_path, 'rb') as f:
                chunk_index = 0
                total_chunks = (file_path.stat().st_size + self.chunk_size - 1) // self.chunk_size
                
                while True:
                    chunk_data = f.read(self.chunk_size)
                    if not chunk_data:
                        break
                        
                    # Create chunk ID
                    chunk_id = f"{video_id}_chunk_{chunk_index:06d}"
                    content_hash = self._calculate_hash(chunk_data)
                    
                    # Store chunk in IPFS
                    ipfs_hash = await self._store_chunk(chunk_data)
                    
                    # Update metadata
                    metadata.chunks.append({
                        'chunk_id': chunk_id,
                        'index': chunk_index,
                        'size': len(chunk_data),
                        'ipfs_hash': ipfs_hash,
                        'content_hash': content_hash
                    })
                    
                    chunk_index += 1
                    
                    # Update progress
                    progress = min(100, int((chunk_index / total_chunks) * 100))
                    logger.info(f"Uploading video: {progress}% complete")
            
            # Store metadata in IPFS
            metadata_ipfs_hash = await self._store_metadata(metadata)
            
            # Store reference in local storage
            self._videos[video_id] = metadata
            
            # TODO: Store reference in blockchain
            # await self._store_on_blockchain(video_id, metadata_ipfs_hash)
            
            logger.info(f"Video stored successfully. Video ID: {video_id}")
            return video_id
            
        except Exception as e:
            logger.error(f"Failed to store video: {e}")
            # Clean up any stored chunks
            await self._cleanup_chunks(metadata.chunks)
            raise
    
    async def retrieve_video(self, video_id: str, output_path: str) -> None:
        """
        Retrieve a video from storage.
        
        Args:
            video_id: ID of the video to retrieve
            output_path: Path to save the retrieved video
        """
        if video_id not in self._videos:
            # Try to load from blockchain if not in local cache
            await self._load_video_metadata(video_id)
        
        metadata = self._videos.get(video_id)
        if not metadata:
            raise ValueError(f"Video not found: {video_id}")
        
        # Sort chunks by index
        chunks = sorted(metadata.chunks, key=lambda x: x['index'])
        
        # Download and assemble chunks
        try:
            with open(output_path, 'wb') as f:
                for chunk_info in chunks:
                    chunk_data = await self._retrieve_chunk(chunk_info['ipfs_hash'])
                    f.write(chunk_data)
                    
                    # Update progress
                    progress = min(100, int(((chunk_info['index'] + 1) / len(chunks)) * 100))
                    logger.info(f"Downloading video: {progress}% complete")
            
            logger.info(f"Video retrieved successfully to: {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to retrieve video: {e}")
            # Clean up partially downloaded file
            if os.path.exists(output_path):
                os.remove(output_path)
            raise
    
    async def delete_video(self, video_id: str) -> None:
        """
        Delete a video from storage.
        
        Args:
            video_id: ID of the video to delete
        """
        if video_id not in self._videos:
            await self._load_video_metadata(video_id)
        
        metadata = self._videos.get(video_id)
        if not metadata:
            return
        
        try:
            # Delete chunks from IPFS
            await self._cleanup_chunks(metadata.chunks)
            
            # TODO: Update blockchain to mark as deleted
            
            # Remove from local cache
            self._videos.pop(video_id, None)
            
            logger.info(f"Video deleted: {video_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete video {video_id}: {e}")
            raise
    
    async def get_video_metadata(self, video_id: str) -> Optional[VideoMetadata]:
        """Get metadata for a video."""
        if video_id not in self._videos:
            await self._load_video_metadata(video_id)
        return self._videos.get(video_id)
    
    async def _store_chunk(self, data: bytes) -> str:
        """Store a chunk of data in IPFS and return its hash."""
        try:
            result = await self._ipfs_client.add_bytes(data)
            return result['Hash']
        except Exception as e:
            logger.error(f"Failed to store chunk in IPFS: {e}")
            raise
    
    async def _retrieve_chunk(self, ipfs_hash: str) -> bytes:
        """Retrieve a chunk of data from IPFS."""
        # Check cache first
        if ipfs_hash in self._chunk_cache:
            return self._chunk_cache[ipfs_hash]
        
        try:
            data = await self._ipfs_client.cat(ipfs_hash)
            # Cache the chunk
            self._chunk_cache[ipfs_hash] = data
            return data
        except Exception as e:
            logger.error(f"Failed to retrieve chunk {ipfs_hash} from IPFS: {e}")
            raise
    
    async def _store_metadata(self, metadata: VideoMetadata) -> str:
        """Store video metadata in IPFS and return its hash."""
        try:
            metadata_dict = metadata.to_dict()
            metadata_json = json.dumps(metadata_dict).encode()
            result = await self._ipfs_client.add_bytes(metadata_json)
            return result['Hash']
        except Exception as e:
            logger.error(f"Failed to store metadata in IPFS: {e}")
            raise
    
    async def _load_video_metadata(self, video_id: str) -> None:
        """Load video metadata from blockchain or other storage nodes."""
        # TODO: Implement loading from blockchain or other nodes
        # This is a placeholder implementation
        raise NotImplementedError("Loading video metadata from blockchain is not implemented yet")
    
    async def _cleanup_chunks(self, chunks: List[Dict]) -> None:
        """Clean up chunks from storage."""
        # TODO: Implement proper cleanup in a real system
        # In a real implementation, we would unpin the chunks from IPFS
        # and update any references in the blockchain
        pass
    
    def _generate_video_id(self, file_path: str) -> str:
        """Generate a unique video ID based on file content and timestamp."""
        file_path = Path(file_path)
        timestamp = int(time.time() * 1000)
        unique_str = f"{file_path.name}_{timestamp}_{os.urandom(8).hex()}"
        return hashlib.sha256(unique_str.encode()).hexdigest()
    
    @staticmethod
    def _calculate_hash(data: bytes) -> str:
        """Calculate the SHA-256 hash of the data."""
        return hashlib.sha256(data).hexdigest()
    
    async def close(self) -> None:
        """Clean up resources."""
        await self._ipfs_client.close()
        self._chunk_cache.clear()
