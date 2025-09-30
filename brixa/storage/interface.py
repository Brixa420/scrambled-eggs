"""
Storage interfaces for the Brixa distributed storage system.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union, BinaryIO, AsyncIterator
from dataclasses import dataclass
from datetime import datetime


@dataclass
class VersionInfo:
    """Represents version information for a stored value."""
    version_id: str
    timestamp: datetime
    size: int
    metadata: Dict[str, Any] = None


class KeyValueStore(ABC):
    """Abstract base class for key-value storage."""
    
    @abstractmethod
    async def get(self, key: str) -> Optional[bytes]:
        """Retrieve a value by key."""
        pass
    
    @abstractmethod
    async def set(self, key: str, value: bytes, **metadata) -> bool:
        """Store a value with the given key and metadata."""
        pass
    
    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a key-value pair."""
        pass
    
    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        pass


class ContentAddressableStorage(ABC):
    """Abstract base class for content-addressable storage."""
    
    @abstractmethod
    async def put(self, data: bytes, **metadata) -> str:
        """
        Store data and return its content address.
        
        Args:
            data: The binary data to store
            metadata: Optional metadata to associate with the data
            
        Returns:
            str: The content address (hash) of the stored data
        """
        pass
    
    @abstractmethod
    async def get(self, content_address: str) -> Optional[bytes]:
        """
        Retrieve data by its content address.
        
        Args:
            content_address: The content address (hash) of the data to retrieve
            
        Returns:
            Optional[bytes]: The stored data, or None if not found
        """
        pass
    
    @abstractmethod
    async def exists(self, content_address: str) -> bool:
        """Check if content exists in storage."""
        pass


class VersionedStorage(KeyValueStore):
    """Abstract base class for versioned key-value storage."""
    
    @abstractmethod
    async def get_version(self, key: str, version_id: str) -> Optional[bytes]:
        """Retrieve a specific version of a value."""
        pass
    
    @abstractmethod
    async def list_versions(self, key: str) -> List[VersionInfo]:
        """List all versions of a value."""
        pass
    
    @abstractmethod
    async def delete_version(self, key: str, version_id: str) -> bool:
        """Delete a specific version of a value."""
        pass
