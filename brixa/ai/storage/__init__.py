"""
Storage module for AI models and artifacts.

This module provides an abstract base class for storage backends and implementations
for different storage types (local filesystem, S3, etc.).
"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import BinaryIO, Optional, Union, Dict, Any
import os


class StorageNode(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def exists(self, path: str) -> bool:
        """Check if a path exists in the storage."""
        pass
    
    @abstractmethod
    def open(self, path: str, mode: str = 'r') -> BinaryIO:
        """Open a file in the storage."""
        pass
    
    @abstractmethod
    def write(self, path: str, data: Union[bytes, str], **kwargs) -> None:
        """Write data to a file in the storage."""
        pass
    
    @abstractmethod
    def read(self, path: str, **kwargs) -> Union[bytes, str]:
        """Read data from a file in the storage."""
        pass
    
    @abstractmethod
    def delete(self, path: str) -> None:
        """Delete a file from the storage."""
        pass
    
    @abstractmethod
    def list(self, path: str) -> list[str]:
        """List contents of a directory in the storage."""
        pass
    
    @abstractmethod
    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        """Create a directory and any parent directories."""
        pass


class LocalStorageNode(StorageNode):
    """Local filesystem storage implementation."""
    
    def __init__(self, root_path: Union[str, Path] = None):
        """Initialize with optional root path."""
        self.root = Path(root_path) if root_path else Path.cwd()
    
    def _resolve_path(self, path: str) -> Path:
        """Resolve a path relative to the storage root."""
        return (self.root / path).resolve()
    
    def exists(self, path: str) -> bool:
        """Check if a path exists in the storage."""
        return self._resolve_path(path).exists()
    
    def open(self, path: str, mode: str = 'r') -> BinaryIO:
        """Open a file in the storage."""
        return open(self._resolve_path(path), mode)
    
    def write(self, path: str, data: Union[bytes, str], **kwargs) -> None:
        """Write data to a file in the storage."""
        full_path = self._resolve_path(path)
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        if 'b' in kwargs.get('mode', '') or isinstance(data, bytes):
            with open(full_path, 'wb') as f:
                f.write(data if isinstance(data, bytes) else data.encode('utf-8'))
        else:
            with open(full_path, 'w', encoding='utf-8') as f:
                f.write(data)
    
    def read(self, path: str, **kwargs) -> Union[bytes, str]:
        """Read data from a file in the storage."""
        mode = 'rb' if kwargs.get('binary', False) else 'r'
        with open(self._resolve_path(path), mode) as f:
            return f.read()
    
    def delete(self, path: str) -> None:
        """Delete a file from the storage."""
        full_path = self._resolve_path(path)
        if full_path.exists():
            if full_path.is_file() or full_path.is_symlink():
                full_path.unlink()
            else:
                import shutil
                shutil.rmtree(full_path)
    
    def list(self, path: str) -> list[str]:
        """List contents of a directory in the storage."""
        return [str(p.relative_to(self.root)) for p in self._resolve_path(path).iterdir()]
    
    def makedirs(self, path: str, exist_ok: bool = False) -> None:
        """Create a directory and any parent directories."""
        self._resolve_path(path).mkdir(parents=True, exist_ok=exist_ok)


# Default storage instance
default_storage = LocalStorageNode()
