"""
Storage node implementation for the Brixa distributed storage system.
"""
import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, AsyncIterator, Tuple

from ..network.p2p import P2PNode
from .interface import KeyValueStore, ContentAddressableStorage, VersionedStorage, VersionInfo
from .merkle_dag import MerkleDAG, DAGNode


class StorageNode(VersionedStorage):
    """
    A node in the Brixa distributed storage network.
    This implements both key-value storage and versioned storage interfaces.
    """
    
    def __init__(
        self,
        node_id: str,
        data_dir: Path,
        p2p_node: P2PNode,
        merkle_dag: Optional[MerkleDAG] = None,
        block_size: int = 1024 * 1024,  # 1MB blocks by default
        replication_factor: int = 3,
    ):
        """
        Initialize the storage node.

        Args:
            node_id: Unique identifier for this node
            data_dir: Directory to store data in
            p2p_node: P2P network node instance for communication
            merkle_dag: Optional MerkleDAG instance (will be created if not provided)
            block_size: Size of data blocks in bytes
            replication_factor: Number of replicas to maintain for each block
        """
        self.temp_dir = self.storage_path / "temp"
        
        for d in [self.data_dir, self.meta_dir, self.temp_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Initialize the content-addressable storage
        self.cas = LocalContentAddressableStorage(self.data_dir)
        
        # Initialize the Merkle DAG
        self.dag = MerkleDAG(self.cas)
        
        # Key-value store (maps keys to DAG CIDs)
        self.kv_store: Dict[str, str] = {}
        self._load_kv_store()
        
        # Version history (maps key to list of (version_id, cid) tuples)
        self.versions: Dict[str, List[Tuple[str, str]]] = {}
        self._load_versions()
        
        # Set up periodic tasks
        self._gc_task = asyncio.create_task(self._periodic_gc())
        self._replication_task = asyncio.create_task(self._periodic_replication())
    
    def _load_kv_store(self):
        """Load the key-value store from disk."""
        kv_path = self.meta_dir / "kv_store.json"
        if kv_path.exists():
            try:
                with open(kv_path, 'r') as f:
                    self.kv_store = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logging.error(f"Failed to load KV store: {e}")
                self.kv_store = {}
    
    def _save_kv_store(self):
        """Save the key-value store to disk."""
        kv_path = self.meta_dir / "kv_store.json"
        try:
            with open(kv_path, 'w') as f:
                json.dump(self.kv_store, f)
        except IOError as e:
            logging.error(f"Failed to save KV store: {e}")
    
    def _load_versions(self):
        """Load version history from disk."""
        versions_path = self.meta_dir / "versions.json"
        if versions_path.exists():
            try:
                with open(versions_path, 'r') as f:
                    # Convert list of lists to list of tuples
                    self.versions = {
                        k: [tuple(vv) for vv in v] 
                        for k, v in json.load(f).items()
                    }
            except (json.JSONDecodeError, IOError) as e:
                logging.error(f"Failed to load versions: {e}")
                self.versions = {}
    
    def _save_versions(self):
        """Save version history to disk."""
        versions_path = self.meta_dir / "versions.json"
        try:
            with open(versions_path, 'w') as f:
                # Convert tuples to lists for JSON serialization
                versions_serializable = {
                    k: [list(vv) for vv in v] 
                    for k, v in self.versions.items()
                }
                json.dump(versions_serializable, f)
        except IOError as e:
            logging.error(f"Failed to save versions: {e}")
    
    async def get(self, key: str) -> Optional[bytes]:
        """
        Get the value for a key.
        
        Args:
            key: The key to look up
            
        Returns:
            Optional[bytes]: The value, or None if not found
        """
        if key not in self.kv_store:
            return None
            
        cid = self.kv_store[key]
        return await self.dag.get(cid)
    
    async def set(self, key: str, value: bytes, **metadata) -> bool:
        """
        Set the value for a key.
        
        Args:
            key: The key to set
            value: The value to store
            metadata: Optional metadata to store with the value
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Store the value in the DAG
            cid = await self.dag.put(value, **metadata)
            
            # Update the key-value mapping
            previous_cid = self.kv_store.get(key)
            self.kv_store[key] = cid
            self._save_kv_store()
            
            # Update version history
            version_id = hashlib.sha256(value).hexdigest()
            if key not in self.versions:
                self.versions[key] = []
            self.versions[key].append((version_id, cid))
            self._save_versions()
            
            # Trigger replication in the background
            asyncio.create_task(self._replicate_key(key, cid))
            
            return True
        except Exception as e:
            logging.error(f"Failed to set key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """
        Delete a key and its value.
        
        Args:
            key: The key to delete
            
        Returns:
            bool: True if the key was deleted, False if it didn't exist
        """
        if key not in self.kv_store:
            return False
            
        # Just remove from the KV store - actual data will be garbage collected later
        del self.kv_store[key]
        self._save_kv_store()
        
        # Keep the version history but mark as deleted
        if key in self.versions:
            self.versions[key].append((f"deleted-{int(time.time())}", ""))
            self._save_versions()
        
        return True
    
    async def exists(self, key: str) -> bool:
        """Check if a key exists."""
        return key in self.kv_store
    
    # VersionedStorage implementation
    
    async def get_version(self, key: str, version_id: str) -> Optional[bytes]:
        """
        Get a specific version of a value.
        
        Args:
            key: The key to look up
            version_id: The version ID to retrieve
            
        Returns:
            Optional[bytes]: The versioned value, or None if not found
        """
        if key not in self.versions:
            return None
            
        for vid, cid in self.versions[key]:
            if vid == version_id:
                return await self.dag.get(cid)
                
        return None
    
    async def list_versions(self, key: str) -> List[VersionInfo]:
        """
        List all versions of a value.
        
        Args:
            key: The key to list versions for
            
        Returns:
            List[VersionInfo]: List of version information
        """
        if key not in self.versions:
            return []
            
        versions = []
        for version_id, cid in self.versions[key]:
            # Get the node to get the size and timestamp
            node_data = await self.cas.get(cid)
            if not node_data:
                continue
                
            try:
                node = DAGNode.from_dict(json.loads(node_data))
                versions.append(VersionInfo(
                    version_id=version_id,
                    timestamp=datetime.fromtimestamp(node.created_at),
                    size=node.size,
                    metadata=node.metadata
                ))
            except (json.JSONDecodeError, KeyError):
                continue
                
        return versions
    
    async def delete_version(self, key: str, version_id: str) -> bool:
        """
        Delete a specific version of a value.
        
        Args:
            key: The key of the value
            version_id: The version ID to delete
            
        Returns:
            bool: True if the version was deleted, False otherwise
        """
        if key not in self.versions:
            return False
            
        # Find and remove the version
        for i, (vid, cid) in enumerate(self.versions[key]):
            if vid == version_id:
                del self.versions[key][i]
                self._save_versions()
                return True
                
        return False
    
    # Internal methods
    
    async def _replicate_key(self, key: str, cid: str):
        """
        Replicate a key-value pair to other nodes in the network.
        
        Args:
            key: The key to replicate
            cid: The content ID of the value
        """
        # In a real implementation, this would:
        # 1. Find other nodes to replicate to (based on DHT or other strategy)
        # 2. Send the key and value to those nodes
        # 3. Handle failures and retries
        pass
    
    async def _periodic_gc(self):
        """Periodic garbage collection."""
        while True:
            try:
                await self._run_gc()
            except Exception as e:
                logging.error(f"Error during GC: {e}")
            
            # Run every hour
            await asyncio.sleep(3600)
    
    async def _run_gc(self):
        """Run garbage collection."""
        # In a real implementation, this would:
        # 1. Scan for unreferenced objects
        # 2. Remove them if they're older than a certain age
        # 3. Handle concurrent access
        pass
    
    async def _periodic_replication(self):
        """Periodic replication of data to other nodes."""
        while True:
            try:
                await self._replicate_data()
            except Exception as e:
                logging.error(f"Error during replication: {e}")
            
            # Run every 5 minutes
            await asyncio.sleep(300)
    
    async def _replicate_data(self):
        """Replicate data to other nodes."""
        # In a real implementation, this would:
        # 1. Find under-replicated data
        # 2. Replicate it to other nodes
        # 3. Handle failures and retries
        pass
    
    async def close(self):
        """Clean up resources."""
        # Cancel background tasks
        self._gc_task.cancel()
        self._replication_task.cancel()
        
        # Wait for tasks to finish
        try:
            await asyncio.gather(
                self._gc_task,
                self._replication_task,
                return_exceptions=True
            )
        except asyncio.CancelledError:
            pass


class LocalContentAddressableStorage(ContentAddressableStorage):
    """
    A simple on-disk content-addressable storage implementation.
    """
    
    def __init__(self, base_path: Path):
        """
        Initialize the storage.
        
        Args:
            base_path: Base directory for storage
        """
        self.base_path = base_path
        
        # Create the directory if it doesn't exist
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def _get_path(self, cid: str) -> Path:
        """Get the filesystem path for a content ID."""
        # Use the first 2 characters as a directory to avoid too many files in one directory
        dir_name = cid[:2]
        dir_path = self.base_path / dir_name
        dir_path.mkdir(exist_ok=True)
        return dir_path / cid[2:]
    
    async def put(self, data: bytes, **metadata) -> str:
        """
        Store data and return its content address.
        
        Args:
            data: The data to store
            metadata: Optional metadata (not used in this implementation)
            
        Returns:
            str: The content address (hash) of the stored data
        """
        # Calculate the content address
        h = hashlib.sha256()
        h.update(data)
        cid = h.hexdigest()
        
        # Don't overwrite existing data (idempotent)
        if not await self.exists(cid):
            # Write to a temporary file first
            temp_path = self.base_path / f".tmp.{os.urandom(8).hex()}"
            try:
                with open(temp_path, 'wb') as f:
                    f.write(data)
                
                # Atomically rename to the final location
                final_path = self._get_path(cid)
                temp_path.rename(final_path)
            except Exception:
                # Clean up on error
                if temp_path.exists():
                    temp_path.unlink()
                raise
        
        return cid
    
    async def get(self, cid: str) -> Optional[bytes]:
        """
        Retrieve data by its content address.
        
        Args:
            cid: The content address (hash) of the data to retrieve
            
        Returns:
            Optional[bytes]: The stored data, or None if not found
        """
        path = self._get_path(cid)
        try:
            with open(path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None
    
    async def exists(self, cid: str) -> bool:
        """
        Check if content exists in storage.
        
        Args:
            cid: The content address to check
            
        Returns:
            bool: True if the content exists, False otherwise
        """
        path = self._get_path(cid)
        return path.exists() and path.is_file()
