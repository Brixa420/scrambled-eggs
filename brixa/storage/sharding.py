"""
Data sharding implementation for distributed storage.

This module provides consistent hashing based sharding for the Brixa storage system.
"""
import hashlib
import json
import logging
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from typing_extensions import Protocol

from .interface import KeyValueStore, VersionedStorage

# Type alias for a shard ID
ShardId = str

# Type alias for a key hash
KeyHash = int

# Type alias for a node address
NodeAddress = str


class ShardManager(Protocol):
    """Protocol for shard management operations."""
    
    def get_shard(self, key: str) -> ShardId:
        """Get the shard ID for a given key."""
        ...
    
    def add_node(self, node_id: str, weight: int = 1) -> None:
        """Add a node to the shard ring."""
        ...
    
    def remove_node(self, node_id: str) -> None:
        """Remove a node from the shard ring."""
        ...
    
    def get_node(self, shard_id: ShardId) -> Optional[NodeAddress]:
        """Get the node responsible for a shard."""
        ...
    
    def get_replicas(self, shard_id: ShardId, count: int) -> List[NodeAddress]:
        """Get replica nodes for a shard."""
        ...


@dataclass
class VirtualNode:
    """Represents a virtual node in the consistent hash ring."""
    id: str
    physical_node: str
    position: int
    weight: int = 1


class ConsistentHashSharder:
    """
    Implements consistent hashing for data sharding.
    
    This uses a ring-based consistent hashing algorithm with virtual nodes
    to ensure even distribution of keys across shards.
    """
    
    def __init__(
        self,
        nodes: Dict[str, int] = None,
        replicas: int = 3,
        vnodes_per_node: int = 100,
        hash_function: Callable[[bytes], bytes] = lambda x: hashlib.sha256(x).digest()
    ):
        """
        Initialize the consistent hash sharder.
        
        Args:
            nodes: Initial nodes and their weights {node_id: weight}
            replicas: Number of replicas for each shard
            vnodes_per_node: Number of virtual nodes per physical node
            hash_function: Function to hash keys (default: SHA-256)
        """
        self.replicas = replicas
        self.vnodes_per_node = vnodes_per_node
        self.hash_function = hash_function
        
        # The consistent hash ring: {position: VirtualNode}
        self.ring: Dict[int, VirtualNode] = {}
        
        # Physical nodes: {node_id: weight}
        self.nodes: Dict[str, int] = {}
        
        # Add initial nodes
        if nodes:
            for node_id, weight in nodes.items():
                self.add_node(node_id, weight)
    
    def _hash(self, key: str) -> int:
        """Hash a key to a position on the ring."""
        # Use the first 8 bytes of the hash as a 64-bit integer
        h = self.hash_function(key.encode('utf-8'))
        return int.from_bytes(h[:8], byteorder='big')
    
    def _get_virtual_node_id(self, node_id: str, replica: int) -> str:
        """Generate a virtual node ID."""
        return f"{node_id}-{replica}"
    
    def add_node(self, node_id: str, weight: int = 1) -> None:
        """
        Add a node to the hash ring.
        
        Args:
            node_id: Unique identifier for the node
            weight: Relative weight of the node (higher = more virtual nodes)
        """
        if node_id in self.nodes:
            self.remove_node(node_id)
        
        self.nodes[node_id] = weight
        
        # Add virtual nodes
        total_weight = sum(self.nodes.values())
        num_vnodes = int((weight / total_weight) * self.vnodes_per_node * len(self.nodes))
        
        for i in range(num_vnodes):
            vnode_id = self._get_virtual_node_id(node_id, i)
            position = self._hash(vnode_id)
            
            # Keep trying new positions if there's a collision (unlikely with 64-bit hashes)
            while position in self.ring:
                vnode_id = f"{vnode_id}-{position}"
                position = self._hash(vnode_id)
            
            vnode = VirtualNode(
                id=vnode_id,
                physical_node=node_id,
                position=position,
                weight=weight
            )
            self.ring[position] = vnode
        
        # Sort the ring by position
        self.ring = dict(sorted(self.ring.items()))
    
    def remove_node(self, node_id: str) -> None:
        """
        Remove a node from the hash ring.
        
        Args:
            node_id: ID of the node to remove
        """
        if node_id not in self.nodes:
            return
        
        # Remove all virtual nodes for this physical node
        self.ring = {
            pos: vnode 
            for pos, vnode in self.ring.items() 
            if not vnode.physical_node.startswith(f"{node_id}-")
        }
        
        # Remove from physical nodes
        del self.nodes[node_id]
    
    def get_shard(self, key: str) -> ShardId:
        """
        Get the shard ID for a key.
        
        Args:
            key: The key to look up
            
        Returns:
            ShardId: The ID of the shard that should store this key
        """
        if not self.ring:
            raise ValueError("No nodes in the ring")
        
        # Hash the key to get a position on the ring
        pos = self._hash(key)
        
        # Find the first virtual node with position >= key's position
        for vnode_pos in sorted(self.ring.keys()):
            if vnode_pos >= pos:
                return self.ring[vnode_pos].physical_node
        
        # Wrap around to the first node
        return self.ring[sorted(self.ring.keys())[0]].physical_node
    
    def get_node(self, shard_id: ShardId) -> Optional[NodeAddress]:
        """
        Get the node responsible for a shard.
        
        Args:
            shard_id: The shard ID
            
        Returns:
            Optional[NodeAddress]: The node address, or None if not found
        """
        # In this simple implementation, the shard ID is the node ID
        return shard_id if shard_id in self.nodes else None
    
    def get_replicas(self, shard_id: ShardId, count: int = None) -> List[NodeAddress]:
        """
        Get replica nodes for a shard.
        
        Args:
            shard_id: The shard ID
            count: Number of replicas to return (default: self.replicas)
            
        Returns:
            List[NodeAddress]: List of node addresses for replicas
        """
        if count is None:
            count = self.replicas
        
        if not self.ring:
            return []
        
        # Find the node in the ring
        node_ids = list(self.nodes.keys())
        try:
            idx = node_ids.index(shard_id)
        except ValueError:
            return []
        
        # Get the next 'count' nodes in the ring (with wrap-around)
        replicas = []
        for i in range(1, count + 1):
            replica_idx = (idx + i) % len(node_ids)
            replicas.append(node_ids[replica_idx])
        
        return replicas
    
    def get_redistributed_keys(
        self, 
        key_provider: Callable[[], List[Tuple[str, Any]]],
        added_node: str = None,
        removed_node: str = None
    ) -> Dict[str, List[Tuple[str, Any]]]:
        """
        Get keys that need to be redistributed when nodes are added or removed.
        
        Args:
            key_provider: Function that returns (key, value) tuples
            added_node: Node that was added (if any)
            removed_node: Node that was removed (if any)
            
        Returns:
            Dict[str, List[Tuple[str, Any]]]: Mapping of node IDs to lists of (key, value) tuples
            that need to be moved to that node
        """
        if not added_node and not removed_node:
            return {}
        
        # Get all keys and their target nodes
        keys = key_provider()
        key_nodes = {}
        
        for key, value in keys:
            shard_id = self.get_shard(key)
            if shard_id not in key_nodes:
                key_nodes[shard_id] = []
            key_nodes[shard_id].append((key, value))
        
        # Determine which keys need to be moved
        moved_keys = {}
        
        if added_node:
            # After adding a node, some keys from other nodes will move to it
            for node_id, keys in key_nodes.items():
                if node_id == added_node:
                    continue
                    
                # Check if any keys should now be on the new node
                for key, value in keys:
                    new_shard = self.get_shard(key)
                    if new_shard == added_node:
                        if added_node not in moved_keys:
                            moved_keys[added_node] = []
                        moved_keys[added_node].append((key, value))
        
        if removed_node:
            # After removing a node, its keys need to be redistributed
            for key, value in keys:
                old_shard = self.get_shard(key)
                if old_shard == removed_node:
                    new_shard = self.get_shard(key)
                    if new_shard not in moved_keys:
                        moved_keys[new_shard] = []
                    moved_keys[new_shard].append((key, value))
        
        return moved_keys


class ShardedKeyValueStore(KeyValueStore):
    """
    A key-value store that shards data across multiple nodes.
    """
    
    def __init__(self, sharder: ShardManager, node_stores: Dict[str, KeyValueStore]):
        """
        Initialize the sharded key-value store.
        
        Args:
            sharder: The sharding strategy to use
            node_stores: Mapping of node IDs to their key-value stores
        """
        self.sharder = sharder
        self.node_stores = node_stores
    
    def _get_store(self, key: str) -> Tuple[KeyValueStore, str]:
        """Get the store and shard ID for a key."""
        shard_id = self.sharder.get_shard(key)
        store = self.node_stores.get(shard_id)
        if not store:
            raise ValueError(f"No store available for shard {shard_id}")
        return store, shard_id
    
    async def get(self, key: str) -> Optional[bytes]:
        store, _ = self._get_store(key)
        return await store.get(key)
    
    async def set(self, key: str, value: bytes, **metadata) -> bool:
        store, shard_id = self._get_store(key)
        
        # Get replica nodes
        replicas = self.sharder.get_replicas(shard_id)
        
        # Write to the primary shard
        success = await store.set(key, value, **metadata)
        
        # Write to replicas in parallel
        replica_tasks = []
        for replica_id in replicas:
            if replica_id in self.node_stores:
                replica_store = self.node_stores[replica_id]
                replica_tasks.append(replica_store.set(key, value, **metadata))
        
        # Wait for all replica writes to complete
        if replica_tasks:
            await asyncio.gather(*replica_tasks, return_exceptions=True)
        
        return success
    
    async def delete(self, key: str) -> bool:
        store, shard_id = self._get_store(key)
        
        # Get replica nodes
        replicas = self.sharder.get_replicas(shard_id)
        
        # Delete from the primary shard
        success = await store.delete(key)
        
        # Delete from replicas in parallel
        replica_tasks = []
        for replica_id in replicas:
            if replica_id in self.node_stores:
                replica_store = self.node_stores[replica_id]
                replica_tasks.append(replica_store.delete(key))
        
        # Wait for all replica deletes to complete
        if replica_tasks:
            await asyncio.gather(*replica_tasks, return_exceptions=True)
        
        return success
    
    async def exists(self, key: str) -> bool:
        store, _ = self._get_store(key)
        return await store.exists(key)


class ShardManagerService:
    """
    Service for managing shards across the cluster.
    """
    
    def __init__(self, sharder: ShardManager, node_id: str):
        """
        Initialize the shard manager service.
        
        Args:
            sharder: The sharding strategy
            node_id: The ID of this node
        """
        self.sharder = sharder
        self.node_id = node_id
        self.shard_locks = {}  # For coordinating shard operations
    
    async def rebalance_shards(self, key_provider: Callable[[], List[Tuple[str, Any]]]) -> Dict[str, List[str]]:
        """
        Rebalance shards across the cluster.
        
        Args:
            key_provider: Function that returns (key, value) tuples
            
        Returns:
            Dict[str, List[str]]: Mapping of node IDs to lists of keys that were moved
        """
        # Get all keys and their target nodes
        keys = key_provider()
        key_nodes = {}
        
        for key, value in keys:
            shard_id = self.sharder.get_shard(key)
            if shard_id not in key_nodes:
                key_nodes[shard_id] = []
            key_nodes[shard_id].append((key, value))
        
        # Determine which keys need to be moved
        moved_keys = {}
        
        # This is a simplified version - in a real implementation, you would:
        # 1. Calculate the desired distribution
        # 2. Find the minimal set of keys to move
        # 3. Coordinate with other nodes to move the data
        
        return moved_keys
    
    async def recover_shard(self, shard_id: str, target_node: str) -> bool:
        """
        Recover a shard on a new node.
        
        Args:
            shard_id: The ID of the shard to recover
            target_node: The node to recover the shard on
            
        Returns:
            bool: True if recovery was successful, False otherwise
        """
        # In a real implementation, this would:
        # 1. Find nodes that have replicas of the shard
        # 2. Copy the data to the target node
        # 3. Update the shard mapping
        # 4. Replicate the shard to other nodes if needed
        return False
