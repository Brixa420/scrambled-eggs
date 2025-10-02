"""
Content Delivery Network (CDN) module for the video platform.
Handles content distribution, caching, and edge delivery.
"""

import asyncio
import hashlib
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .storage import VideoStorage

logger = logging.getLogger(__name__)

@dataclass
class CDNNode:
    """Represents a node in the CDN network."""
    node_id: str
    address: str
    port: int
    capacity: int  # in bytes
    used_space: int = 0
    active: bool = True
    last_seen: float = field(default_factory=lambda: time.time())
    
    @property
    def available_space(self) -> int:
        """Get available space on this node."""
        return max(0, self.capacity - self.used_space)
    
    def can_store(self, size: int) -> bool:
        """Check if this node can store a file of the given size."""
        return self.active and (self.available_space >= size)
    
    def update_usage(self, size: int) -> None:
        """Update the used space on this node."""
        self.used_space = max(0, min(self.capacity, self.used_space + size))

@dataclass
class ContentLocation:
    """Tracks where content is stored in the CDN."""
    content_id: str
    size: int
    locations: Set[str] = field(default_factory=set)  # Set of node IDs
    access_count: int = 0
    last_accessed: float = field(default_factory=lambda: time.time())
    
    def add_location(self, node_id: str) -> None:
        """Add a node where this content is stored."""
        self.locations.add(node_id)
    
    def remove_location(self, node_id: str) -> bool:
        """Remove a node where this content is stored."""
        if node_id in self.locations:
            self.locations.remove(node_id)
            return True
        return False
    
    def get_best_location(self, nodes: Dict[str, CDNNode]) -> Optional[str]:
        """Get the best node to serve this content from."""
        if not self.locations:
            return None
            
        # Sort by node availability and load (simplified)
        def sort_key(node_id: str) -> Tuple[bool, float]:
            node = nodes.get(node_id)
            if not node or not node.active:
                return (False, float('inf'))
            # Prefer nodes with more available space (lower utilization)
            utilization = node.used_space / node.capacity if node.capacity > 0 else 0
            return (True, utilization)
        
        sorted_nodes = sorted(self.locations, key=sort_key, reverse=True)
        return sorted_nodes[0] if sorted_nodes else None

class ContentDeliveryNetwork:
    """Manages a distributed content delivery network for video streaming."""
    
    def __init__(
        self,
        node_id: str,
        storage_dir: str = "./cdn",
        replication_factor: int = 3,
        storage_limit: int = 100 * 1024 * 1024 * 1024  # 100GB default
    ):
        self.node_id = node_id
        self.replication_factor = replication_factor
        self.storage_limit = storage_limit
        self.storage_dir = Path(storage_dir) / node_id
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Track known nodes and content locations
        self.nodes: Dict[str, CDNNode] = {}  # node_id -> CDNNode
        self.content_map: Dict[str, ContentLocation] = {}  # content_id -> ContentLocation
        self.local_content: Set[str] = set()  # content_ids stored locally
        
        # Track pending operations
        self._lock = asyncio.Lock()
        self._pending_operations: Dict[str, asyncio.Event] = {}
        
        # Background tasks
        self._background_tasks: Set[asyncio.Task] = set()
        self._running = False
    
    async def start(self) -> None:
        """Start the CDN node."""
        if self._running:
            return
            
        self._running = True
        
        # Register this node
        self.nodes[self.node_id] = CDNNode(
            node_id=self.node_id,
            address="localhost",  # In a real implementation, this would be the public IP
            port=8000,  # Default port
            capacity=self.storage_limit
        )
        
        # Start background tasks
        self._background_tasks.update({
            asyncio.create_task(self._monitor_nodes()),
            asyncio.create_task(self._rebalance_content()),
            asyncio.create_task(self._cleanup_old_content())
        })
        
        logger.info(f"CDN node {self.node_id} started")
    
    async def stop(self) -> None:
        """Stop the CDN node."""
        if not self._running:
            return
            
        self._running = False
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self._background_tasks:
            await asyncio.wait(self._background_tasks, return_when=asyncio.ALL_COMPLETED)
        
        logger.info(f"CDN node {self.node_id} stopped")
    
    async def add_node(self, node_id: str, address: str, port: int, capacity: int) -> bool:
        """Add or update a CDN node."""
        async with self._lock:
            if node_id in self.nodes:
                # Update existing node
                node = self.nodes[node_id]
                node.address = address
                node.port = port
                node.capacity = capacity
                node.last_seen = time.time()
                node.active = True
                logger.info(f"Updated CDN node {node_id}")
            else:
                # Add new node
                self.nodes[node_id] = CDNNode(
                    node_id=node_id,
                    address=address,
                    port=port,
                    capacity=capacity
                )
                logger.info(f"Added new CDN node {node_id}")
            
            return True
    
    async def remove_node(self, node_id: str) -> bool:
        """Remove a CDN node."""
        if node_id == self.node_id:
            logger.warning("Cannot remove self from CDN")
            return False
            
        async with self._lock:
            if node_id in self.nodes:
                # Mark as inactive
                self.nodes[node_id].active = False
                
                # Redistribute content if this node had any
                for content_id, location in list(self.content_map.items()):
                    if node_id in location.locations:
                        location.remove_location(node_id)
                        if not location.locations:
                            # Last copy was removed, try to re-replicate
                            await self._replicate_content(content_id)
                
                # Remove from nodes
                del self.nodes[node_id]
                logger.info(f"Removed CDN node {node_id}")
                return True
            
            return False
    
    async def store_content(
        self,
        content_id: str,
        data: bytes,
        replication: Optional[int] = None
    ) -> bool:
        """Store content in the CDN."""
        if replication is None:
            replication = self.replication_factor
            
        size = len(data)
        
        # Check if we already have this content
        if content_id in self.content_map:
            return True
            
        # Find nodes to store the content
        selected_nodes = await self._select_nodes_for_content(content_id, size, replication)
        if not selected_nodes:
            logger.error(f"Failed to find enough nodes to store content {content_id}")
            return False
        
        # Store the content locally if this node was selected
        local_path = None
        if self.node_id in selected_nodes:
            local_path = self._get_content_path(content_id)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                with open(local_path, "wb") as f:
                    f.write(data)
                self.local_content.add(content_id)
                logger.info(f"Stored content {content_id} locally")
            except IOError as e:
                logger.error(f"Failed to store content {content_id} locally: {e}")
                selected_nodes.remove(self.node_id)
                if not selected_nodes:
                    return False
        
        # Track the content location
        async with self._lock:
            if content_id in self.content_map:
                # Content was already added by another operation
                return True
                
            self.content_map[content_id] = ContentLocation(
                content_id=content_id,
                size=size,
                locations=set(selected_nodes)
            )
        
        # Replicate to other nodes in the background
        if len(selected_nodes) < replication:
            asyncio.create_task(self._replicate_content(content_id))
        
        return True
    
    async def get_content(self, content_id: str) -> Optional[bytes]:
        """Retrieve content from the CDN."""
        # Check if we have the content locally
        if content_id in self.local_content:
            local_path = self._get_content_path(content_id)
            try:
                with open(local_path, "rb") as f:
                    data = f.read()
                await self._update_content_access(content_id)
                return data
            except IOError as e:
                logger.error(f"Failed to read local content {content_id}: {e}")
                self.local_content.remove(content_id)
        
        # Check if we know about this content
        content_loc = self.content_map.get(content_id)
        if not content_loc:
            return None
        
        # Find the best node to fetch from
        best_node_id = content_loc.get_best_location(self.nodes)
        if not best_node_id:
            logger.error(f"No available nodes have content {content_id}")
            return None
        
        # If the best node is us but we don't have the content, something is wrong
        if best_node_id == self.node_id:
            logger.error(f"Inconsistent state: content {content_id} marked as local but not found")
            return None
        
        # Fetch from another node
        node = self.nodes[best_node_id]
        try:
            # In a real implementation, this would make an HTTP request to the node
            # For now, we'll just simulate it
            logger.info(f"Fetching content {content_id} from node {best_node_id}")
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Store locally for future use
            # In a real implementation, we would get the actual data
            data = f"Content {content_id} from {best_node_id}".encode()
            
            # Cache the content locally if we have space
            if self._can_store(content_loc.size):
                local_path = self._get_content_path(content_id)
                local_path.parent.mkdir(parents=True, exist_ok=True)
                
                try:
                    with open(local_path, "wb") as f:
                        f.write(data)
                    self.local_content.add(content_id)
                    
                    # Update content location
                    async with self._lock:
                        if content_id in self.content_map:
                            self.content_map[content_id].add_location(self.node_id)
                    
                    logger.info(f"Cached content {content_id} locally")
                except IOError as e:
                    logger.error(f"Failed to cache content {content_id} locally: {e}")
            
            await self._update_content_access(content_id)
            return data
            
        except Exception as e:
            logger.error(f"Failed to fetch content {content_id} from node {best_node_id}: {e}")
            # Mark node as potentially down
            if best_node_id in self.nodes:
                self.nodes[best_node_id].active = False
            return None
    
    async def delete_content(self, content_id: str) -> bool:
        """Delete content from the CDN."""
        async with self._lock:
            if content_id not in self.content_map:
                return False
            
            # Remove from local storage if we have it
            if content_id in self.local_content:
                try:
                    local_path = self._get_content_path(content_id)
                    os.remove(local_path)
                    self.local_content.remove(content_id)
                    logger.info(f"Deleted local copy of content {content_id}")
                except OSError as e:
                    logger.error(f"Failed to delete local content {content_id}: {e}"
            
            # Remove from content map
            del self.content_map[content_id]
            
            # TODO: Notify other nodes to delete their copies
            
            return True
    
    async def _select_nodes_for_content(
        self,
        content_id: str,
        size: int,
        replication: int
    ) -> List[str]:
        """Select nodes to store a piece of content."""
        if size > self.storage_limit:
            logger.error(f"Content {content_id} is too large ({size} bytes)")
            return []
        
        # Get all nodes with enough space, sorted by available space (descending)
        eligible_nodes = [
            node for node in self.nodes.values()
            if node.active and node.can_store(size)
        ]
        eligible_nodes.sort(key=lambda n: n.available_space, reverse=True)
        
        # Select nodes, preferring those that don't already have the content
        selected_nodes = []
        for node in eligible_nodes:
            if node.node_id in self.content_map.get(content_id, {}).locations:
                continue
                
            selected_nodes.append(node.node_id)
            if len(selected_nodes) >= replication:
                break
        
        return selected_nodes
    
    async def _replicate_content(self, content_id: str) -> None:
        """Ensure content is replicated to enough nodes."""
        if content_id not in self.content_map:
            return
            
        content_loc = self.content_map[content_id]
        current_replicas = len(content_loc.locations)
        
        if current_replicas >= self.replication_factor:
            return
            
        needed = self.replication_factor - current_replicas
        
        # Find nodes to replicate to
        selected_nodes = await self._select_nodes_for_content(
            content_id,
            content_loc.size,
            needed
        )
        
        if not selected_nodes:
            logger.warning(f"Could not find enough nodes to replicate content {content_id}")
            return
        
        # In a real implementation, we would transfer the content to the selected nodes
        logger.info(f"Replicating content {content_id} to {len(selected_nodes)} nodes")
        
        # Update content locations
        async with self._lock:
            if content_id in self.content_map:
                for node_id in selected_nodes:
                    self.content_map[content_id].add_location(node_id)
    
    async def _update_content_access(self, content_id: str) -> None:
        """Update access statistics for content."""
        async with self._lock:
            if content_id in self.content_map:
                content_loc = self.content_map[content_id]
                content_loc.access_count += 1
                content_loc.last_accessed = time.time()
    
    async def _monitor_nodes(self) -> None:
        """Background task to monitor node health."""
        while self._running:
            try:
                current_time = time.time()
                dead_nodes = []
                
                # Check for dead nodes
                async with self._lock:
                    for node_id, node in list(self.nodes.items()):
                        if node_id == self.node_id:
                            continue
                            
                        # Mark as inactive if we haven't heard from them in a while
                        if current_time - node.last_seen > 60:  # 1 minute timeout
                            logger.warning(f"Node {node_id} appears to be down")
                            node.active = False
                            
                            # If we've been trying for too long, give up
                            if current_time - node.last_seen > 3600:  # 1 hour
                                dead_nodes.append(node_id)
                
                # Clean up dead nodes
                for node_id in dead_nodes:
                    await self.remove_node(node_id)
                
                # Send heartbeat to other nodes
                await self._send_heartbeats()
                
            except Exception as e:
                logger.error(f"Error in node monitoring: {e}")
                
            await asyncio.sleep(30)  # Check every 30 seconds
    
    async def _rebalance_content(self) -> None:
        """Background task to rebalance content across nodes."""
        while self._running:
            try:
                # In a real implementation, this would:
                # 1. Identify underutilized and overutilized nodes
                # 2. Move content from hot nodes to cold nodes
                # 3. Ensure the replication factor is maintained
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in content rebalancing: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _cleanup_old_content(self) -> None:
        """Background task to clean up old or unused content."""
        while self._running:
            try:
                current_time = time.time()
                to_delete = []
                
                # Find content that hasn't been accessed in a while
                async with self._lock:
                    for content_id, content_loc in list(self.content_map.items()):
                        # Skip if this is the only copy
                        if len(content_loc.locations) <= 1:
                            continue
                            
                        # Delete if not accessed in 7 days
                        if current_time - content_loc.last_accessed > 7 * 24 * 3600:
                            to_delete.append(content_id)
                
                # Delete old content
                for content_id in to_delete:
                    await self.delete_content(content_id)
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Error in content cleanup: {e}")
                await asyncio.sleep(300)  # Wait before retrying
    
    async def _send_heartbeats(self) -> None:
        """Send heartbeat to other nodes."""
        # In a real implementation, this would send a heartbeat to other nodes
        # to let them know we're still alive and provide our current status
        pass
    
    def _get_content_path(self, content_id: str) -> Path:
        """Get the local filesystem path for a piece of content."""
        # Use the first few characters of the hash to avoid too many files in one directory
        hash_prefix = content_id[:2]
        return self.storage_dir / hash_prefix / content_id
    
    def _can_store(self, size: int) -> bool:
        """Check if we can store a piece of content of the given size."""
        if size > self.storage_limit:
            return False
            
        # Calculate used space
        used = sum(
            loc.size for content_id, loc in self.content_map.items()
            if content_id in self.local_content
        )
        
        return (used + size) <= self.storage_limit
