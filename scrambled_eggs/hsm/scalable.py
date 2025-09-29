"""
Scalable Architecture Module for Cloud HSM

This module provides scalable architecture features for the Cloud HSM client,
including load balancing, sharding, and distributed state management.
"""

import asyncio
import hashlib
import json
import logging
import random
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# Distributed state management
try:
    import redis.asyncio as redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# For consistent hashing
try:
    import mmh3  # MurmurHash3 for consistent hashing

    MMH3_AVAILABLE = True
except ImportError:
    MMH3_AVAILABLE = False


class NodeStatus(Enum):
    """Status of a node in the cluster."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DRAINING = "draining"
    MAINTENANCE = "maintenance"


class ShardingStrategy(Enum):
    """Sharding strategies."""

    RANGE = "range"  # Range-based sharding
    HASH = "hash"  # Hash-based sharding
    TAG = "tag"  # Tag-based sharding


class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""

    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    CONSISTENT_HASHING = "consistent_hashing"
    RANDOM = "random"


@dataclass
class Node:
    """Represents a node in the cluster."""

    id: str
    address: str
    port: int
    weight: int = 1
    tags: Dict[str, str] = field(default_factory=dict)
    status: NodeStatus = NodeStatus.HEALTHY
    last_heartbeat: float = field(default_factory=time.time)
    connections: int = 0
    shard_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert node to dictionary."""
        return {
            "id": self.id,
            "address": self.address,
            "port": self.port,
            "weight": self.weight,
            "tags": self.tags,
            "status": self.status.value,
            "last_heartbeat": self.last_heartbeat,
            "connections": self.connections,
            "shard_id": self.shard_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Node":
        """Create node from dictionary."""
        return cls(
            id=data["id"],
            address=data["address"],
            port=data["port"],
            weight=data.get("weight", 1),
            tags=data.get("tags", {}),
            status=NodeStatus(data.get("status", "healthy")),
            last_heartbeat=data.get("last_heartbeat", time.time()),
            connections=data.get("connections", 0),
            shard_id=data.get("shard_id"),
        )


class Shard:
    """Represents a shard in the cluster."""

    def __init__(self, shard_id: str, nodes: List[Node] = None):
        """
        Initialize a shard.

        Args:
            shard_id: Unique identifier for the shard
            nodes: List of nodes in the shard
        """
        self.id = shard_id
        self.nodes = {node.id: node for node in (nodes or [])}
        self.primary_node_id = nodes[0].id if nodes else None
        self.replica_nodes = {}
        self.status = "active"
        self.created_at = time.time()
        self.updated_at = self.created_at

        # Track metrics
        self.metrics = {
            "keys": 0,
            "size_bytes": 0,
            "read_ops": 0,
            "write_ops": 0,
            "last_updated": self.created_at,
        }

    def add_node(self, node: Node, is_primary: bool = False) -> None:
        """
        Add a node to the shard.

        Args:
            node: Node to add
            is_primary: Whether this node should be the primary
        """
        self.nodes[node.id] = node
        if is_primary or not self.primary_node_id:
            self.primary_node_id = node.id
        self.updated_at = time.time()

    def remove_node(self, node_id: str) -> bool:
        """
        Remove a node from the shard.

        Args:
            node_id: ID of the node to remove

        Returns:
            True if the node was removed, False otherwise
        """
        if node_id in self.nodes:
            del self.nodes[node_id]

            # If the primary node was removed, select a new primary
            if node_id == self.primary_node_id and self.nodes:
                self.primary_node_id = next(iter(self.nodes.keys()))

            self.updated_at = time.time()
            return True
        return False

    def get_primary_node(self) -> Optional[Node]:
        """Get the primary node for this shard."""
        if not self.primary_node_id:
            return None
        return self.nodes.get(self.primary_node_id)

    def get_replica_nodes(self, exclude_primary: bool = True) -> List[Node]:
        """
        Get replica nodes for this shard.

        Args:
            exclude_primary: Whether to exclude the primary node

        Returns:
            List of replica nodes
        """
        replicas = []
        for node_id, node in self.nodes.items():
            if not exclude_primary or node_id != self.primary_node_id:
                replicas.append(node)
        return replicas

    def update_metrics(self, **kwargs) -> None:
        """
        Update shard metrics.

        Args:
            **kwargs: Metrics to update (keys, size_bytes, read_ops, write_ops)
        """
        for key, value in kwargs.items():
            if key in self.metrics:
                self.metrics[key] = value
        self.metrics["last_updated"] = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Convert shard to dictionary."""
        return {
            "id": self.id,
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "primary_node_id": self.primary_node_id,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metrics": self.metrics,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Shard":
        """Create shard from dictionary."""
        shard = cls(
            shard_id=data["id"],
            nodes=[Node.from_dict(node_data) for node_data in data.get("nodes", [])],
        )
        shard.primary_node_id = data.get("primary_node_id")
        shard.status = data.get("status", "active")
        shard.created_at = data.get("created_at", time.time())
        shard.updated_at = data.get("updated_at", shard.created_at)
        shard.metrics = data.get(
            "metrics",
            {
                "keys": 0,
                "size_bytes": 0,
                "read_ops": 0,
                "write_ops": 0,
                "last_updated": shard.created_at,
            },
        )
        return shard


class ClusterManager:
    """
    Manages a cluster of HSM nodes with support for sharding and load balancing.
    """

    def __init__(
        self,
        sharding_strategy: ShardingStrategy = ShardingStrategy.HASH,
        load_balancing_strategy: LoadBalancingStrategy = LoadBalancingStrategy.LEAST_CONNECTIONS,
        redis_url: str = None,
        replication_factor: int = 2,
        auto_rebalance: bool = True,
    ):
        """
        Initialize the cluster manager.

        Args:
            sharding_strategy: Strategy for sharding data across nodes
            load_balancing_strategy: Strategy for load balancing requests
            redis_url: URL for Redis server for distributed state
            replication_factor: Number of replicas for each shard
            auto_rebalance: Whether to automatically rebalance shards
        """
        self.sharding_strategy = sharding_strategy
        self.load_balancing_strategy = load_balancing_strategy
        self.replication_factor = max(1, replication_factor)
        self.auto_rebalance = auto_rebalance

        # Node and shard management
        self.nodes: Dict[str, Node] = {}
        self.shards: Dict[str, Shard] = {}
        self.node_to_shard: Dict[str, str] = {}
        self.shard_keys: Dict[str, List[str]] = {}

        # Consistent hashing ring
        self.hash_ring = None
        if MMH3_AVAILABLE and self.sharding_strategy == ShardingStrategy.HASH:
            self._init_hash_ring()

        # Distributed state management
        self.redis = None
        if redis_url and REDIS_AVAILABLE:
            self.redis = redis.from_url(redis_url)

        # Load balancing state
        self.current_node_index = 0

        # Health check and monitoring
        self.health_check_interval = 30  # seconds
        self.health_check_task = None
        self.running = False

        # Metrics
        self.metrics = {
            "total_requests": 0,
            "failed_requests": 0,
            "shard_operations": {},
            "node_operations": {},
            "last_updated": time.time(),
        }

    def _init_hash_ring(self) -> None:
        """Initialize the consistent hashing ring."""
        if not MMH3_AVAILABLE:
            raise ImportError(
                "mmh3 is required for consistent hashing. Install with: pip install mmh3"
            )

        # Using a simple dict to simulate a hash ring
        self.hash_ring = {}

    def _get_shard_id_for_key(self, key: str) -> str:
        """
        Get the shard ID for a given key based on the sharding strategy.

        Args:
            key: The key to determine the shard for

        Returns:
            The shard ID
        """
        if not self.shards:
            raise ValueError("No shards available")

        if self.sharding_strategy == ShardingStrategy.HASH and MMH3_AVAILABLE:
            # Use consistent hashing
            if not self.hash_ring:
                self._populate_hash_ring()

            # Get the hash of the key
            key_hash = mmh3.hash(key)

            # Find the shard with the next highest hash value
            sorted_hashes = sorted(self.hash_ring.keys())
            for h in sorted_hashes:
                if key_hash <= h:
                    return self.hash_ring[h]

            # Wrap around to the first shard
            return self.hash_ring[sorted_hashes[0]]

        elif self.sharding_strategy == ShardingStrategy.RANGE:
            # Simple range-based sharding (e.g., A-M, N-Z)
            # This is a simplified example - in practice, you'd want a more sophisticated approach
            first_char = key[0].lower()
            shard_count = len(self.shards)
            shard_index = min(ord(first_char) % shard_count, shard_count - 1)
            return list(self.shards.keys())[shard_index]

        else:
            # Fall back to random sharding
            return random.choice(list(self.shards.keys()))

    def _populate_hash_ring(self, replicas: int = 100) -> None:
        """
        Populate the consistent hashing ring with virtual nodes.

        Args:
            replicas: Number of virtual nodes per shard
        """
        if not self.shards:
            return

        self.hash_ring = {}

        for shard_id in self.shards:
            for i in range(replicas):
                # Create a virtual node by appending a number to the shard ID
                virtual_node = f"{shard_id}-{i}"
                # Hash the virtual node to get its position on the ring
                node_hash = mmh3.hash(virtual_node)
                self.hash_ring[node_hash] = shard_id

    async def add_node(
        self,
        node_id: str,
        address: str,
        port: int,
        weight: int = 1,
        tags: Dict[str, str] = None,
        shard_id: str = None,
    ) -> bool:
        """
        Add a node to the cluster.

        Args:
            node_id: Unique identifier for the node
            address: Node hostname or IP address
            port: Node port
            weight: Node weight for load balancing
            tags: Key-value pairs for tagging the node
            shard_id: Optional shard ID to assign the node to

        Returns:
            True if the node was added successfully, False otherwise
        """
        if node_id in self.nodes:
            self.logger.warning(f"Node {node_id} already exists")
            return False

        # Create the node
        node = Node(
            id=node_id,
            address=address,
            port=port,
            weight=weight,
            tags=tags or {},
            shard_id=shard_id,
        )

        # Add to the nodes collection
        self.nodes[node_id] = node

        # If a shard ID was provided, add the node to that shard
        if shard_id:
            if shard_id not in self.shards:
                self.shards[shard_id] = Shard(shard_id)

            shard = self.shards[shard_id]
            is_primary = not bool(shard.primary_node_id)  # First node becomes primary
            shard.add_node(node, is_primary=is_primary)
            self.node_to_shard[node_id] = shard_id

        # Update the hash ring if using consistent hashing
        if self.sharding_strategy == ShardingStrategy.HASH and MMH3_AVAILABLE:
            self._populate_hash_ring()

        # Update metrics
        self._update_metrics("node_operations", "add_node")

        self.logger.info(f"Added node {node_id} to the cluster")
        return True

    async def remove_node(self, node_id: str) -> bool:
        """
        Remove a node from the cluster.

        Args:
            node_id: ID of the node to remove

        Returns:
            True if the node was removed, False otherwise
        """
        if node_id not in self.nodes:
            self.logger.warning(f"Node {node_id} not found")
            return False

        # Remove from shard if assigned to one
        if node_id in self.node_to_shard:
            shard_id = self.node_to_shard[node_id]
            if shard_id in self.shards:
                self.shards[shard_id].remove_node(node_id)

                # If this was the last node in the shard, remove the shard
                if not self.shards[shard_id].nodes:
                    del self.shards[shard_id]

                del self.node_to_shard[node_id]

        # Remove from nodes collection
        del self.nodes[node_id]

        # Update the hash ring if using consistent hashing
        if self.sharding_strategy == ShardingStrategy.HASH and MMH3_AVAILABLE:
            self._populate_hash_ring()

        # Update metrics
        self._update_metrics("node_operations", "remove_node")

        self.logger.info(f"Removed node {node_id} from the cluster")
        return True

    async def get_node_for_key(self, key: str, read_only: bool = False) -> Optional[Node]:
        """
        Get the appropriate node for a given key based on the load balancing strategy.

        Args:
            key: The key to determine the node for
            read_only: Whether this is a read-only operation

        Returns:
            The selected Node, or None if no nodes are available
        """
        if not self.nodes:
            return None

        # Get the shard for the key
        shard_id = self._get_shard_id_for_key(key)
        if shard_id not in self.shards:
            return None

        shard = self.shards[shard_id]

        # For read operations, we can use any replica
        if read_only and shard.get_replica_nodes():
            candidates = shard.get_replica_nodes()
        else:
            # For write operations, we must use the primary
            primary = shard.get_primary_node()
            if not primary:
                return None
            candidates = [primary]

        # Select a node based on the load balancing strategy
        if self.load_balancing_strategy == LoadBalancingStrategy.ROUND_ROBIN:
            if not hasattr(self, "_rr_index"):
                self._rr_index = {}

            if shard_id not in self._rr_index:
                self._rr_index[shard_id] = 0

            index = self._rr_index[shard_id] % len(candidates)
            self._rr_index[shard_id] = (index + 1) % len(candidates)
            return candidates[index]

        elif self.load_balancing_strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            return min(candidates, key=lambda n: n.connections)

        elif self.load_balancing_strategy == LoadBalancingStrategy.RANDOM:
            return random.choice(candidates)

        else:  # Default to round-robin
            index = self.current_node_index % len(candidates)
            self.current_node_index = (self.current_node_index + 1) % len(candidates)
            return candidates[index]

    async def start_health_checks(self) -> None:
        """Start periodic health checks for all nodes."""
        if self.health_check_task and not self.health_check_task.done():
            return

        self.running = True
        self.health_check_task = asyncio.create_task(self._health_check_loop())

    async def stop_health_checks(self) -> None:
        """Stop the health check loop."""
        self.running = False
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass

    async def _health_check_loop(self) -> None:
        """Background task to check the health of all nodes."""
        while self.running:
            try:
                await self._check_node_health()
            except Exception as e:
                self.logger.error(f"Error in health check: {str(e)}")

            await asyncio.sleep(self.health_check_interval)

    async def _check_node_health(self) -> None:
        """Check the health of all nodes in the cluster."""
        for node_id, node in list(self.nodes.items()):
            try:
                # In a real implementation, this would make an actual health check request
                is_healthy = await self._check_node(node)

                if is_healthy:
                    if node.status != NodeStatus.HEALTHY:
                        self.logger.info(f"Node {node_id} is now healthy")
                    node.status = NodeStatus.HEALTHY
                else:
                    if node.status == NodeStatus.HEALTHY:
                        self.logger.warning(f"Node {node_id} is unhealthy")
                    node.status = NodeStatus.UNHEALTHY

                node.last_heartbeat = time.time()

            except Exception as e:
                self.logger.error(f"Error checking health of node {node_id}: {str(e)}")
                node.status = NodeStatus.UNHEALTHY

    async def _check_node(self, node: Node) -> bool:
        """
        Check if a node is healthy.

        Args:
            node: The node to check

        Returns:
            True if the node is healthy, False otherwise
        """
        # In a real implementation, this would make an actual health check request
        # For now, we'll simulate a health check that randomly fails 1% of the time
        return random.random() > 0.01

    async def rebalance_shards(self) -> None:
        """Rebalance shards across nodes."""
        if not self.auto_rebalance:
            return

        self.logger.info("Starting shard rebalancing")

        # Get all nodes that can accept shards
        available_nodes = [
            n for n in self.nodes.values() if n.status == NodeStatus.HEALTHY and not n.shard_id
        ]

        if not available_nodes:
            self.logger.warning("No available nodes for rebalancing")
            return

        # Calculate target number of shards per node
        target_shards_per_node = len(self.shards) / len(available_nodes)

        # Track shard assignments
        node_shard_counts = {node.id: 0 for node in available_nodes}

        # Assign shards to nodes
        for shard_id, shard in self.shards.items():
            # Find the node with the fewest shards that doesn't already have this shard
            target_node = min(
                available_nodes,
                key=lambda n: (
                    node_shard_counts[n.id],
                    -1 if n.id not in [nid for nid in shard.nodes] else 1,
                ),
            )

            # Assign the shard to the target node
            if shard_id not in self.node_to_shard or self.node_to_shard[shard_id] != target_node.id:
                self.logger.info(
                    f"Rebalancing: Assigning shard {shard_id} to node {target_node.id}"
                )
                await self._assign_shard_to_node(shard_id, target_node.id)
                node_shard_counts[target_node.id] += 1

        self._update_metrics("shard_operations", "rebalance")
        self.logger.info("Shard rebalancing complete")

    async def _assign_shard_to_node(self, shard_id: str, node_id: str) -> bool:
        """
        Assign a shard to a node.

        Args:
            shard_id: ID of the shard to assign
            node_id: ID of the node to assign the shard to

        Returns:
            True if the assignment was successful, False otherwise
        """
        if shard_id not in self.shards or node_id not in self.nodes:
            return False

        shard = self.shards[shard_id]
        node = self.nodes[node_id]

        # Add the node to the shard
        is_primary = not bool(shard.primary_node_id)  # First node becomes primary
        shard.add_node(node, is_primary=is_primary)

        # Update the node's shard assignment
        node.shard_id = shard_id
        self.node_to_shard[node_id] = shard_id

        # In a real implementation, this would trigger data migration
        self.logger.info(
            f"Assigned shard {shard_id} to node {node_id} "
            f"as {'primary' if is_primary else 'replica'}"
        )

        return True

    def _update_metrics(self, category: str, operation: str) -> None:
        """
        Update operation metrics.

        Args:
            category: Metric category (e.g., 'node_operations', 'shard_operations')
            operation: Operation name (e.g., 'add_node', 'rebalance')
        """
        if category not in self.metrics:
            self.metrics[category] = {}

        if operation not in self.metrics[category]:
            self.metrics[category][operation] = 0

        self.metrics[category][operation] += 1
        self.metrics["last_updated"] = time.time()

    async def get_cluster_state(self) -> Dict[str, Any]:
        """
        Get the current cluster state.

        Returns:
            Dictionary containing the cluster state
        """
        return {
            "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
            "shards": {sid: shard.to_dict() for sid, shard in self.shards.items()},
            "node_to_shard": self.node_to_shard,
            "metrics": self.metrics,
            "config": {
                "sharding_strategy": self.sharding_strategy.value,
                "load_balancing_strategy": self.load_balancing_strategy.value,
                "replication_factor": self.replication_factor,
                "auto_rebalance": self.auto_rebalance,
            },
        }

    async def save_state(self) -> bool:
        """
        Save the cluster state to persistent storage.

        Returns:
            True if the state was saved successfully, False otherwise
        """
        if not self.redis:
            self.logger.warning("Redis not configured, cannot save state")
            return False

        try:
            state = await self.get_cluster_state()
            await self.redis.set("cluster:state", json.dumps(state))
            return True
        except Exception as e:
            self.logger.error(f"Failed to save cluster state: {str(e)}")
            return False

    async def load_state(self) -> bool:
        """
        Load the cluster state from persistent storage.

        Returns:
            True if the state was loaded successfully, False otherwise
        """
        if not self.redis:
            self.logger.warning("Redis not configured, cannot load state")
            return False

        try:
            state_json = await self.redis.get("cluster:state")
            if not state_json:
                return False

            state = json.loads(state_json)

            # Clear existing state
            self.nodes = {}
            self.shards = {}
            self.node_to_shard = {}

            # Load nodes
            for nid, node_data in state.get("nodes", {}).items():
                self.nodes[nid] = Node.from_dict(node_data)

            # Load shards
            for sid, shard_data in state.get("shards", {}).items():
                self.shards[sid] = Shard.from_dict(shard_data)

            # Load node-to-shard mapping
            self.node_to_shard = state.get("node_to_shard", {})

            # Update metrics
            self.metrics = state.get("metrics", self.metrics)

            # Rebuild the hash ring if using consistent hashing
            if self.sharding_strategy == ShardingStrategy.HASH and MMH3_AVAILABLE:
                self._populate_hash_ring()

            return True

        except Exception as e:
            self.logger.error(f"Failed to load cluster state: {str(e)}")
            return False

    async def close(self) -> None:
        """Clean up resources."""
        await self.stop_health_checks()

        if self.redis:
            await self.redis.close()


# Example usage
async def example():
    # Create a cluster manager
    cluster = ClusterManager(
        sharding_strategy=ShardingStrategy.HASH,
        load_balancing_strategy=LoadBalancingStrategy.LEAST_CONNECTIONS,
        redis_url="redis://localhost:6379",
        replication_factor=2,
        auto_rebalance=True,
    )

    try:
        # Add some nodes
        await cluster.add_node("node1", "10.0.0.1", 8000, shard_id="shard1")
        await cluster.add_node("node2", "10.0.0.2", 8000, shard_id="shard1")
        await cluster.add_node("node3", "10.0.0.3", 8000, shard_id="shard2")
        await cluster.add_node("node4", "10.0.0.4", 8000, shard_id="shard2")

        # Start health checks
        await cluster.start_health_checks()

        # Get a node for a key
        key = "example-key"
        node = await cluster.get_node_for_key(key)
        print(f"Node for key '{key}': {node.id if node else 'None'}")

        # Save cluster state
        await cluster.save_state()

        # Simulate some time passing
        await asyncio.sleep(5)

    finally:
        # Clean up
        await cluster.close()


if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)
    asyncio.run(example())
