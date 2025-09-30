"""
Network Partition Manager for Scrambled Eggs P2P Network.
Handles detection and recovery from network partitions.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Callable, Awaitable

from .discovery import DiscoveryProtocol
from .enhanced_p2p import P2PNetwork, PeerInfo

logger = logging.getLogger(__name__)

class PartitionState(Enum):
    """Represents the state of network partitioning."""
    STABLE = auto()
    SUSPECTED = auto()
    PARTITIONED = auto()
    RECOVERING = auto()

@dataclass
class PartitionInfo:
    """Information about a network partition."""
    partition_id: str
    nodes: Set[str] = field(default_factory=set)
    state: PartitionState = PartitionState.STABLE
    detected_at: float = 0.0
    last_checked: float = 0.0
    recovery_attempts: int = 0

class NetworkPartitionManager:
    """Manages network partition detection and recovery."""
    
    def __init__(
        self,
        p2p_network: P2PNetwork,
        discovery: DiscoveryProtocol,
        heartbeat_interval: float = 5.0,
        suspicion_threshold: int = 3,
        recovery_timeout: float = 30.0,
        max_recovery_attempts: int = 3
    ):
        self.p2p = p2p_network
        self.discovery = discovery
        self.heartbeat_interval = heartbeat_interval
        self.suspicion_threshold = suspicion_threshold
        self.recovery_timeout = recovery_timeout
        self.max_recovery_attempts = max_recovery_attempts
        
        self.state = PartitionState.STABLE
        self.partitions: Dict[str, PartitionInfo] = {}
        self.node_states: Dict[str, Dict] = {}
        self.heartbeat_counters: Dict[str, int] = {}
        self.callbacks: Dict[str, List[Callable[[PartitionInfo], Awaitable[None]]]] = {
            'on_partition_detected': [],
            'on_recovery_started': [],
            'on_recovery_completed': []
        }
        
        # Start background tasks
        self._running = False
        self._tasks: List[asyncio.Task] = []
        
    def register_callback(self, event: str, callback: Callable[[PartitionInfo], Awaitable[None]]):
        """Register a callback for partition events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event}")
            
    async def start(self):
        """Start the partition manager."""
        if self._running:
            return
            
        self._running = True
        self._tasks = [
            asyncio.create_task(self._monitor_partitions()),
            asyncio.create_task(self._check_node_health())
        ]
        logger.info("Network partition manager started")
        
    async def stop(self):
        """Stop the partition manager."""
        if not self._running:
            return
            
        self._running = False
        for task in self._tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Network partition manager stopped")
        
    async def _monitor_partitions(self):
        """Monitor the network for partitions."""
        while self._running:
            try:
                await self._detect_partitions()
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in partition monitoring: {e}")
                await asyncio.sleep(5)  # Back off on error
                
    async def _detect_partitions(self):
        """Detect network partitions using SWIM protocol."""
        current_time = time.time()
        known_nodes = set(self.discovery.known_nodes.keys())
        
        # Update node states
        for node_id in known_nodes:
            if node_id not in self.node_states:
                self.node_states[node_id] = {
                    'last_seen': current_time,
                    'suspicion': 0,
                    'status': 'alive'
                }
            
            # Check if node is responsive
            try:
                if await self._check_node(node_id):
                    self.node_states[node_id].update({
                        'last_seen': current_time,
                        'suspicion': 0,
                        'status': 'alive'
                    })
                else:
                    self.node_states[node_id]['suspicion'] += 1
                    if self.node_states[node_id]['suspicion'] >= self.suspicion_threshold:
                        self.node_states[node_id]['status'] = 'suspected'
                        await self._handle_suspected_node(node_id)
                        
            except Exception as e:
                logger.warning(f"Error checking node {node_id}: {e}")
                self.node_states[node_id]['suspicion'] += 1
                
        # Check for partitions
        await self._update_partitions()
        
    async def _check_node(self, node_id: str) -> bool:
        """Check if a node is responsive."""
        try:
            # Try to ping the node directly
            if node_id in self.p2p.connected_peers:
                return await self.p2p.ping_peer(node_id)
                
            # If not directly connected, try through DHT
            node_info = self.discovery.known_nodes.get(node_id)
            if node_info:
                return await self.discovery.ping(node_info.addr[0], node_info.addr[1])
                
            return False
            
        except Exception as e:
            logger.debug(f"Node check failed for {node_id}: {e}")
            return False
            
    async def _handle_suspected_node(self, node_id: str):
        """Handle a node that is suspected to be down."""
        # Ask other nodes about this node's status
        responses = await self._gossip_about_node(node_id)
        
        # If majority think the node is down, mark it as partitioned
        alive_count = sum(1 for r in responses if r)
        if alive_count < len(responses) / 2:
            await self._mark_node_partitioned(node_id)
            
    async def _gossip_about_node(self, node_id: str) -> List[bool]:
        """Gossip with other nodes about a node's status."""
        # Implementation would query multiple nodes about the target node's status
        # This is a simplified version
        responses = []
        for peer_id in list(self.p2p.connected_peers.keys())[:3]:  # Ask up to 3 peers
            try:
                response = await self.p2p.send_rpc(peer_id, 'check_node', {'node_id': node_id})
                responses.append(response.get('alive', False))
            except Exception as e:
                logger.debug(f"Gossip failed with {peer_id}: {e}")
                
        return responses
        
    async def _mark_node_partitioned(self, node_id: str):
        """Mark a node as partitioned and update partition info."""
        self.node_states[node_id]['status'] = 'partitioned'
        
        # Find or create a partition for this node
        partition = next((p for p in self.partitions.values() if node_id in p.nodes), None)
        if not partition:
            partition_id = f"partition_{len(self.partitions) + 1}"
            partition = PartitionInfo(
                partition_id=partition_id,
                nodes={node_id},
                state=PartitionState.PARTITIONED,
                detected_at=time.time()
            )
            self.partitions[partition_id] = partition
            
            # Notify about new partition
            await self._trigger_callbacks('on_partition_detected', partition)
            
    async def _update_partitions(self):
        """Update partition information based on current node states."""
        current_time = time.time()
        
        # Check for recovered nodes
        for partition_id in list(self.partitions.keys()):
            partition = self.partitions[partition_id]
            recovered_nodes = set()
            
            for node_id in list(partition.nodes):
                node_state = self.node_states.get(node_id, {})
                if node_state.get('status') == 'alive':
                    recovered_nodes.add(node_id)
                    
            if recovered_nodes:
                await self._handle_recovered_nodes(partition_id, recovered_nodes)
                
    async def _handle_recovered_nodes(self, partition_id: str, node_ids: Set[str]):
        """Handle nodes that have recovered from a partition."""
        partition = self.partitions.get(partition_id)
        if not partition:
            return
            
        partition.nodes -= node_ids
        
        if not partition.nodes:  # All nodes recovered
            partition.state = PartitionState.STABLE
            await self._trigger_callbacks('on_recovery_completed', partition)
            del self.partitions[partition_id]
            
    async def _check_node_health(self):
        """Background task to periodically check node health."""
        while self._running:
            try:
                await self._check_connected_nodes()
                await asyncio.sleep(self.heartbeat_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in node health check: {e}")
                await asyncio.sleep(5)
                
    async def _check_connected_nodes(self):
        """Check health of directly connected nodes."""
        for node_id in list(self.p2p.connected_peers.keys()):
            try:
                is_alive = await self.p2p.ping_peer(node_id)
                if not is_alive:
                    await self._handle_node_failure(node_id)
            except Exception as e:
                logger.warning(f"Failed to check node {node_id}: {e}")
                await self._handle_node_failure(node_id)
                
    async def _handle_node_failure(self, node_id: str):
        """Handle a node that has failed to respond."""
        if node_id in self.node_states:
            self.node_states[node_id]['suspicion'] += 1
            if self.node_states[node_id]['suspicion'] >= self.suspicion_threshold:
                self.node_states[node_id]['status'] = 'suspected'
                await self._handle_suspected_node(node_id)
                
    async def _trigger_callbacks(self, event: str, partition: PartitionInfo):
        """Trigger registered callbacks for an event."""
        for callback in self.callbacks.get(event, []):
            try:
                await callback(partition)
            except Exception as e:
                logger.error(f"Error in {event} callback: {e}")
