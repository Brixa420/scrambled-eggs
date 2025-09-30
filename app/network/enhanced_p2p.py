"""
Enhanced P2P Networking Module for Scrambled Eggs.
Implements a robust P2P networking layer with DHT-based peer discovery and secure messaging.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from p2p.dht import DHTNode, NodeID
from p2p.network import Network, Peer as BasePeer
from p2p.protocol import Protocol, ProtocolHandler
from p2p.transport import Transport, TCPTransport

from .discovery import DiscoveryProtocol
from .nat_traversal import NATTraversal, NATType
from .bandwidth import BandwidthMonitor, TrafficShaper, QoSManager, AdaptiveController

from ..core.crypto import CryptoEngine
from ..core.config import settings

logger = logging.getLogger(__name__)

class ConnectionState(Enum):
    """Represents the state of a P2P connection."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"

@dataclass
class PeerInfo:
    """Represents information about a peer in the network."""
    peer_id: str
    public_key: bytes
    addresses: List[Tuple[str, int]] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    state: ConnectionState = ConnectionState.DISCONNECTED
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert peer info to a dictionary."""
        return {
            "peer_id": self.peer_id,
            "public_key": self.public_key.hex() if self.public_key else None,
            "addresses": [f"{host}:{port}" for host, port in self.addresses],
            "last_seen": self.last_seen,
            "state": self.state.value,
            "metadata": self.metadata,
        }

class P2PNetwork:
    """Manages the P2P network layer with DHT-based peer discovery."""
    
    def __init__(self, node_id: Optional[str] = None, port: int = 0):
        """Initialize the P2P network.
        
        Args:
            node_id: Optional node ID (will generate one if not provided)
            port: Port to listen on (0 for random port)
        """
        self.node_id = node_id or self._generate_node_id()
        self.port = port
        self.crypto = CryptoEngine()
        
        # Generate or load node key pair
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Initialize NAT traversal
        self.nat_traversal = NATTraversal(port=self.port)
        
        # Initialize DHT node with discovered port
        self.dht = DHTNode(self.node_id, port=self.port)
        
        # Initialize network transport with NAT traversal
        self.transport = TCPTransport(self.node_id, port=self.port)
        self.network = Network(self.transport)
        
        # Initialize discovery protocol
        self.discovery = DiscoveryProtocol(self.dht, port=self.port)
        
        # Protocol handlers
        self.protocols: Dict[str, Protocol] = {}
        self.message_handlers: Dict[str, Callable] = {}
        
        # Known peers
        self.peers: Dict[str, PeerInfo] = {}
        self.connected_peers: Dict[str, BasePeer] = {}
        
        # Bandwidth management
        self.bandwidth_monitor = BandwidthMonitor()
        self.traffic_shaper = TrafficShaper(self.bandwidth_monitor)
        self.qos_manager = QoSManager(self.bandwidth_monitor, self.traffic_shaper)
        self.bandwidth_controller = AdaptiveController(
            self.bandwidth_monitor,
            self.traffic_shaper,
            self.qos_manager
        )
        
        # Event loop and tasks
        self.loop = asyncio.get_event_loop()
        self.running = False
    
    def _generate_node_id(self) -> str:
        """Generate a random node ID."""
        return NodeID.random().hex()
    
    async def start(self):
        """Start the P2P network with bandwidth management."""
        if self.running:
            return
            
        self.running = True
        
        try:
            # Initialize NAT traversal
            await self.nat_traversal.initialize()
            
            # Start network components with discovered port
            await self.transport.start()
            
            # Start DHT with discovered public address if available
            if self.nat_traversal.nat_info.public_ip:
                self.dht = DHTNode(
                    self.node_id,
                    port=self.port,
                    external_ip=self.nat_traversal.nat_info.public_ip,
                    external_port=self.nat_traversal.nat_info.public_port
                )
                
            await self.dht.start()
            
            # Start discovery protocol
            await self.discovery.start()
            
            # Start protocol handlers
            for protocol in self.protocols.values():
                await protocol.start()
            
            # Start bandwidth management components
            await self.bandwidth_monitor.start()
            await self.traffic_shaper.start()
            await self.qos_manager.start()
            await self.bandwidth_controller.start()
            
            logger.info(f"P2P network started on port {self.port}")
            logger.info(f"NAT Type: {self.nat_traversal.nat_info.type}")
            if self.nat_traversal.nat_info.public_ip:
                logger.info(f"Public address: {self.nat_traversal.nat_info.public_ip}:"
                          f"{self.nat_traversal.nat_info.public_port}")
            
            # Log initial bandwidth stats
            stats = self.bandwidth_monitor.get_stats()
            logger.info(f"Initial bandwidth stats: {stats}")
                          
        except Exception as e:
            logger.error(f"Failed to start P2P network: {e}")
            await self.stop()
            raise
        
        self.tasks = [
            self.loop.create_task(self._bootstrap_task()),
            self.loop.create_task(self._peer_discovery_task()),
            self.loop.create_task(self._connection_cleanup_task()),
        ]
        
        self.running = True
        logger.info("P2P network started")
    
    async def stop(self):
        """Stop the P2P network and cleanup bandwidth management."""
        if not self.running:
            return
            
        self.running = False
        
        try:
            # Stop all tasks
            for task in self.tasks:
                if not task.done():
                    task.cancel()
                    
            # Stop network components
            await self.transport.stop()
            
            # Stop discovery and NAT traversal
            await self.discovery.stop()
            await self.nat_traversal.close()
            
            # Stop DHT
            await self.dht.stop()
            
            # Stop protocol handlers
            for protocol in self.protocols.values():
                await protocol.stop()
            
            # Stop bandwidth management components
            await self.bandwidth_controller.stop()
            await self.qos_manager.stop()
            await self.traffic_shaper.stop()
            await self.bandwidth_monitor.stop()
            
            # Log final bandwidth stats
            stats = self.bandwidth_monitor.get_stats()
            logger.info(f"Final bandwidth stats: {stats}")
            logger.info("P2P network stopped")
            
        except Exception as e:
            logger.error(f"Error during P2P network shutdown: {e}")
            raise
    
    async def _bootstrap_task(self) -> None:
        """Background task for bootstrapping the P2P network."""
        while self.running:
            try:
                # Try to bootstrap with known bootstrap nodes
                bootstrap_nodes = settings.P2P_BOOTSTRAP_NODES
                if bootstrap_nodes:
                    for addr in bootstrap_nodes:
                        try:
                            host, port = addr.split(":")
                            await self.dht.bootstrap([(host, int(port))])
                            break
                        except Exception as e:
                            logger.warning(f"Failed to bootstrap with {addr}: {e}")
                
                # Wait before next bootstrap attempt
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in bootstrap task: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _peer_discovery_task(self) -> None:
        """Background task for discovering new peers."""
        while self.running:
            try:
                # Discover peers via DHT
                peers = await self.dht.find_peers()
                
                # Connect to new peers
                for peer_info in peers:
                    if peer_info.node_id != self.node_id and peer_info.node_id not in self.peers:
                        await self.connect_peer(peer_info)
                
                # Update peer list
                await self._update_peer_list()
                
                # Wait before next discovery
                await asyncio.sleep(60)  # 1 minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in peer discovery task: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _connection_cleanup_task(self) -> None:
        """Background task for cleaning up stale connections."""
        while self.running:
            try:
                current_time = time.time()
                stale_peers = []
                
                # Find stale peers
                for peer_id, peer_info in self.peers.items():
                    if current_time - peer_info.last_seen > settings.P2P_PEER_TIMEOUT:
                        stale_peers.append(peer_id)
                
                # Remove stale peers
                for peer_id in stale_peers:
                    if peer_id in self.connected_peers:
                        await self.disconnect_peer(peer_id)
                    self.peers.pop(peer_id, None)
                
                # Wait before next cleanup
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in connection cleanup task: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    def _register_default_handlers(self) -> None:
        """Register default protocol handlers."""
        self.register_message_handler("ping", self._handle_ping)
        self.register_message_handler("pong", self._handle_pong)
    
    async def _handle_ping(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle ping message."""
        await self.send_message(peer_id, "pong", {"timestamp": message.get("timestamp")})
    
    async def _handle_pong(self, peer_id: str, message: Dict[str, Any]) -> None:
        """Handle pong message."""
        if peer_id in self.peers:
            self.peers[peer_id].last_seen = time.time()
    
    async def connect_peer(self, peer_info: PeerInfo) -> bool:
        """Connect to a peer."""
        if peer_info.peer_id == self.node_id:
            return False
            
        if peer_info.peer_id in self.connected_peers:
            return True
        
        try:
            # Update peer info
            self.peers[peer_info.peer_id] = peer_info
            
            # Connect to peer
            peer = await self.network.connect(peer_info.addresses[0])
            if peer:
                self.connected_peers[peer_info.peer_id] = peer
                peer_info.state = ConnectionState.CONNECTED
                peer_info.last_seen = time.time()
                logger.info(f"Connected to peer {peer_info.peer_id}")
                return True
            
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_info.peer_id}: {e}")
            peer_info.state = ConnectionState.FAILED
        
        return False
    
    async def disconnect_peer(self, peer_id: str) -> None:
        """Disconnect from a peer."""
        if peer_id in self.connected_peers:
            peer = self.connected_peers.pop(peer_id)
            await peer.disconnect()
            
            if peer_id in self.peers:
                self.peers[peer_id].state = ConnectionState.DISCONNECTED
            
            logger.info(f"Disconnected from peer {peer_id}")
    
    async def broadcast_message(self, message_type: str, payload: Dict[str, Any], 
                              exclude_peers: Optional[Set[str]] = None) -> None:
        """Broadcast a message to all connected peers."""
        if exclude_peers is None:
            exclude_peers = set()
        
        for peer_id in list(self.connected_peers.keys()):
            if peer_id not in exclude_peers:
                await self.send_message(peer_id, message_type, payload)
    
    async def send_message(self, peer_id: str, message_type: str, payload: Dict[str, Any], 
                         priority: int = 3) -> bool:
        """Send a message to a specific peer with bandwidth management.
        
        Args:
            peer_id: ID of the peer to send the message to
            message_type: Type of the message (used for QoS classification)
            payload: Message payload (must be JSON-serializable)
            priority: Message priority (1-5, where 1 is highest)
            
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        if peer_id not in self.connected_peers:
            logger.warning(f"No active connection to peer {peer_id}")
            return False
        
        try:
            # Create message with metadata
            message = {
                "type": message_type,
                "payload": payload,
                "timestamp": time.time(),
                "sender": self.node_id,
                "priority": min(max(1, priority), 5)  # Ensure priority is 1-5
            }
            
            # Serialize and encrypt the message
            message_json = json.dumps(message)
            encrypted_message = self.crypto.encrypt_message(
                message_json.encode(),
                self.peers[peer_id].public_key
            )
            
            # Record message size for bandwidth monitoring
            message_size = len(encrypted_message)
            self.bandwidth_monitor.record_sent(peer_id, message_size)
            
            # Apply traffic shaping based on message type and priority
            await self.traffic_shaper.shape_traffic(
                peer_id=peer_id,
                message_type=message_type,
                size=message_size,
                priority=priority
            )
            
            # Send the message
            await self.connected_peers[peer_id].send(encrypted_message)
            await self.connected_peers[peer_id].send(json.dumps(message).encode())
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message to {peer_id}: {e}")
            return False
    
    def register_message_handler(self, message_type: str, 
                               handler: Callable[[str, Dict[str, Any]], None]) -> None:
        """Register a message handler for a specific message type."""
        self.message_handlers[message_type] = handler
    
    async def _handle_incoming_message(self, peer_id: str, message: bytes) -> None:
        """Handle an incoming message from a peer."""
        try:
            # Parse message
            try:
                message_data = json.loads(message.decode())
            except json.JSONDecodeError:
                logger.warning(f"Received invalid JSON message from {peer_id}")
                return
            
            # Decrypt message if needed
            if message_data.get("encrypted", False):
                try:
                    encrypted_data = bytes.fromhex(message_data["data"])
                    decrypted_data = self.crypto.decrypt_asymmetric(encrypted_data, self.private_key)
                    message_data = json.loads(decrypted_data.decode())
                except Exception as e:
                    logger.error(f"Failed to decrypt message from {peer_id}: {e}")
                    return
            
            # Update last seen
            if peer_id in self.peers:
                self.peers[peer_id].last_seen = time.time()
            
            # Handle message
            message_type = message_data.get("type")
            if message_type in self.message_handlers:
                await self.message_handlers[message_type](peer_id, message_data.get("payload", {}))
            else:
                logger.warning(f"No handler registered for message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error handling message from {peer_id}: {e}")
    
    async def _update_peer_list(self) -> None:
        """Update the list of known peers from DHT."""
        try:
            # Get peers from DHT
            peers = await self.dht.get_peers()
            
            # Update known peers
            for peer_info in peers:
                if peer_info.node_id != self.node_id:
                    if peer_info.node_id not in self.peers:
                        self.peers[peer_info.node_id] = PeerInfo(
                            peer_id=peer_info.node_id,
                            public_key=peer_info.public_key,
                            addresses=peer_info.addresses,
                        )
                    else:
                        # Update addresses if needed
                        existing_peer = self.peers[peer_info.node_id]
                        existing_peer.addresses = list(set(existing_peer.addresses + peer_info.addresses))
                        
        except Exception as e:
            logger.error(f"Failed to update peer list: {e}")

# Example usage:
# async def main():
#     # Create and start P2P network
#     p2p = P2PNetwork(port=8000)
#     await p2p.start()
#     
#     try:
#         # Keep the network running
#         while True:
#             await asyncio.sleep(1)
#     except KeyboardInterrupt:
#         await p2p.stop()
# 
# if __name__ == "__main__":
#     asyncio.run(main())
