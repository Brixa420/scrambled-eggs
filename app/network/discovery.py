"""
Node Discovery Protocol for Scrambled Eggs P2P Network.
Implements Kademlia-like DHT for peer discovery and NAT traversal techniques.
"""

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import aiodns
from aiohttp import web
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519

from .dht_manager import DHTManager
from ..core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class NodeInfo:
    """Represents a node in the discovery network."""
    node_id: bytes
    public_key: bytes
    addresses: List[Tuple[str, int]]  # List of (ip, port) tuples
    last_seen: float
    distance: int = 0  # XOR distance from local node

class DiscoveryProtocol:
    """Implements the node discovery protocol using Kademlia DHT."""
    
    def __init__(self, dht: DHTManager, port: int = 30303):
        self.dht = dht
        self.port = port
        self.local_node_id = self._generate_node_id()
        self.known_nodes: Dict[bytes, NodeInfo] = {}
        self.bootstrap_nodes = settings.BOOTSTRAP_NODES
        self.running = False
        
        # For NAT traversal
        self.stun_servers = [
            ('stun.l.google.com', 19302),
            ('stun1.l.google.com', 19302),
            ('stun2.l.google.com', 19302)
        ]
        self.public_address: Optional[Tuple[str, int]] = None
        
    def _generate_node_id(self) -> bytes:
        """Generate a random node ID."""
        return x25519.X25519PrivateKey.generate().public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    async def start(self):
        """Start the discovery protocol."""
        if self.running:
            return
            
        self.running = True
        
        # Start DHT server
        await self.dht.start()
        
        # Start NAT traversal
        await self._discover_public_address()
        
        # Start discovery tasks
        asyncio.create_task(self._bootstrap())
        asyncio.create_task(self._refresh_nodes())
        
    async def stop(self):
        """Stop the discovery protocol."""
        self.running = False
        await self.dht.stop()
        
    async def _discover_public_address(self):
        """Discover public address using STUN servers."""
        for stun_host, stun_port in self.stun_servers:
            try:
                reader, writer = await asyncio.open_connection(stun_host, stun_port)
                
                # Simple STUN binding request
                request = b'\x00\x01\x00\x00'  # Binding request
                writer.write(request)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(1024), timeout=5)
                
                # Parse STUN response (simplified)
                if len(response) > 20:
                    # Get the MAPPED-ADDRESS attribute (0x0001)
                    attr_type = response[20:22]
                    if attr_type == b'\x00\x01':
                        port = int.from_bytes(response[24:26], 'big')
                        ip = socket.inet_ntoa(response[26:30])
                        self.public_address = (ip, port)
                        logger.info(f"Discovered public address: {ip}:{port}")
                        return
                        
            except (asyncio.TimeoutError, ConnectionError) as e:
                logger.warning(f"STUN request to {stun_host}:{stun_port} failed: {e}")
                continue
                
        logger.warning("Failed to determine public address via STUN")
        
    async def _bootstrap(self):
        """Bootstrap the node by connecting to known bootstrap nodes."""
        for node_id, (host, port) in self.bootstrap_nodes.items():
            try:
                await self.ping(host, port)
            except Exception as e:
                logger.warning(f"Failed to bootstrap with {host}:{port}: {e}")
                
    async def _refresh_nodes(self):
        """Periodically refresh the node list."""
        while self.running:
            # Find the 16 closest nodes to a random target
            target = os.urandom(32)
            nodes = await self.dht.find_nodes(target)
            
            # Update known nodes
            for node in nodes:
                if node.node_id not in self.known_nodes:
                    self.known_nodes[node.node_id] = node
                    
            # Remove stale nodes
            current_time = time.time()
            stale_nodes = [
                node_id for node_id, node in self.known_nodes.items()
                if current_time - node.last_seen > 3600  # 1 hour timeout
            ]
            for node_id in stale_nodes:
                self.known_nodes.pop(node_id, None)
                
            await asyncio.sleep(300)  # Refresh every 5 minutes
            
    async def ping(self, host: str, port: int) -> bool:
        """Ping a remote node to check connectivity."""
        try:
            # Implementation would send a PING message and wait for PONG
            # This is a simplified version
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(b'PING')
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4), timeout=5)
            writer.close()
            await writer.wait_closed()
            return response == b'PONG'
        except (asyncio.TimeoutError, ConnectionError) as e:
            logger.warning(f"Ping to {host}:{port} failed: {e}")
            return False
            
    def get_closest_nodes(self, target: bytes, count: int = 8) -> List[NodeInfo]:
        """Get the closest nodes to the given target ID."""
        nodes = list(self.known_nodes.values())
        
        # Calculate distances
        for node in nodes:
            distance = int.from_bytes(
                bytes(a ^ b for a, b in zip(target, node.node_id)),
                'big'
            )
            node.distance = distance
            
        # Sort by distance and return top N
        return sorted(nodes, key=lambda n: n.distance)[:count]
