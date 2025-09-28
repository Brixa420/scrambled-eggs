"""
Distributed Hash Table (DHT) implementation using Kademlia for peer discovery.
"""
import asyncio
import logging
import pickle
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from kademlia.network import Server
from kademlia.storage import IStorage, Storage as KademliaStorage
from twisted.internet import reactor, defer
from twisted.internet.task import LoopingCall

logger = logging.getLogger(__name__)

@dataclass
class PeerInfo:
    """Information about a peer in the DHT."""
    peer_id: str
    address: str
    port: int
    public_key: str
    last_seen: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'peer_id': self.peer_id,
            'address': self.address,
            'port': self.port,
            'public_key': self.public_key,
            'last_seen': self.last_seen.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PeerInfo':
        """Create a PeerInfo from a dictionary."""
        return cls(
            peer_id=data['peer_id'],
            address=data['address'],
            port=data['port'],
            public_key=data['public_key'],
            last_seen=datetime.fromisoformat(data['last_seen']),
            metadata=data.get('metadata', {})
        )

class DHTStorage(IStorage):
    """Custom storage for Kademlia DHT with expiration."""
    def __init__(self, ttl: int = 3600):
        """Initialize with time-to-live in seconds."""
        self.data = {}
        self.ttl = ttl
        self._cleanup_loop = LoopingCall(self._cleanup_expired)
        self._cleanup_loop.start(300)  # Run cleanup every 5 minutes
    
    def set(self, key: str, value: str) -> None:
        """Store a key-value pair with expiration."""
        self.data[key] = (value, datetime.utcnow() + timedelta(seconds=self.ttl))
    
    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value by key if it exists and hasn't expired."""
        if key not in self.data:
            return default
        
        value, expiration = self.data[key]
        if datetime.utcnow() > expiration:
            del self.data[key]
            return default
        
        return value
    
    def _cleanup_expired(self) -> None:
        """Remove expired entries."""
        now = datetime.utcnow()
        expired = [k for k, (_, exp) in self.data.items() if now > exp]
        for key in expired:
            del self.data[key]
        
        if expired:
            logger.debug(f"Cleaned up {len(expired)} expired DHT entries")

class DHTManager:
    """Manager for the Kademlia DHT network."""
    
    def __init__(self, node_id: str, port: int = 0, bootstrap_nodes: List[Tuple[str, int]] = None):
        """Initialize the DHT manager.
        
        Args:
            node_id: Unique identifier for this node
            port: Port to listen on (0 = random port)
            bootstrap_nodes: List of (host, port) tuples for bootstrap nodes
        """
        self.node_id = node_id
        self.port = port
        self.bootstrap_nodes = bootstrap_nodes or []
        self.server = Server(storage=DHTStorage(ttl=3600))  # 1 hour TTL
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self._running = False
    
    async def start(self) -> None:
        """Start the DHT server and connect to the network."""
        if self._running:
            return
        
        try:
            # Start the server
            await self.server.listen(self.port)
            self.port = self.server.transport.getHost().port
            logger.info(f"DHT server started on port {self.port}")
            
            # Bootstrap with known nodes
            if self.bootstrap_nodes:
                await self.bootstrap(self.bootstrap_nodes)
            
            self._running = True
            
            # Publish our own information
            await self.publish_peer_info()
            
        except Exception as e:
            logger.error(f"Failed to start DHT server: {e}")
            raise
    
    async def stop(self) -> None:
        """Stop the DHT server."""
        if not self._running:
            return
        
        try:
            self.server.stop()
            self._running = False
            logger.info("DHT server stopped")
        except Exception as e:
            logger.error(f"Error stopping DHT server: {e}")
    
    async def bootstrap(self, nodes: List[Tuple[str, int]]) -> None:
        """Bootstrap the DHT with known nodes."""
        if not nodes:
            return
        
        logger.info(f"Bootstrapping DHT with {len(nodes)} nodes...")
        
        for node in nodes:
            try:
                await self.server.bootstrap(node)
                logger.debug(f"Successfully bootstrapped with {node}")
            except Exception as e:
                logger.warning(f"Failed to bootstrap with {node}: {e}")
    
    async def publish_peer_info(self, peer_info: Optional[PeerInfo] = None) -> None:
        """Publish peer information to the DHT."""
        if not peer_info:
            peer_info = PeerInfo(
                peer_id=self.node_id,
                address=self.server.external_ip,
                port=self.port,
                public_key="",  # Should be replaced with actual public key
                metadata={"version": "1.0.0"}
            )
        
        # Store the peer info under its ID
        key = f"peer:{peer_info.peer_id}"
        value = pickle.dumps(peer_info.to_dict())
        await self.server.set(key, value)
        
        # Also store under a well-known key for discovery
        await self.server.set(f"peers:{peer_info.peer_id}", value)
        logger.debug(f"Published peer info for {peer_info.peer_id}")
    
    async def find_peer(self, peer_id: str) -> Optional[PeerInfo]:
        """Find a peer by ID in the DHT."""
        try:
            value = await self.server.get(f"peer:{peer_id}")
            if value:
                return PeerInfo.from_dict(pickle.loads(value))
        except Exception as e:
            logger.error(f"Error finding peer {peer_id}: {e}")
        return None
    
    async def find_peers(self, limit: int = 20) -> List[PeerInfo]:
        """Find peers in the DHT."""
        peers = []
        try:
            # This is a simplified approach - in a real implementation, you'd use
            # a more sophisticated query mechanism to discover peers
            for i in range(1, limit + 1):
                key = f"peers:{i}"  # This is just an example - you'd need a better way to enumerate peers
                value = await self.server.get(key)
                if value:
                    peers.append(PeerInfo.from_dict(pickle.loads(value)))
        except Exception as e:
            logger.error(f"Error finding peers: {e}")
        
        return peers
    
    def run_async(self, coro):
        """Run a coroutine in the event loop."""
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

# Example usage
if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    async def example():
        # Create two DHT nodes
        node1 = DHTManager("node1", 8468)
        node2 = DHTManager("node2", 8469)
        
        # Start the first node
        await node1.start()
        
        # Start the second node and bootstrap with the first
        await node2.start()
        await node2.bootstrap([('127.0.0.1', 8468)])
        
        # Publish some data
        await node1.publish_peer_info()
        await node2.publish_peer_info()
        
        # Find peers
        peers = await node1.find_peers()
        print(f"Node 1 found {len(peers)} peers")
        
        # Keep running
        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await node1.stop()
            await node2.stop()
    
    asyncio.run(example())
