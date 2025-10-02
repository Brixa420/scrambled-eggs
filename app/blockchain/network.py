"""
P2P networking for Brixa blockchain.
Handles node discovery, block propagation, and transaction broadcasting.
"""
import asyncio
import json
import random
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict

@dataclass
class Peer:
    """Represents a peer node in the network."""
    host: str
    port: int
    last_seen: float = 0.0
    version: str = "1.0.0"
    
    def to_dict(self) -> Dict:
        """Convert peer to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Peer':
        """Create peer from dictionary."""
        return cls(**data)

class Network:
    """P2P network manager for Brixa blockchain."""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8333):
        """
        Initialize the P2P network.
        
        Args:
            host: Host to bind to
            port: Port to listen on
        """
        self.host = host
        self.port = port
        self.peers: Dict[Tuple[str, int], Peer] = {}  # (host, port) -> Peer
        self.known_peers: Set[Tuple[str, int]] = set()  # All known peers
        self.server = None
        self.running = False
        
    async def start(self) -> None:
        """Start the P2P server."""
        self.server = await asyncio.start_server(
            self._handle_connection,
            self.host,
            self.port
        )
        self.running = True
        asyncio.create_task(self._maintain_connections())
        
    async def stop(self) -> None:
        """Stop the P2P server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.running = False
    
    async def _handle_connection(self, reader: asyncio.StreamReader, 
                              writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection from peer."""
        peer_addr = writer.get_extra_info('peername')
        print(f"New connection from {peer_addr}")
        
        try:
            while self.running:
                data = await reader.read(4096)
                if not data:
                    break
                    
                message = json.loads(data.decode())
                await self._process_message(message, writer)
        except (ConnectionError, json.JSONDecodeError) as e:
            print(f"Connection error with {peer_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
            print(f"Connection closed with {peer_addr}")
    
    async def _process_message(self, message: Dict, writer: asyncio.StreamWriter) -> None:
        """Process incoming message from peer."""
        msg_type = message.get('type')
        
        if msg_type == 'version':
            await self._handle_version(message, writer)
        elif msg_type == 'verack':
            await self._handle_verack(message, writer)
        elif msg_type == 'addr':
            await self._handle_addr(message)
        elif msg_type == 'getblocks':
            await self._handle_getblocks(message, writer)
        elif msg_type == 'inv':
            await self._handle_inv(message)
        elif msg_type == 'getdata':
            await self._handle_getdata(message, writer)
        elif msg_type == 'block':
            await self._handle_block(message)
        elif msg_type == 'tx':
            await self._handle_tx(message)
    
    async def _handle_version(self, message: Dict, writer: asyncio.StreamWriter) -> None:
        """Handle version handshake."""
        peer_addr = writer.get_extra_info('peername')
        peer = Peer(peer_addr[0], peer_addr[1])
        self.peers[(peer.host, peer.port)] = peer
        
        # Send verack
        verack_msg = {'type': 'verack'}
        writer.write(json.dumps(verack_msg).encode())
        await writer.drain()
    
    async def _handle_verack(self, message: Dict, writer: asyncio.StreamWriter) -> None:
        """Handle verack message."""
        # Connection established, request peer list
        getaddr_msg = {'type': 'getaddr'}
        writer.write(json.dumps(getaddr_msg).encode())
        await writer.drain()
    
    async def _handle_addr(self, message: Dict) -> None:
        """Handle address message (list of peers)."""
        for peer_data in message.get('peers', []):
            peer = Peer.from_dict(peer_data)
            self.known_peers.add((peer.host, peer.port))
    
    async def _handle_getblocks(self, message: Dict, writer: asyncio.StreamWriter) -> None:
        """Handle request for block hashes."""
        # In a real implementation, you would send an 'inv' message
        # with the list of block hashes
        pass
    
    async def _handle_inv(self, message: Dict) -> None:
        """Handle inventory message."""
        # In a real implementation, you would request the actual data
        # for any hashes we're interested in
        pass
    
    async def _handle_getdata(self, message: Dict, writer: asyncio.StreamWriter) -> None:
        """Handle request for specific data."""
        # In a real implementation, you would send the requested data
        pass
    
    async def _handle_block(self, message: Dict) -> None:
        """Handle new block."""
        # In a real implementation, you would validate and add the block
        # to your blockchain
        pass
    
    async def _handle_tx(self, message: Dict) -> None:
        """Handle new transaction."""
        # In a real implementation, you would validate and add the transaction
        # to your mempool
        pass
    
    async def _maintain_connections(self) -> None:
        """Maintain connections to peers."""
        while self.running:
            # Connect to new peers if we don't have enough connections
            if len(self.peers) < 8 and self.known_peers:
                await self._connect_to_peers()
            
            # Ping peers to keep connections alive
            await self._ping_peers()
            
            # Clean up dead connections
            self._cleanup_peers()
            
            await asyncio.sleep(60)  # Check every minute
    
    async def _connect_to_peers(self) -> None:
        """Connect to new peers from the known peers list."""
        for peer_addr in list(self.known_peers):
            if peer_addr not in self.peers and len(self.peers) < 8:
                try:
                    reader, writer = await asyncio.open_connection(
                        peer_addr[0], peer_addr[1])
                    
                    # Send version message
                    version_msg = {
                        'type': 'version',
                        'version': '1.0.0',
                        'services': 1,
                        'timestamp': asyncio.get_event_loop().time(),
                        'addr_recv': {'host': self.host, 'port': self.port},
                        'addr_from': {'host': self.host, 'port': self.port},
                        'nonce': random.getrandbits(64),
                        'user_agent': '/Brixa:1.0.0/',
                        'start_height': 0,
                        'relay': True
                    }
                    
                    writer.write(json.dumps(version_msg).encode())
                    await writer.drain()
                    
                    # Start handling this connection
                    asyncio.create_task(self._handle_connection(reader, writer))
                    
                except (ConnectionError, OSError) as e:
                    print(f"Failed to connect to {peer_addr}: {e}")
                    self.known_peers.discard(peer_addr)
    
    async def _ping_peers(self) -> None:
        """Ping connected peers to keep connections alive."""
        ping_msg = {'type': 'ping', 'nonce': random.getrandbits(64)}
        
        for peer_addr, peer in list(self.peers.items()):
            try:
                reader, writer = await asyncio.open_connection(
                    peer.host, peer.port)
                writer.write(json.dumps(ping_msg).encode())
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                # Peer is down, remove it
                self.peers.pop(peer_addr, None)
    
    def _cleanup_peers(self) -> None:
        """Remove peers that haven't been seen in a while."""
        current_time = asyncio.get_event_loop().time()
        timeout = 3600  # 1 hour
        
        for peer_addr, peer in list(self.peers.items()):
            if current_time - peer.last_seen > timeout:
                self.peers.pop(peer_addr, None)
    
    async def broadcast_block(self, block: Dict) -> None:
        """Broadcast a new block to all connected peers."""
        block_msg = {
            'type': 'block',
            'block': block
        }
        await self._broadcast_message(block_msg)
    
    async def broadcast_transaction(self, tx: Dict) -> None:
        """Broadcast a new transaction to all connected peers."""
        tx_msg = {
            'type': 'tx',
            'tx': tx
        }
        await self._broadcast_message(tx_msg)
    
    async def _broadcast_message(self, message: Dict) -> None:
        """Broadcast a message to all connected peers."""
        message_bytes = json.dumps(message).encode()
        
        for peer_addr, peer in list(self.peers.items()):
            try:
                _, writer = await asyncio.open_connection(peer.host, peer.port)
                writer.write(message_bytes)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                # Peer is down, remove it
                self.peers.pop(peer_addr, None)
