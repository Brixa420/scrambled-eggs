"""
Enhanced P2P Manager with WebRTC DataChannels integration.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from aiortc import RTCPeerConnection, RTCSessionDescription

from .data_channels import DataChannelManager, ChannelType, Message
from .dht_manager import DHTManager
from .mdns_manager import MDNSManager
from ..core.crypto import CryptoEngine

logger = logging.getLogger(__name__)

@dataclass
class PeerConnection:
    """Represents a connection to a peer with multiple data channels."""
    peer_id: str
    pc: RTCPeerConnection
    data_manager: DataChannelManager
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_connected: bool = False

class EnhancedP2PManager:
    """Enhanced P2P manager with WebRTC DataChannels support."""
    
    def __init__(
        self,
        node_id: Optional[str] = None,
        port: int = 0,
        enable_dht: bool = True,
        enable_mdns: bool = True,
        stun_servers: Optional[List[Tuple[str, int]]] = None,
        turn_servers: Optional[List[Tuple[str, int, str, str]]] = None,
    ):
        """Initialize the enhanced P2P manager.
        
        Args:
            node_id: Optional node ID (will generate one if not provided)
            port: Port to listen on (0 = random port)
            enable_dht: Whether to enable DHT for peer discovery
            enable_mdns: Whether to enable mDNS for local discovery
            stun_servers: List of STUN servers as (host, port) tuples
            turn_servers: List of TURN servers as (host, port, username, credential) tuples
        """
        self.node_id = node_id or f"node-{int(time.time())}"
        self.port = port
        self.crypto = CryptoEngine()
        
        # Peer connections
        self.peers: Dict[str, PeerConnection] = {}
        self.pending_offers: Dict[str, str] = {}
        
        # Discovery services
        self.dht = DHTManager() if enable_dht else None
        self.mdns = MDNSManager() if enable_mdns else None
        
        # ICE servers configuration
        self.ice_servers = []
        
        # Add STUN servers
        stun_servers = stun_servers or [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302),
        ]
        
        for host, port in stun_servers:
            self.ice_servers.append({"urls": f"stun:{host}:{port}"})
        
        # Add TURN servers if provided
        if turn_servers:
            for host, port, username, credential in turn_servers:
                self.ice_servers.append({
                    "urls": f"turn:{host}:{port}",
                    "username": username,
                    "credential": credential,
                })
        
        # Event handlers
        self.on_peer_connected: Optional[Callable[[str], None]] = None
        self.on_peer_disconnected: Optional[Callable[[str], None]] = None
        self.on_message: Optional[Callable[[str, bytes, Dict[str, Any]], None]] = None
        
        # Message handlers by type
        self.message_handlers: Dict[str, Callable[[str, bytes, Dict[str, Any]], None]] = {}
    
    async def start(self):
        """Start the P2P manager and discovery services."""
        logger.info(f"Starting P2P manager (Node ID: {self.node_id})")
        
        # Start DHT if enabled
        if self.dht:
            await self.dht.start()
            logger.info("DHT service started")
        
        # Start mDNS if enabled
        if self.mdns:
            await self.mdns.start()
            logger.info("mDNS service started")
        
        logger.info("P2P manager started")
    
    async def stop(self):
        """Stop the P2P manager and clean up resources."""
        logger.info("Stopping P2P manager")
        
        # Close all peer connections
        for peer_id in list(self.peers.keys()):
            await self._disconnect_peer(peer_id)
        
        # Stop discovery services
        if self.dht:
            await self.dht.stop()
        
        if self.mdns:
            await self.mdns.stop()
        
        logger.info("P2P manager stopped")
    
    async def connect_to_peer(self, peer_id: str, peer_info: Dict[str, Any]) -> bool:
        """Connect to a peer using the provided peer info.
        
        Args:
            peer_id: ID of the peer to connect to
            peer_info: Dictionary containing peer connection info (e.g., SDP offer)
            
        Returns:
            bool: True if connection was initiated successfully
        """
        if peer_id in self.peers:
            logger.warning(f"Already connected to peer {peer_id}")
            return True
        
        try:
            # Create a new peer connection
            pc = RTCPeerConnection(iceServers=self.ice_servers)
            
            # Create data channel manager
            data_manager = DataChannelManager(
                peer_id=peer_id,
                crypto_engine=self.crypto,
                on_message=self._on_data_channel_message,
                on_channel_open=lambda p, t: self._on_channel_open(peer_id, t),
                on_channel_close=lambda p, t: self._on_channel_close(peer_id, t),
            )
            
            # Store the peer connection
            self.peers[peer_id] = PeerConnection(
                peer_id=peer_id,
                pc=pc,
                data_manager=data_manager,
                metadata=peer_info.get('metadata', {}),
            )
            
            # Handle ICE candidates
            @pc.on("icecandidate")
            def on_ice_candidate(candidate):
                if candidate:
                    # Send the ICE candidate to the peer via signaling
                    self._send_ice_candidate(peer_id, candidate)
            
            # Handle connection state changes
            @pc.on("connectionstatechange")
            async def on_connection_state_change():
                if pc.connectionState == "connected":
                    await self._on_peer_connected(peer_id)
                elif pc.connectionState in ["disconnected", "failed", "closed"]:
                    await self._on_peer_disconnected(peer_id)
            
            # If we have an offer, process it
            if 'offer' in peer_info:
                answer = await data_manager.connect(peer_info['offer'])
                return {"answer": answer}
            
            # Otherwise, create an offer
            else:
                # Create a data channel
                await data_manager.create_channel(ChannelType.RELIABLE)
                
                # Create an offer
                offer = await pc.createOffer()
                await pc.setLocalDescription(offer)
                
                # Save the offer for when we get an answer
                self.pending_offers[peer_id] = offer.sdp
                
                return {"offer": offer.sdp}
                
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            if peer_id in self.peers:
                await self._disconnect_peer(peer_id)
            return False
    
    async def send_message(
        self,
        peer_id: str,
        data: Union[bytes, str],
        channel_type: ChannelType = ChannelType.RELIABLE,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Send a message to a peer.
        
        Args:
            peer_id: ID of the peer to send the message to
            data: Data to send (bytes or string)
            channel_type: Type of channel to use for sending
            metadata: Additional metadata to include with the message
            
        Returns:
            bool: True if the message was sent successfully
        """
        if peer_id not in self.peers:
            logger.warning(f"Cannot send message to unknown peer: {peer_id}")
            return False
        
        try:
            peer = self.peers[peer_id]
            return await peer.data_manager.send_message(
                data=data,
                channel_type=channel_type,
                is_binary=isinstance(data, bytes),
                metadata=metadata or {},
            )
        except Exception as e:
            logger.error(f"Failed to send message to {peer_id}: {e}")
            return False
    
    def register_message_handler(
        self,
        message_type: str,
        handler: Callable[[str, bytes, Dict[str, Any]], None],
    ) -> None:
        """Register a handler for a specific message type.
        
        Args:
            message_type: The type of message to handle
            handler: Callback function that takes (peer_id, data, metadata)
        """
        self.message_handlers[message_type] = handler
    
    # Internal methods
    
    async def _on_peer_connected(self, peer_id: str) -> None:
        """Handle a peer connection."""
        if peer_id not in self.peers:
            return
            
        peer = self.peers[peer_id]
        peer.is_connected = True
        peer.last_seen = time.time()
        
        logger.info(f"Connected to peer: {peer_id}")
        
        if self.on_peer_connected:
            self.on_peer_connected(peer_id)
    
    async def _on_peer_disconnected(self, peer_id: str) -> None:
        """Handle a peer disconnection."""
        if peer_id not in self.peers:
            return
            
        logger.info(f"Peer disconnected: {peer_id}")
        
        if self.on_peer_disconnected:
            self.on_peer_disconnected(peer_id)
        
        # Clean up the peer connection
        await self._disconnect_peer(peer_id)
    
    async def _disconnect_peer(self, peer_id: str) -> None:
        """Disconnect from a peer and clean up resources."""
        if peer_id not in self.peers:
            return
            
        peer = self.peers[peer_id]
        
        try:
            # Close the data channel manager
            await peer.data_manager.close()
            
            # Close the peer connection
            await peer.pc.close()
        except Exception as e:
            logger.error(f"Error disconnecting from peer {peer_id}: {e}")
        finally:
            # Remove the peer from our connections
            if peer_id in self.peers:
                del self.peers[peer_id]
    
    def _on_data_channel_message(self, peer_id: str, message: Message) -> None:
        """Handle an incoming message from a data channel."""
        try:
            # Update last seen time
            if peer_id in self.peers:
                self.peers[peer_id].last_seen = time.time()
            
            # Extract message type and data
            if isinstance(message.data, bytes):
                # Binary message
                data = message.data
                message_type = message.metadata.get('type', 'binary')
            else:
                # Text message (assume JSON)
                try:
                    msg = json.loads(message.data)
                    message_type = msg.get('type', 'unknown')
                    data = msg.get('data', b'').encode()
                    metadata = msg.get('metadata', {})
                except (json.JSONDecodeError, AttributeError):
                    message_type = 'text'
                    data = message.data.encode()
                    metadata = {}
            
            # Call the appropriate handler
            if message_type in self.message_handlers:
                self.message_handlers[message_type](peer_id, data, metadata)
            elif self.on_message:
                self.on_message(peer_id, data, metadata)
                
        except Exception as e:
            logger.error(f"Error handling message from {peer_id}: {e}")
    
    def _on_channel_open(self, peer_id: str, channel_type: ChannelType) -> None:
        """Handle a data channel opening."""
        logger.debug(f"{channel_type.name} channel opened with {peer_id}")
    
    def _on_channel_close(self, peer_id: str, channel_type: ChannelType) -> None:
        """Handle a data channel closing."""
        logger.debug(f"{channel_type.name} channel closed with {peer_id}")
    
    def _send_ice_candidate(self, peer_id: str, candidate: Any) -> None:
        """Send an ICE candidate to the peer via signaling."""
        # In a real implementation, this would send the candidate to the peer
        # using the signaling channel (e.g., WebSocket, HTTP, etc.)
        logger.debug(f"Sending ICE candidate to {peer_id}: {candidate}")
        
        # TODO: Implement actual signaling mechanism
        # This is where you would send the candidate to the peer via your signaling server
        # For example:
        # await self.signaling.send_ice_candidate(peer_id, candidate.to_json())
        pass
