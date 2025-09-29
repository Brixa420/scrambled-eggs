""
P2P Communication Manager for Brixa
Handles P2P chat, voice, and video communications with end-to-end encryption.
"""
import asyncio
import json
import logging
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from enum import Enum
import webrtc

from ..security.scrambled_eggs_crypto import ScrambledEggsCrypto, ClippyAI

class ConnectionType(Enum):
    CHAT = "chat"
    VOICE = "voice"
    VIDEO = "video"
    FILE = "file"

@dataclass
class PeerConnection:
    peer_id: str
    connection: Any  # WebRTC connection object
    connection_type: ConnectionType
    crypto: ScrambledEggsCrypto
    is_connected: bool = False

class P2PManager:
    """Manages P2P connections for chat, voice, and video."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.peers: Dict[str, PeerConnection] = {}
        self.crypto = ScrambledEggsCrypto()
        self.clippy = ClippyAI()
        self.logger = logging.getLogger(__name__)
        self._message_handlers = {}
        
        # Initialize WebRTC configuration
        self.rtc_config = {
            'iceServers': [
                {'urls': ['stun:stun.l.google.com:19302']},
                # TURN servers will be added dynamically based on NAT traversal needs
            ]
        }
    
    async def connect_to_peer(self, peer_id: str, connection_type: ConnectionType) -> bool:
        """Establish a P2P connection with another peer."""
        if peer_id in self.peers:
            self.logger.warning(f"Already connected to peer {peer_id}")
            return True
            
        try:
            # Initialize WebRTC connection
            pc = webrtc.RTCPeerConnection(self.rtc_config)
            
            # Set up data channel for chat and file transfer
            if connection_type in [ConnectionType.CHAT, ConnectionType.FILE]:
                channel = pc.createDataChannel(connection_type.value)
                channel.on("open", self._on_channel_open(peer_id))
                channel.on("message", self._on_channel_message(peer_id))
            
            # Set up media streams for voice/video
            if connection_type in [ConnectionType.VOICE, ConnectionType.VIDEO]:
                await self._setup_media_streams(pc, connection_type)
            
            # Create and store peer connection
            peer = PeerConnection(
                peer_id=peer_id,
                connection=pc,
                connection_type=connection_type,
                crypto=ScrambledEggsCrypto()
            )
            self.peers[peer_id] = peer
            
            # Handle ICE candidates
            @pc.on("icecandidate")
            def on_ice_candidate(event):
                if event.candidate:
                    # Send ICE candidate to signaling server or peer
                    self._send_ice_candidate(peer_id, event.candidate)
            
            # Handle connection state changes
            @pc.on("connectionstatechange")
            def on_connection_state_change():
                if pc.connectionState == "connected":
                    peer.is_connected = True
                    self.logger.info(f"Connected to peer {peer_id}")
                elif pc.connectionState in ["failed", "closed", "disconnected"]:
                    self._handle_disconnect(peer_id)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to peer {peer_id}: {str(e)}")
            return False
    
    async def send_message(self, peer_id: str, message: str) -> bool:
        """Send an encrypted message to a peer."""
        if peer_id not in self.peers:
            self.logger.error(f"No active connection to peer {peer_id}")
            return False
            
        try:
            peer = self.peers[peer_id]
            
            # Encrypt the message
            ciphertext, metadata = peer.crypto.encrypt(message.encode('utf-8'))
            
            # Create message packet
            packet = {
                'type': 'message',
                'data': ciphertext.hex(),
                'metadata': metadata
            }
            
            # Send through WebRTC data channel
            channel = next((c for c in peer.connection.getDataChannels() 
                          if c.label == 'chat'), None)
            if channel and channel.readyState == 'open':
                channel.send(json.dumps(packet))
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to send message to {peer_id}: {str(e)}")
            return False
    
    def register_message_handler(self, message_type: str, handler: Callable):
        """Register a handler for incoming messages."""
        self._message_handlers[message_type] = handler
    
    # Internal methods
    
    def _on_channel_open(self, peer_id: str) -> Callable:
        """Handle data channel open event."""
        def handler():
            self.logger.info(f"Data channel opened with {peer_id}")
            # Notify any listeners
            self._notify_message_handlers('channel_open', {'peer_id': peer_id})
        return handler
    
    def _on_channel_message(self, peer_id: str) -> Callable:
        """Handle incoming data channel messages."""
        def handler(event):
            try:
                packet = json.loads(event.data)
                
                # Handle different message types
                if packet['type'] == 'message':
                    self._handle_incoming_message(peer_id, packet)
                elif packet['type'] == 'file':
                    self._handle_incoming_file(peer_id, packet)
                
            except Exception as e:
                self.logger.error(f"Error handling message from {peer_id}: {str(e)}")
        return handler
    
    async def _setup_media_streams(self, pc: Any, connection_type: ConnectionType):
        """Set up audio/video streams for WebRTC."""
        constraints = {
            'audio': connection_type in [ConnectionType.VOICE, ConnectionType.VIDEO],
            'video': connection_type == ConnectionType.VIDEO
        }
        
        try:
            stream = await webrtc.get_user_media(constraints)
            for track in stream.getTracks():
                pc.addTrack(track, stream)
        except Exception as e:
            self.logger.error(f"Failed to get media: {str(e)}")
    
    def _handle_incoming_message(self, peer_id: str, packet: Dict[str, Any]):
        """Process an incoming encrypted message."""
        try:
            peer = self.peers[peer_id]
            
            # Decrypt the message
            ciphertext = bytes.fromhex(packet['data'])
            decrypted = peer.crypto.decrypt(ciphertext, packet['metadata'])
            
            # Notify message handlers
            self._notify_message_handlers('message', {
                'peer_id': peer_id,
                'message': decrypted.decode('utf-8'),
                'timestamp': packet.get('timestamp')
            })
            
        except Exception as e:
            self.logger.error(f"Failed to process message from {peer_id}: {str(e)}")
    
    def _notify_message_handlers(self, message_type: str, data: Dict[str, Any]):
        """Notify all registered message handlers."""
        if message_type in self._message_handlers:
            try:
                self._message_handlers[message_type](data)
            except Exception as e:
                self.logger.error(f"Error in {message_type} handler: {str(e)}")
    
    def _send_ice_candidate(self, peer_id: str, candidate: Any):
        """Send ICE candidate to peer via signaling server."""
        # TODO: Implement signaling server communication
        pass
    
    def _handle_disconnect(self, peer_id: str):
        """Handle peer disconnection."""
        if peer_id in self.peers:
            self.peers[peer_id].is_connected = False
            self.logger.info(f"Disconnected from peer {peer_id}")
            self._notify_message_handlers('disconnect', {'peer_id': peer_id})
