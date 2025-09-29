"""
P2P Networking Module for Scrambled Eggs.
Handles peer discovery, connection management, and secure message routing.
"""

import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional

from aiortc import RTCPeerConnection, RTCSessionDescription

from ..core.crypto import CryptoEngine

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Represents the state of a P2P connection."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"


@dataclass
class Peer:
    """Represents a peer in the P2P network."""

    peer_id: str
    public_key: bytes
    last_seen: float
    connection: Optional[RTCPeerConnection] = None
    state: ConnectionState = ConnectionState.DISCONNECTED

    def to_dict(self) -> Dict[str, Any]:
        """Convert peer to dictionary."""
        return {
            "peer_id": self.peer_id,
            "public_key": self.public_key.hex() if self.public_key else None,
            "last_seen": self.last_seen,
            "state": self.state.value,
        }


class P2PManager:
    """Manages P2P connections and message routing."""

    def __init__(
        self,
        crypto_engine: CryptoEngine,
        on_message: Callable[[str, bytes], None],
        on_peer_connected: Optional[Callable[[str], None]] = None,
        on_peer_disconnected: Optional[Callable[[str], None]] = None,
    ):
        """
        Initialize the P2P manager.

        Args:
            crypto_engine: Instance of CryptoEngine for encryption
            on_message: Callback for received messages (peer_id, message)
            on_peer_connected: Callback when a peer connects
            on_peer_disconnected: Callback when a peer disconnects
        """
        self.crypto = crypto_engine
        self.peers: Dict[str, Peer] = {}
        self.on_message = on_message
        self.on_peer_connected = on_peer_connected
        self.on_peer_disconnected = on_peer_disconnected
        self._peer_connection = None
        self._data_channels: Dict[str, Any] = {}
        self._ice_servers = [{"urls": ["stun:stun.l.google.com:19302"]}]

    async def initialize(self):
        """Initialize the P2P manager and set up the peer connection."""
        config = {"iceServers": self._ice_servers}
        self._peer_connection = RTCPeerConnection(configuration=config)

        # Set up event handlers
        self._peer_connection.on("connectionstatechange", self._on_connection_state_change)
        self._peer_connection.on("iceconnectionstatechange", self._on_ice_connection_state_change)
        self._peer_connection.on("datachannel", self._on_data_channel)

        logger.info("P2P manager initialized")

    async def connect_to_peer(self, peer_id: str, offer_sdp: str) -> str:
        """
        Connect to a peer using a signaling offer.

        Args:
            peer_id: ID of the peer to connect to
            offer_sdp: SDP offer from the peer

        Returns:
            str: SDP answer to send back to the peer
        """
        if peer_id in self.peers and self.peers[peer_id].state == ConnectionState.CONNECTED:
            logger.warning(f"Already connected to peer {peer_id}")
            return ""

        try:
            # Create a new data channel
            data_channel = self._peer_connection.createDataChannel(f"chat-{peer_id}")
            self._setup_data_channel(data_channel, peer_id)

            # Create an offer
            offer = RTCSessionDescription(sdp=offer_sdp, type="offer")
            await self._peer_connection.setRemoteDescription(offer)

            # Create and set local description
            answer = await self._peer_connection.createAnswer()
            await self._peer_connection.setLocalDescription(answer)

            # Create or update peer
            if peer_id not in self.peers:
                self.peers[peer_id] = Peer(
                    peer_id=peer_id,
                    public_key=None,  # Will be set during key exchange
                    last_seen=time.time(),
                )

            self.peers[peer_id].state = ConnectionState.CONNECTING
            self.peers[peer_id].connection = self._peer_connection

            return answer.sdp

        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            if peer_id in self.peers:
                self.peers[peer_id].state = ConnectionState.FAILED
            raise

    async def send_message(self, peer_id: str, message: bytes) -> bool:
        """
        Send a message to a peer.

        Args:
            peer_id: ID of the target peer
            message: Message to send (will be encrypted)

        Returns:
            bool: True if message was sent successfully
        """
        if peer_id not in self.peers or self.peers[peer_id].state != ConnectionState.CONNECTED:
            logger.warning(f"Cannot send message to {peer_id}: Not connected")
            return False

        try:
            # Encrypt the message for the target peer
            # In a real implementation, we'd use the peer's public key
            encrypted_msg = self.crypto.encrypt_message(message, associated_data=peer_id.encode())

            # Convert to JSON for transmission
            message_data = {
                "type": "message",
                "data": {
                    "ciphertext": encrypted_msg.ciphertext.hex(),
                    "key_id": encrypted_msg.key_id,
                    "iv": encrypted_msg.iv.hex(),
                    "tag": encrypted_msg.tag.hex(),
                    "metadata": encrypted_msg.metadata,
                },
            }

            # Send through the data channel
            if peer_id in self._data_channels and self._data_channels[peer_id].readyState == "open":
                self._data_channels[peer_id].send(json.dumps(message_data))
                return True
            else:
                logger.warning(f"No active data channel for peer {peer_id}")
                return False

        except Exception as e:
            logger.error(f"Failed to send message to {peer_id}: {e}")
            return False

    def _on_data_channel(self, channel):
        """Handle new data channel from a peer."""
        peer_id = channel.label.split("-")[-1]  # Extract peer ID from channel label
        logger.info(f"New data channel from peer {peer_id}")

        # Store the channel
        self._data_channels[peer_id] = channel

        # Set up message handler
        @channel.on("message")
        def on_message(message):
            self._handle_message(peer_id, message)

    def _handle_message(self, peer_id: str, message: str):
        """Handle incoming message from a peer."""
        try:
            message_data = json.loads(message)

            if message_data["type"] == "message":
                # Decrypt the message
                data = message_data["data"]
                ciphertext = bytes.fromhex(data["ciphertext"])
                iv = bytes.fromhex(data["iv"])
                tag = bytes.fromhex(data["tag"])

                # In a real implementation, we'd use the key_id to look up the decryption key
                # For now, we'll just pass the raw data to the callback
                decrypted = self.crypto.decrypt_message(
                    ciphertext,
                    key=None,  # Should be looked up using key_id
                    iv=iv,
                    tag=tag,
                    associated_data=peer_id.encode(),
                )

                # Notify the application
                self.on_message(peer_id, decrypted)

        except Exception as e:
            logger.error(f"Error handling message from {peer_id}: {e}")

    def _on_connection_state_change(self):
        """Handle connection state changes."""
        if self._peer_connection:
            logger.info(f"Connection state changed to {self._peer_connection.connectionState}")

            # Update all peers' connection states
            new_state = ConnectionState(self._peer_connection.connectionState)
            for peer_id in self.peers:
                self.peers[peer_id].state = new_state

                # Notify on connection state changes
                if new_state == ConnectionState.CONNECTED and self.on_peer_connected:
                    self.on_peer_connected(peer_id)
                elif new_state == ConnectionState.DISCONNECTED and self.on_peer_disconnected:
                    self.on_peer_disconnected(peer_id)

    def _on_ice_connection_state_change(self):
        """Handle ICE connection state changes."""
        if self._peer_connection:
            logger.info(
                f"ICE connection state changed to {self._peer_connection.iceConnectionState}"
            )

    async def close(self):
        """Close all connections and clean up resources."""
        if self._peer_connection:
            await self._peer_connection.close()
            self._peer_connection = None

        # Close all data channels
        for channel in self._data_channels.values():
            channel.close()
        self._data_channels.clear()

        # Update peer states
        for peer_id in self.peers:
            self.peers[peer_id].state = ConnectionState.DISCONNECTED

        logger.info("P2P manager shut down")
