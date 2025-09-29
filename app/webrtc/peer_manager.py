"""
WebRTC peer connection manager.

Handles WebRTC peer connections and data channels.
"""

import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Set

from aiortc import RTCPeerConnection
from aiortc.contrib.signaling import object_from_string, object_to_string

logger = logging.getLogger(__name__)


class WebRTCPeerManager:
    """Manages WebRTC peer connections and data channels."""

    def __init__(
        self,
        peer_id: str,
        room_id: str,
        signaling_url: str = "ws://localhost:8080/ws",
        ice_servers: Optional[list] = None,
    ):
        """Initialize the WebRTC peer manager.

        Args:
            peer_id: Unique identifier for this peer
            room_id: Room ID to join
            signaling_url: URL of the signaling server
            ice_servers: List of STUN/TURN servers
        """
        self.peer_id = peer_id
        self.room_id = room_id
        base_url = f"{signaling_url}?peer_id={peer_id}"
        self.signaling_url = f"{base_url}&room_id={room_id}"
        self.ice_servers = ice_servers or [
            {"urls": "stun:stun.l.google.com:19302"},
            # Add TURN servers here if needed
        ]

        self.peers: Dict[str, RTCPeerConnection] = {}
        self.data_channels: Dict[str, Any] = {}
        self.message_handlers: Set[Callable[[str, dict], Awaitable[None]]] = set()

        # Event handlers
        self.on_peer_connected = None
        self.on_peer_disconnected = None
        self.on_data_channel_message = None

        # WebSocket connection
        self.ws = None
        self._running = False

    async def connect(self) -> None:
        """Connect to the signaling server and start the peer connection manager."""
        import websockets

        self._running = True

        async def handle_signaling():
            async with websockets.connect(self.signaling_url) as ws:
                self.ws = ws
                logger.info(f"Connected to signaling server: {self.signaling_url}")

                # Handle incoming messages
                while self._running:
                    try:
                        message = await ws.recv()
                        await self._handle_signaling_message(message)
                    except websockets.exceptions.ConnectionClosed:
                        logger.warning("Signaling server connection closed")
                        break
                    except Exception as e:
                        logger.error(f"Error handling signaling message: {e}", exc_info=True)
                        await asyncio.sleep(1)  # Prevent tight loop on errors

        # Start the signaling connection in the background
        self._signaling_task = asyncio.create_task(handle_signaling())

    async def disconnect(self) -> None:
        """Disconnect from the signaling server and close all peer connections."""
        self._running = False

        # Close all peer connections
        for peer_id in list(self.peers.keys()):
            await self._close_peer_connection(peer_id)

        # Close WebSocket connection
        if self.ws:
            await self.ws.close()
            self.ws = None

        # Cancel the signaling task
        if hasattr(self, "_signaling_task"):
            self._signaling_task.cancel()
            try:
                await self._signaling_task
            except asyncio.CancelledError:
                pass

    async def _handle_signaling_message(self, message: str) -> None:
        """Handle incoming signaling messages."""
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "peers":
                # Connect to existing peers in the room
                for peer_id in data.get("peers", []):
                    if peer_id != self.peer_id and peer_id not in self.peers:
                        await self._create_peer_connection(peer_id)

            elif msg_type == "peer-joined":
                # A new peer joined the room
                peer_id = data.get("peer_id")
                if peer_id != self.peer_id and peer_id not in self.peers:
                    await self._create_peer_connection(peer_id)

            elif msg_type == "peer-left":
                # A peer left the room
                peer_id = data.get("peer_id")
                if peer_id in self.peers:
                    await self._close_peer_connection(peer_id)

            elif msg_type in ["offer", "answer", "candidate"]:
                # Handle WebRTC signaling
                sender_id = data.get("sender_id")
                if not sender_id or sender_id == self.peer_id:
                    return

                if sender_id not in self.peers:
                    await self._create_peer_connection(sender_id)

                pc = self.peers[sender_id]

                if msg_type == "offer":
                    # Create answer for the offer
                    offer = object_from_string(data["sdp"])
                    await pc.setRemoteDescription(offer)
                    answer = await pc.createAnswer()
                    await pc.setLocalDescription(answer)

                    # Send the answer back to the sender
                    await self._send_signaling_message(
                        sender_id, {"type": "answer", "sdp": object_to_string(pc.localDescription)}
                    )

                    # Create a data channel if we're the answerer
                    if not self.data_channels.get(sender_id):
                        await self._setup_data_channel(pc, sender_id)

                elif msg_type == "answer":
                    # Set the remote description
                    answer = object_from_string(data["sdp"])
                    await pc.setRemoteDescription(answer)

                elif msg_type == "candidate":
                    # Add ICE candidate
                    candidate = object_from_string(data["candidate"])
                    await pc.addIceCandidate(candidate)

        except Exception as e:
            logger.error(f"Error handling signaling message: {e}", exc_info=True)

    async def _create_peer_connection(self, peer_id: str) -> RTCPeerConnection:
        """Create a new RTCPeerConnection for a peer."""
        if peer_id in self.peers:
            return self.peers[peer_id]

        logger.info(f"Creating peer connection for {peer_id}")

        # Configure the peer connection
        config = {"iceServers": self.ice_servers}
        pc = RTCPeerConnection(config)
        self.peers[peer_id] = pc

        # Set up event handlers
        @pc.on("iceconnectionstatechange")
        async def on_iceconnectionstatechange():
            logger.debug(f"ICE connection state for {peer_id}: {pc.iceConnectionState}")
            if pc.iceConnectionState in ["failed", "disconnected", "closed"]:
                await self._close_peer_connection(peer_id)

        @pc.on("track")
        def on_track(track):
            logger.info(f"Received track {track.kind} from {peer_id}")
            # Handle incoming media tracks here

        # Create a data channel if we're the initiator
        if peer_id > self.peer_id:  # Simple way to decide who initiates
            dc = pc.createDataChannel("data")
            await self._setup_data_channel(dc, peer_id)

            # Create and send an offer
            offer = await pc.createOffer()
            await pc.setLocalDescription(offer)

            await self._send_signaling_message(
                peer_id, {"type": "offer", "sdp": object_to_string(pc.localDescription)}
            )

        return pc

    async def _setup_data_channel(self, dc_or_pc, peer_id: str) -> None:
        """Set up a data channel for a peer."""
        if isinstance(dc_or_pc, RTCPeerConnection):
            # This is the answerer, wait for the data channel to be created by the remote peer
            @dc_or_pc.on("datachannel")
            def on_datachannel(channel):
                self.data_channels[peer_id] = channel
                self._configure_data_channel(channel, peer_id)

        else:
            # This is the initiator, use the provided data channel
            channel = dc_or_pc
            self.data_channels[peer_id] = channel
            self._configure_data_channel(channel, peer_id)

    def _configure_data_channel(self, channel, peer_id: str) -> None:
        """Configure a data channel with event handlers."""

        @channel.on("open")
        def on_open():
            logger.info(f"Data channel with {peer_id} is open")
            if self.on_peer_connected:
                asyncio.create_task(self.on_peer_connected(peer_id))

        @channel.on("close")
        def on_close():
            logger.info(f"Data channel with {peer_id} is closed")
            if self.on_peer_disconnected:
                asyncio.create_task(self.on_peer_disconnected(peer_id))

            # Clean up
            if peer_id in self.data_channels:
                del self.data_channels[peer_id]

            # Close the peer connection if it's still active
            if peer_id in self.peers:
                asyncio.create_task(self._close_peer_connection(peer_id))

        @channel.on("message")
        def on_message(message):
            try:
                if isinstance(message, str):
                    data = json.loads(message)
                    if self.on_data_channel_message:
                        asyncio.create_task(self.on_data_channel_message(peer_id, data))

                    # Notify registered message handlers
                    for handler in self.message_handlers:
                        asyncio.create_task(handler(peer_id, data))
                else:
                    logger.warning(
                        f"Received binary message from {peer_id}, which is not supported"
                    )
            except json.JSONDecodeError:
                logger.error(f"Failed to parse message from {peer_id}: {message}")
            except Exception as e:
                logger.error(f"Error handling message from {peer_id}: {e}", exc_info=True)

    async def _close_peer_connection(self, peer_id: str) -> None:
        """Close a peer connection and clean up resources."""
        if peer_id in self.peers:
            logger.info(f"Closing peer connection to {peer_id}")
            pc = self.peers[peer_id]
            await pc.close()
            del self.peers[peer_id]

        if peer_id in self.data_channels:
            del self.data_channels[peer_id]

        if self.on_peer_disconnected:
            await self.on_peer_disconnected(peer_id)

    async def _send_signaling_message(self, target_peer_id: str, message: dict) -> None:
        """Send a signaling message through the WebSocket."""
        if not self.ws:
            logger.warning("Cannot send signaling message: WebSocket not connected")
            return

        try:
            message["target_peer_id"] = target_peer_id
            await self.ws.send(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send signaling message: {e}")

    async def send_message(self, peer_id: str, message: dict) -> bool:
        """Send a message to a specific peer through the data channel.

        Args:
            peer_id: ID of the target peer
            message: Message to send (must be JSON-serializable)

        Returns:
            bool: True if the message was sent successfully, False otherwise
        """
        if peer_id not in self.data_channels:
            logger.warning(f"No data channel available for peer {peer_id}")
            return False

        try:
            channel = self.data_channels[peer_id]
            if channel.readyState != "open":
                logger.warning(f"Data channel to {peer_id} is not open")
                return False

            await channel.send(json.dumps(message))
            return True
        except Exception as e:
            logger.error(f"Failed to send message to {peer_id}: {e}")
            return False

    async def broadcast(self, message: dict, exclude: Optional[set] = None) -> int:
        """Broadcast a message to all connected peers.

        Args:
            message: Message to broadcast (must be JSON-serializable)
            exclude: Set of peer IDs to exclude from the broadcast

        Returns:
            int: Number of peers the message was sent to
        """
        if exclude is None:
            exclude = set()

        sent_count = 0
        for peer_id in list(self.data_channels.keys()):
            if peer_id not in exclude:
                if await self.send_message(peer_id, message):
                    sent_count += 1

        return sent_count

    def add_message_handler(self, handler: Callable[[str, dict], Awaitable[None]]) -> None:
        """Add a message handler for incoming messages."""
        self.message_handlers.add(handler)

    def remove_message_handler(self, handler: Callable[[str, dict], Awaitable[None]]) -> None:
        """Remove a message handler."""
        self.message_handlers.discard(handler)
