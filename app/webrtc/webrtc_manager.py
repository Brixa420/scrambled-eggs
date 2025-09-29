"""
Enhanced WebRTC manager for handling peer connections, media streaming, and P2P messaging.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from aiortc import RTCDataChannel, RTCIceCandidate, RTCPeerConnection, RTCSessionDescription
from aiortc.mediastreams import MediaStreamTrack

# Type aliases
IceCandidateDict = Dict[str, Any]
SDPType = str
MessageCallback = Callable[[str, Dict[str, Any]], Awaitable[None]]
ConnectionStateCallback = Callable[[str, str], None]
IceCandidateCallback = Callable[[str, Dict[str, Any]], None]


class ConnectionState(Enum):
    """WebRTC connection states."""

    NEW = "new"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    FAILED = "failed"
    CLOSED = "closed"


logger = logging.getLogger(__name__)

# Type aliases
IceCandidateDict = Dict[str, Any]
SDPType = str


@dataclass
class WebRTCConfig:
    """Configuration for WebRTC manager."""

    stun_servers: List[Dict[str, str]] = field(
        default_factory=lambda: [
            {"urls": ["stun:stun.l.google.com:19302"]},
            {"urls": ["stun:stun1.l.google.com:19302"]},
        ]
    )
    turn_servers: List[Dict[str, Any]] = field(default_factory=list)
    ice_transport_policy: str = "all"
    bundle_policy: str = "balanced"
    rtcp_mux_policy: str = "require"


class WebRTCManager:
    """
    Enhanced WebRTC manager that handles peer connections, data channels, and P2P messaging.
    """

    def __init__(self, config: Optional[WebRTCConfig] = None):
        """
        Initialize the WebRTC manager with configuration.

        Args:
            config: Optional WebRTC configuration
        """
        self.config = config or WebRTCConfig()
        self.peer_connections: Dict[str, RTCPeerConnection] = {}
        self.data_channels: Dict[str, Dict[str, RTCDataChannel]] = (
            {}
        )  # peer_id -> {label -> channel}
        self.media_tracks: Dict[str, List[MediaStreamTrack]] = {}
        self.on_message_callbacks: List[MessageCallback] = []
        self.on_connection_state_change: Optional[ConnectionStateCallback] = None
        self.on_ice_candidate: Optional[IceCandidateCallback] = None
        self.on_data_channel: Optional[Callable[[str, RTCDataChannel], None]] = None
        self._connection_states: Dict[str, ConnectionState] = {}
        self._logger = logging.getLogger(__name__)

    async def create_peer_connection(self, peer_id: str) -> RTCPeerConnection:
        """Create a new peer connection."""
        if peer_id in self.peer_connections:
            return self.peer_connections[peer_id]

        # Configure ICE servers
        ice_servers = self.config.stun_servers + self.config.turn_servers

        # Create peer connection
        pc = RTCPeerConnection(
            iceServers=ice_servers,
            iceTransportPolicy=self.config.ice_transport_policy,
            bundlePolicy=self.config.bundle_policy,
            rtcpMuxPolicy=self.config.rtcp_mux_policy,
        )

        # Set up event handlers
        @pc.on("connectionstatechange")
        async def on_connectionstatechange():
            logger.info(f"Connection state for {peer_id}: {pc.connectionState}")
            if self.on_connection_state_change:
                self.on_connection_state_change(peer_id, pc.connectionState)

            if pc.connectionState == "failed":
                await self.close_peer_connection(peer_id)

        @pc.on("iceconnectionstatechange")
        async def on_iceconnectionstatechange():
            logger.info(f"ICE connection state for {peer_id}: {pc.iceConnectionState}")

            if pc.iceConnectionState == "failed":
                await self.close_peer_connection(peer_id)

        @pc.on("icecandidate")
        async def on_icecandidate(event):
            if event.candidate and self.on_ice_candidate:
                candidate_dict = {
                    "candidate": event.candidate.candidate,
                    "sdpMid": event.candidate.sdpMid,
                    "sdpMLineIndex": event.candidate.sdpMLineIndex,
                }
                self.on_ice_candidate(peer_id, candidate_dict)

        @pc.on("datachannel")
        def on_datachannel(channel: RTCDataChannel):
            logger.info(f"Data channel opened with {peer_id}: {channel.label}")
            self._setup_data_channel(peer_id, channel)

        # Store the peer connection
        self.peer_connections[peer_id] = pc
        return pc

    def _setup_data_channel(self, peer_id: str, channel: RTCDataChannel):
        """Set up a data channel with event handlers."""
        self.data_channels[peer_id] = channel

        @channel.on("message")
        async def on_message(message):
            try:
                if isinstance(message, str):
                    data = json.loads(message)
                    await self._handle_message(peer_id, data)
            except Exception as e:
                logger.error(f"Error handling message from {peer_id}: {e}")

        @channel.on("close")
        def on_close():
            logger.info(f"Data channel closed for {peer_id}")
            if peer_id in self.data_channels:
                del self.data_channels[peer_id]

        @channel.on("error")
        def on_error(error):
            logger.error(f"Data channel error for {peer_id}: {error}")

    async def _handle_message(self, peer_id: str, data: dict):
        """Handle incoming WebRTC data channel messages."""
        logger.debug(f"Received message from {peer_id}: {data}")

        # Call all registered message callbacks
        for callback in self.on_message_callbacks:
            try:
                await callback(peer_id, data)
            except Exception as e:
                logger.error(f"Error in message callback: {e}")

    async def create_data_channel(
        self, peer_id: str, label: str = "chat"
    ) -> Optional[RTCDataChannel]:
        """Create a data channel with the specified peer."""
        if peer_id not in self.peer_connections:
            logger.error(f"No peer connection found for {peer_id}")
            return None

        pc = self.peer_connections[peer_id]
        channel = pc.createDataChannel(label)
        self._setup_data_channel(peer_id, channel)
        return channel

    async def send_message(self, peer_id: str, message: dict) -> bool:
        """Send a message to the specified peer."""
        if peer_id not in self.data_channels:
            logger.error(f"No data channel found for {peer_id}")
            return False

        try:
            channel = self.data_channels[peer_id]
            if channel.readyState != "open":
                logger.warning(f"Data channel for {peer_id} is not open")
                return False

            channel.send(json.dumps(message))
            return True
        except Exception as e:
            logger.error(f"Error sending message to {peer_id}: {e}")
            return False

    async def create_offer(self, peer_id: str) -> Optional[dict]:
        """Create an SDP offer for the specified peer."""
        if peer_id not in self.peer_connections:
            logger.error(f"No peer connection found for {peer_id}")
            return None

        pc = self.peer_connections[peer_id]

        try:
            # Create a data channel if none exists
            if peer_id not in self.data_channels:
                await self.create_data_channel(peer_id)

            # Create offer
            offer = await pc.createOffer()
            await pc.setLocalDescription(offer)

            # Wait for ICE gathering to complete
            await self._wait_for_ice_gathering(pc)

            return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
        except Exception as e:
            logger.error(f"Error creating offer for {peer_id}: {e}")
            return None

    async def create_answer(self, peer_id: str, offer: dict) -> Optional[dict]:
        """Create an SDP answer for the specified offer."""
        if peer_id not in self.peer_connections:
            logger.error(f"No peer connection found for {peer_id}")
            return None

        pc = self.peer_connections[peer_id]

        try:
            # Set remote description
            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=offer["sdp"], type=offer["type"])
            )

            # Create answer
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)

            # Wait for ICE gathering to complete
            await self._wait_for_ice_gathering(pc)

            return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
        except Exception as e:
            logger.error(f"Error creating answer for {peer_id}: {e}")
            return None

    async def set_remote_description(self, peer_id: str, sdp: dict) -> bool:
        """Set the remote description for a peer connection."""
        if peer_id not in self.peer_connections:
            logger.error(f"No peer connection found for {peer_id}")
            return False

        pc = self.peer_connections[peer_id]

        try:
            await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp["sdp"], type=sdp["type"]))
            return True
        except Exception as e:
            logger.error(f"Error setting remote description for {peer_id}: {e}")
            return False

    async def add_ice_candidate(self, peer_id: str, candidate_dict: dict) -> bool:
        """Add an ICE candidate to a peer connection."""
        if peer_id not in self.peer_connections:
            logger.error(f"No peer connection found for {peer_id}")
            return False

        pc = self.peer_connections[peer_id]

        try:
            candidate = RTCIceCandidate(
                candidate_dict["candidate"],
                candidate_dict.get("sdpMid"),
                candidate_dict.get("sdpMLineIndex"),
            )
            await pc.addIceCandidate(candidate)
            return True
        except Exception as e:
            logger.error(f"Error adding ICE candidate for {peer_id}: {e}")
            return False

    async def add_media_track(self, peer_id: str, track: MediaStreamTrack) -> bool:
        """Add a media track to a peer connection."""
        if peer_id not in self.peer_connections:
            logger.error(f"No peer connection found for {peer_id}")
            return False

        pc = self.peer_connections[peer_id]

        try:
            sender = pc.addTrack(track)
            if peer_id not in self.media_tracks:
                self.media_tracks[peer_id] = []
            self.media_tracks[peer_id].append(track)

            # If this is the first track, create an offer
            if len(self.media_tracks[peer_id]) == 1:
                offer = await pc.createOffer()
                await pc.setLocalDescription(offer)

                return {"sdp": pc.localDescription.sdp, "type": pc.localDescription.type}
            return True
        except Exception as e:
            logger.error(f"Error adding media track for {peer_id}: {e}")
            return False

    async def close_peer_connection(self, peer_id: str) -> bool:
        """Close a peer connection and clean up resources."""
        if peer_id not in self.peer_connections:
            return False

        pc = self.peer_connections[peer_id]

        try:
            # Close data channels
            if peer_id in self.data_channels:
                self.data_channels[peer_id].close()
                del self.data_channels[peer_id]

            # Close peer connection
            await pc.close()

            # Clean up media tracks
            if peer_id in self.media_tracks:
                for track in self.media_tracks[peer_id]:
                    if hasattr(track, "stop"):
                        track.stop()
                del self.media_tracks[peer_id]

            # Remove from peer connections
            del self.peer_connections[peer_id]

            return True
        except Exception as e:
            logger.error(f"Error closing peer connection for {peer_id}: {e}")
            return False

    async def _wait_for_ice_gathering(self, pc: RTCPeerConnection, timeout: float = 5.0) -> bool:
        """Wait for ICE gathering to complete."""
        if pc.iceGatheringState == "complete":
            return True

        # Set up event
        event = asyncio.Event()

        def on_icegatheringstatechange():
            if pc.iceGatheringState == "complete":
                event.set()

        pc.on("icegatheringstatechange", on_icegatheringstatechange)

        # Check if already complete
        if pc.iceGatheringState == "complete":
            pc.on("icegatheringstatechange", None)
            return True

        # Wait for event or timeout
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning("ICE gathering timed out")
            return False
        finally:
            pc.on("icegatheringstatechange", None)

    def register_message_callback(self, callback: Callable[[str, dict], Awaitable[None]]) -> None:
        """Register a callback for incoming messages."""
        if callback not in self.on_message_callbacks:
            self.on_message_callbacks.append(callback)

    def unregister_message_callback(self, callback: Callable[[str, dict], Awaitable[None]]) -> None:
        """Unregister a message callback."""
        if callback in self.on_message_callbacks:
            self.on_message_callbacks.remove(callback)
