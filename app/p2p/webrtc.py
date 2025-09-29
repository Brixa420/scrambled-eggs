"""
WebRTC manager for P2P voice/video communication.
"""

from dataclasses import dataclass
from typing import Callable, Dict, Optional

from ..extensions import socketio


@dataclass
class PeerConnection:
    """Represents a WebRTC peer connection."""

    peer_id: str
    connection: object = None
    data_channel: object = None
    on_message: Optional[Callable] = None
    on_disconnect: Optional[Callable] = None


class WebRTCManager:
    """Manages WebRTC peer connections."""

    def __init__(self, socketio):
        self.peers: Dict[str, PeerConnection] = {}
        self.socketio = socketio
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Set up WebSocket event handlers."""

        @self.socketio.on("rtc_offer")
        def handle_offer(data):
            """Handle incoming WebRTC offer."""
            from_id = data.get("from")
            to_id = data.get("to")
            offer = data.get("offer")

            if not all([from_id, to_id, offer]):
                return

            # Forward the offer to the target peer
            self.socketio.emit("rtc_offer", {"from": from_id, "offer": offer}, room=to_id)

        @self.socketio.on("rtc_answer")
        def handle_answer(data):
            """Handle WebRTC answer."""
            from_id = data.get("from")
            to_id = data.get("to")
            answer = data.get("answer")

            if not all([from_id, to_id, answer]):
                return

            # Forward the answer to the caller
            self.socketio.emit("rtc_answer", {"from": from_id, "answer": answer}, room=to_id)

        @self.socketio.on("ice_candidate")
        def handle_ice_candidate(data):
            """Handle ICE candidate exchange."""
            from_id = data.get("from")
            to_id = data.get("to")
            candidate = data.get("candidate")

            if not all([from_id, to_id, candidate]):
                return

            # Forward the ICE candidate
            self.socketio.emit(
                "ice_candidate", {"from": from_id, "candidate": candidate}, room=to_id
            )

    def create_peer_connection(self, peer_id: str) -> PeerConnection:
        """Create a new peer connection."""
        if peer_id in self.peers:
            return self.peers[peer_id]

        peer = PeerConnection(peer_id=peer_id)
        self.peers[peer_id] = peer
        return peer

    def get_peer(self, peer_id: str) -> Optional[PeerConnection]:
        """Get a peer connection by ID."""
        return self.peers.get(peer_id)

    def remove_peer(self, peer_id: str):
        """Remove a peer connection."""
        if peer_id in self.peers:
            peer = self.peers.pop(peer_id)
            if peer.on_disconnect:
                peer.on_disconnect(peer_id)

    def send_message(self, from_id: str, to_id: str, message: dict):
        """Send a message to a peer through the signaling server."""
        self.socketio.emit(
            "data_message", {"from": from_id, "to": to_id, "data": message}, room=to_id
        )


# Global WebRTC manager instance
webrtc_manager = WebRTCManager(socketio)
