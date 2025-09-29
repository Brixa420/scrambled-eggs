"""
P2P Messaging Demo for Scrambled Eggs

This script demonstrates the P2P messaging capabilities of Scrambled Eggs.
It creates two peers that can exchange encrypted messages.
"""

import asyncio
import json
import logging
import sys
from pathlib import Path

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from app.core.crypto import CryptoEngine
from app.network.p2p import ConnectionState, P2PManager

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class PeerNode:
    """Represents a peer node in the P2P network."""

    def __init__(self, peer_id: str):
        """Initialize the peer node."""
        self.peer_id = peer_id
        self.crypto = CryptoEngine()
        self.p2p_manager = None
        self.connected_peers = set()

    async def initialize(self):
        """Initialize the peer node."""
        logger.info(f"Initializing peer {self.peer_id}")

        # Initialize P2P manager
        self.p2p_manager = P2PManager(
            crypto_engine=self.crypto,
            on_message=self._on_message_received,
            on_peer_connected=self._on_peer_connected,
            on_peer_disconnected=self._on_peer_disconnected,
        )

        await self.p2p_manager.initialize()
        logger.info(f"Peer {self.peer_id} initialized")

    async def connect_to_peer(self, peer_id: str, offer_sdp: str) -> str:
        """Connect to another peer using a signaling offer."""
        if not self.p2p_manager:
            raise RuntimeError("P2P manager not initialized")

        logger.info(f"{self.peer_id}: Connecting to peer {peer_id}")
        try:
            answer_sdp = await self.p2p_manager.connect_to_peer(peer_id, offer_sdp)
            return answer_sdp
        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}")
            raise

    async def send_message(self, peer_id: str, message: str) -> bool:
        """Send a message to a connected peer."""
        if not self.p2p_manager:
            raise RuntimeError("P2P manager not initialized")

        logger.info(f"{self.peer_id}: Sending message to {peer_id}: {message}")
        return await self.p2p_manager.send_message(peer_id, message.encode())

    def _on_message_received(self, peer_id: str, message: bytes):
        """Handle incoming messages from peers."""
        try:
            message_text = message.decode()
            logger.info(f"{self.peer_id}: Received from {peer_id}: {message_text}")

            # In a real application, you would handle the message here
            # For the demo, we'll just print it
            print(f"\n[{peer_id}]: {message_text}")

        except Exception as e:
            logger.error(f"Error processing message from {peer_id}: {e}")

    def _on_peer_connected(self, peer_id: str):
        """Handle peer connection events."""
        logger.info(f"{self.peer_id}: Connected to peer {peer_id}")
        self.connected_peers.add(peer_id)
        print(f"\n[SYSTEM] Connected to {peer_id}")

    def _on_peer_disconnected(self, peer_id: str):
        """Handle peer disconnection events."""
        logger.info(f"{self.peer_id}: Disconnected from peer {peer_id}")
        if peer_id in self.connected_peers:
            self.connected_peers.remove(peer_id)
        print(f"\n[SYSTEM] Disconnected from {peer_id}")

    async def close(self):
        """Clean up resources."""
        if self.p2p_manager:
            await self.p2p_manager.close()


async def run_demo():
    """Run the P2P messaging demo."""
    print("=== Scrambled Eggs P2P Messaging Demo ===\n")

    # Create two peer nodes
    alice = PeerNode("Alice")
    bob = PeerNode("Bob")

    try:
        # Initialize both peers
        await asyncio.gather(alice.initialize(), bob.initialize())

        print("\nPeers initialized. Simulating connection...")

        # In a real application, you would exchange SDP offers/answers through a signaling server
        # For this demo, we'll simulate the connection process

        # Alice creates an offer
        dummy_offer = json.dumps(
            {"type": "offer", "sdp": "v=0\r\no=- 1234567890 2 IN IP4 127.0.0.1\r\ns=-\r\n..."}
        )

        # Bob receives the offer and creates an answer
        answer_sdp = await bob.connect_to_peer("Alice", dummy_offer)

        # Alice receives the answer (in a real app, this would be sent back through the signaling server)
        await alice.connect_to_peer("Bob", answer_sdp)

        # Give the connection a moment to establish
        await asyncio.sleep(1)

        # Start the chat interface
        print("\n=== Chat Started ===")
        print("Type a message and press Enter to send")
        print("Type 'exit' to quit\n")

        # Simple chat interface
        while True:
            message = input("You: ")

            if message.lower() == "exit":
                break

            # In a real app, you would select which peer to send to
            # For this demo, Alice sends to Bob and vice versa
            sender = alice if alice.peer_id == "Alice" else bob
            recipient = bob if sender == alice else alice

            await sender.send_message(recipient.peer_id, message)

    except KeyboardInterrupt:
        print("\nShutting down...")

    finally:
        # Clean up
        await asyncio.gather(alice.close(), bob.close())
        print("Demo completed.")


if __name__ == "__main__":
    asyncio.run(run_demo())
