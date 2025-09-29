"""
Secure P2P Communication Module

This module provides secure peer-to-peer communication using Scrambled Eggs encryption.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.security import SecurityManager
from app.services.scrambled_eggs_crypto import ScrambledEggsCrypto

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """Types of P2P messages."""

    HANDSHAKE = "handshake"
    DATA = "data"
    ACK = "ack"
    ERROR = "error"
    KEEPALIVE = "keepalive"


@dataclass
class PeerInfo:
    """Information about a peer in the P2P network."""

    peer_id: str
    public_key: bytes
    address: str
    port: int
    last_seen: float = field(default_factory=time.time)
    is_authenticated: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecureMessage:
    """A secure message for P2P communication."""

    message_id: str
    message_type: MessageType
    sender_id: str
    recipient_id: str
    payload: bytes
    timestamp: float = field(default_factory=time.time)
    nonce: Optional[bytes] = None
    signature: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            "message_id": self.message_id,
            "message_type": self.message_type.value,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "payload": self.payload.hex(),
            "timestamp": self.timestamp,
            "nonce": self.nonce.hex() if self.nonce else None,
            "signature": self.signature.hex() if self.signature else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecureMessage":
        """Create from a dictionary."""
        return cls(
            message_id=data["message_id"],
            message_type=MessageType(data["message_type"]),
            sender_id=data["sender_id"],
            recipient_id=data["recipient_id"],
            payload=bytes.fromhex(data["payload"]),
            timestamp=data["timestamp"],
            nonce=bytes.fromhex(data["nonce"]) if data.get("nonce") else None,
            signature=bytes.fromhex(data["signature"]) if data.get("signature") else None,
            metadata=data.get("metadata", {}),
        )


class SecureP2PManager:
    """Manages secure P2P communication using Scrambled Eggs encryption."""

    def __init__(
        self,
        node_id: str,
        host: str = "0.0.0.0",
        port: int = 0,  # 0 = auto-select port
        private_key: Optional[bytes] = None,
        security_manager: Optional[SecurityManager] = None,
        crypto_service: Optional[ScrambledEggsCrypto] = None,
    ):
        """
        Initialize the P2P manager.

        Args:
            node_id: Unique identifier for this node
            host: Host to bind to
            port: Port to bind to (0 = auto-select)
            private_key: Optional private key for this node (generated if None)
            security_manager: Optional security manager instance
            crypto_service: Optional crypto service instance
        """
        self.node_id = node_id
        self.host = host
        self.port = port
        self.running = False
        self.server = None
        self.connections = {}
        self.peers: Dict[str, PeerInfo] = {}
        self.message_handlers = {}
        self.security_manager = security_manager or SecurityManager()
        self.crypto = crypto_service or ScrambledEggsCrypto(self.security_manager)

        # Generate or load private key
        if private_key:
            self.private_key = x25519.X25519PrivateKey.from_private_bytes(private_key)
        else:
            self.private_key = x25519.X25519PrivateKey.generate()

        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

        # Register default message handlers
        self.register_message_handler(MessageType.HANDSHAKE, self._handle_handshake)
        self.register_message_handler(MessageType.ACK, self._handle_ack)
        self.register_message_handler(MessageType.KEEPALIVE, self._handle_keepalive)

    async def start(self) -> None:
        """Start the P2P server."""
        if self.running:
            logger.warning("P2P server already running")
            return

        self.server = await asyncio.start_server(
            self._handle_connection, host=self.host, port=self.port
        )

        # Get the actual port if it was auto-selected
        if self.port == 0:
            self.port = self.server.sockets[0].getsockname()[1]

        self.running = True
        logger.info(f"P2P server started on {self.host}:{self.port}")

        # Start background tasks
        asyncio.create_task(self._keepalive_task())
        asyncio.create_task(self._peer_discovery_task())

    async def stop(self) -> None:
        """Stop the P2P server."""
        if not self.running:
            return

        self.running = False

        # Close all connections
        for writer in list(self.connections.values()):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.error(f"Error closing connection: {e}")

        # Stop the server
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        logger.info("P2P server stopped")

    def register_message_handler(
        self,
        message_type: MessageType,
        handler: Callable[["SecureMessage", "asyncio.StreamWriter"], Awaitable[None]],
    ) -> None:
        """Register a handler for a specific message type."""
        self.message_handlers[message_type] = handler

    async def connect_to_peer(self, host: str, port: int) -> bool:
        """
        Connect to a remote peer.

        Args:
            host: Peer host
            port: Peer port

        Returns:
            bool: True if connection and handshake were successful
        """
        peer_addr = f"{host}:{port}"

        try:
            reader, writer = await asyncio.open_connection(host, port)
            self.connections[peer_addr] = writer

            # Perform handshake
            handshake_success = await self._perform_handshake(reader, writer)

            if handshake_success:
                # Start listening for messages from this peer
                asyncio.create_task(self._listen_for_messages(reader, writer, peer_addr))
                return True

            return False

        except Exception as e:
            logger.error(f"Failed to connect to {peer_addr}: {e}")
            if peer_addr in self.connections:
                del self.connections[peer_addr]
            return False

    async def send_message(
        self,
        recipient_id: str,
        message_type: MessageType,
        payload: bytes,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Send a secure message to a peer.

        Args:
            recipient_id: ID of the recipient peer
            message_type: Type of message
            payload: Message payload
            metadata: Optional metadata

        Returns:
            bool: True if the message was sent successfully
        """
        if recipient_id not in self.peers or not self.peers[recipient_id].is_authenticated:
            logger.error(f"Cannot send message to unauthenticated peer: {recipient_id}")
            return False

        # Create the message
        message = SecureMessage(
            message_id=str(uuid4()),
            message_type=message_type,
            sender_id=self.node_id,
            recipient_id=recipient_id,
            payload=payload,
            metadata=metadata or {},
        )

        # Find a connection to the peer
        peer_info = self.peers[recipient_id]
        peer_addr = f"{peer_info.address}:{peer_info.port}"

        if peer_addr not in self.connections:
            # Try to establish a new connection
            connected = await self.connect_to_peer(peer_info.address, peer_info.port)
            if not connected:
                logger.error(f"No active connection to peer {recipient_id}")
                return False

        writer = self.connections[peer_addr]

        try:
            # Encrypt the message
            encrypted_message = await self._encrypt_message(message, peer_info.public_key)

            # Send the message
            writer.write(encrypted_message)
            await writer.drain()

            logger.debug(f"Sent {message_type.value} message to {recipient_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send message to {recipient_id}: {e}")

            # Remove the connection if it's no longer valid
            if peer_addr in self.connections:
                del self.connections[peer_addr]

            return False

    async def broadcast(
        self, message_type: MessageType, payload: bytes, metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, bool]:
        """
        Broadcast a message to all connected and authenticated peers.

        Returns:
            Dict mapping peer IDs to success status
        """
        results = {}

        for peer_id in list(self.peers.keys()):
            if self.peers[peer_id].is_authenticated:
                success = await self.send_message(peer_id, message_type, payload, metadata)
                results[peer_id] = success

        return results

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new incoming connection."""
        peer_addr = writer.get_extra_info("peername")
        logger.debug(f"New connection from {peer_addr}")

        try:
            # Perform handshake
            handshake_success = await self._handle_incoming_handshake(reader, writer)

            if handshake_success:
                # Start listening for messages
                await self._listen_for_messages(reader, writer, f"{peer_addr[0]}:{peer_addr[1]}")

        except Exception as e:
            logger.error(f"Error handling connection from {peer_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

            # Clean up
            for peer_id, info in list(self.peers.items()):
                if info.address == peer_addr[0] and info.port == peer_addr[1]:
                    del self.peers[peer_id]
                    break

    async def _listen_for_messages(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_addr: str
    ) -> None:
        """Listen for incoming messages from a peer."""
        try:
            while self.running:
                # Read message length (4 bytes)
                data = await reader.readexactly(4)
                if not data:
                    break

                message_length = int.from_bytes(data, byteorder="big")

                # Read the message
                message_data = await reader.readexactly(message_length)

                # Process the message
                await self._process_message(message_data, writer)

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            logger.debug(f"Connection closed by peer: {peer_addr}")
        except Exception as e:
            logger.error(f"Error reading from {peer_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

            # Clean up
            if peer_addr in self.connections:
                del self.connections[peer_addr]

    async def _process_message(self, message_data: bytes, writer: asyncio.StreamWriter) -> None:
        """Process an incoming message."""
        try:
            # Decrypt the message
            message = await self._decrypt_message(message_data)

            if not message:
                logger.warning("Failed to decrypt message")
                return

            # Update peer's last seen time
            if message.sender_id in self.peers:
                self.peers[message.sender_id].last_seen = time.time()

            # Log the message
            logger.debug(f"Received {message.message_type.value} message from {message.sender_id}")

            # Call the appropriate handler
            handler = self.message_handlers.get(message.message_type)
            if handler:
                await handler(message, writer)
            else:
                logger.warning(f"No handler registered for message type: {message.message_type}")

                # Send error response
                error_msg = SecureMessage(
                    message_id=str(uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.node_id,
                    recipient_id=message.sender_id,
                    payload=f"No handler for message type: {message.message_type}".encode(),
                )

                if message.sender_id in self.peers:
                    peer_info = self.peers[message.sender_id]
                    peer_addr = f"{peer_info.address}:{peer_info.port}"
                    if peer_addr in self.connections:
                        encrypted_msg = await self._encrypt_message(error_msg, peer_info.public_key)
                        self.connections[peer_addr].write(encrypted_msg)
                        await self.connections[peer_addr].drain()

        except Exception as e:
            logger.error(f"Error processing message: {e}", exc_info=True)

    async def _perform_handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Perform the handshake protocol with a remote peer."""
        try:
            # Send our handshake message
            handshake_msg = {
                "node_id": self.node_id,
                "public_key": self.public_key_bytes.hex(),
                "timestamp": time.time(),
            }

            message = SecureMessage(
                message_id=str(uuid4()),
                message_type=MessageType.HANDSHAKE,
                sender_id=self.node_id,
                recipient_id="",  # Will be filled in by the receiver
                payload=json.dumps(handshake_msg).encode(),
            )

            # Send the handshake
            writer.write(message.to_json().encode())
            await writer.drain()

            # Wait for the response
            response_data = await reader.readexactly(4)  # Message length
            response_length = int.from_bytes(response_data, byteorder="big")
            response_msg = await reader.readexactly(response_length)

            # Parse the response
            response = json.loads(response_msg.decode())

            # Verify the handshake
            if response.get("message_type") != MessageType.HANDSHAKE.value:
                logger.error("Invalid handshake response")
                return False

            # Store peer information
            peer_info = json.loads(response["payload"])
            peer_id = peer_info["node_id"]
            public_key = bytes.fromhex(peer_info["public_key"])

            # Add or update the peer
            peer_addr = writer.get_extra_info("peername")
            self.peers[peer_id] = PeerInfo(
                peer_id=peer_id,
                public_key=public_key,
                address=peer_addr[0],
                port=peer_addr[1],
                is_authenticated=True,
            )

            logger.info(f"Successfully completed handshake with {peer_id}")
            return True

        except Exception as e:
            logger.error(f"Handshake failed: {e}")
            return False

    async def _handle_incoming_handshake(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Handle an incoming handshake request."""
        try:
            # Read the handshake message
            data = await reader.readexactly(4)  # Message length
            message_length = int.from_bytes(data, byteorder="big")
            message_data = await reader.readexactly(message_length)

            # Parse the message
            message = json.loads(message_data.decode())

            if message.get("message_type") != MessageType.HANDSHAKE.value:
                logger.error("Expected handshake message")
                return False

            # Parse peer information
            peer_info = json.loads(message["payload"])
            peer_id = peer_info["node_id"]
            public_key = bytes.fromhex(peer_info["public_key"])

            # Store peer information
            peer_addr = writer.get_extra_info("peername")
            self.peers[peer_id] = PeerInfo(
                peer_id=peer_id,
                public_key=public_key,
                address=peer_addr[0],
                port=peer_addr[1],
                is_authenticated=True,
            )

            # Send our handshake response
            handshake_msg = {
                "node_id": self.node_id,
                "public_key": self.public_key_bytes.hex(),
                "timestamp": time.time(),
            }

            response = SecureMessage(
                message_id=str(uuid4()),
                message_type=MessageType.HANDSHAKE,
                sender_id=self.node_id,
                recipient_id=peer_id,
                payload=json.dumps(handshake_msg).encode(),
            )

            # Send the response
            writer.write(response.to_json().encode())
            await writer.drain()

            logger.info(f"Completed handshake with {peer_id}")
            return True

        except Exception as e:
            logger.error(f"Error during handshake: {e}")
            return False

    async def _handle_handshake(self, message: SecureMessage, writer: asyncio.StreamWriter) -> None:
        """Handle a handshake message (already handled in _handle_incoming_handshake)."""

    async def _handle_ack(self, message: SecureMessage, writer: asyncio.StreamWriter) -> None:
        """Handle an acknowledgment message."""
        # Update message tracking, etc.
        logger.debug(f"Received ACK for message {message.metadata.get('in_reply_to')}")

    async def _handle_keepalive(self, message: SecureMessage, writer: asyncio.StreamWriter) -> None:
        """Handle a keepalive message."""
        # Just update the last seen time (already done in _process_message)

    async def _encrypt_message(self, message: SecureMessage, peer_public_key: bytes) -> bytes:
        """Encrypt a message for a specific peer."""
        try:
            # Serialize the message
            message_data = message.to_json().encode()

            # Generate a unique nonce for this message
            nonce = os.urandom(12)  # 96-bit nonce for AES-GCM

            # Derive a shared secret using ECDH
            shared_key = await self._derive_shared_secret(peer_public_key)

            # Encrypt the message
            cipher = AESGCM(shared_key)
            ciphertext = cipher.encrypt(nonce, message_data, None)

            # The ciphertext includes the authentication tag at the end
            encrypted_data = nonce + ciphertext

            # Prepend the length of the encrypted data (4 bytes)
            return len(encrypted_data).to_bytes(4, byteorder="big") + encrypted_data

        except Exception as e:
            logger.error(f"Failed to encrypt message: {e}")
            raise

    async def _decrypt_message(self, message_data: bytes) -> Optional[SecureMessage]:
        """Decrypt a message from a peer."""
        try:
            # Extract the nonce and ciphertext
            nonce = message_data[:12]  # 96-bit nonce
            ciphertext = message_data[12:]

            # For now, we'll just parse the message without decryption
            # In a real implementation, you would use the peer's public key to derive a shared secret
            # and decrypt the message
            try:
                message_dict = json.loads(ciphertext.decode())
                return SecureMessage.from_dict(message_dict)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error(f"Failed to parse message: {e}")
                return None

            # The following is a placeholder for the actual decryption logic:
            # 1. Determine which peer sent the message (e.g., from the connection)
            # 2. Get the peer's public key
            # 3. Derive the shared secret using ECDH
            # 4. Decrypt the message using AES-GCM
            # 5. Parse the decrypted JSON into a SecureMessage

        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return None

    async def _derive_shared_secret(self, peer_public_key: bytes) -> bytes:
        """Derive a shared secret using ECDH."""
        try:
            # Convert the peer's public key
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)

            # Perform the key exchange
            shared_key = self.private_key.exchange(peer_key)

            # Derive a secure key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"scrambled-eggs-p2p",
                backend=default_backend(),
            ).derive(shared_key)

            return derived_key

        except Exception as e:
            logger.error(f"Failed to derive shared secret: {e}")
            raise

    async def _keepalive_task(self) -> None:
        """Periodically send keepalive messages to connected peers."""
        while self.running:
            try:
                # Send keepalive to all connected peers
                for peer_id in list(self.peers.keys()):
                    if self.peers[peer_id].is_authenticated:
                        await self.send_message(
                            recipient_id=peer_id,
                            message_type=MessageType.KEEPALIVE,
                            payload=b"keepalive",
                        )

                # Sleep for 30 seconds
                await asyncio.sleep(30)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in keepalive task: {e}")
                await asyncio.sleep(5)  # Avoid tight loop on error

    async def _peer_discovery_task(self) -> None:
        """Periodically discover and connect to new peers."""
        while self.running:
            try:
                # In a real implementation, this would use a peer discovery protocol
                # like mDNS, a bootstrap server, or a DHT to find new peers

                # For now, just log that we're running
                logger.debug("Peer discovery task running")

                # Sleep for 60 seconds
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in peer discovery task: {e}")
                await asyncio.sleep(10)  # Avoid tight loop on error


# Helper function to create a new P2P node
def create_p2p_node(
    node_id: str, host: str = "0.0.0.0", port: int = 0, private_key: Optional[bytes] = None
) -> SecureP2PManager:
    """
    Create and initialize a new P2P node.

    Args:
        node_id: Unique identifier for this node
        host: Host to bind to
        port: Port to bind to (0 = auto-select)
        private_key: Optional private key (generated if None)

    Returns:
        Initialized SecureP2PManager instance
    """
    # In a real implementation, you might want to load/save the private key
    # from a secure storage location
    return SecureP2PManager(node_id=node_id, host=host, port=port, private_key=private_key)
