"""
WebRTC Manager
-------------
Handles WebRTC connections for P2P communication including voice and video.
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set


class ConnectionState(Enum):
    """Represents the state of a WebRTC connection."""

    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()
    FAILED = auto()


class ConnectionEvent(Enum):
    """Represents events that can occur on a WebRTC connection."""

    CONNECTION_CHANGE = auto()
    DATA_CHANNEL_OPEN = auto()
    DATA_CHANNEL_CLOSE = auto()
    DATA_CHANNEL_ERROR = auto()


import aiohttp
from aiortc import MediaStreamTrack, RTCIceCandidate, RTCPeerConnection, RTCSessionDescription
from aiortc.contrib.media import MediaBlackhole, MediaPlayer, MediaRecorder
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logger = logging.getLogger(__name__)


@dataclass
class Contact:
    """Represents a contact in the P2P network."""

    id: str
    name: str
    public_key: str
    last_seen: Optional[float] = None
    online: bool = False
    peer_connection: Optional[RTCPeerConnection] = None
    data_channel: Any = None


class WebRTCManager:
    """Manages WebRTC connections for P2P communication."""

    def __init__(self, config: dict):
        """
        Initialize the WebRTC manager.

        Args:
            config: Configuration dictionary with settings like STUN/TURN servers
        """
        self.config = config
        self.contacts: Dict[str, Contact] = {}
        self.message_handlers: List[Callable[[str, str, str], None]] = []
        self.call_handlers: List[Callable[[str, str, bool], None]] = []
        self.connection_handlers: List[Callable[[str, bool], None]] = []

        # WebRTC configuration
        self.ice_servers = [
            {"urls": ["stun:stun.l.google.com:19302"]},
            # Add TURN servers here if available
        ]

        # Generate a unique ID for this client
        self.client_id = str(uuid.uuid4())

        # Generate encryption keys
        self._generate_keys()

        # WebSocket connection for signaling
        self.ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self.signaling_url = config.get("signaling_url", "ws://localhost:8000/ws/")

        # Media settings
        self.audio_enabled = True
        self.video_enabled = True
        self.media_constraints = {
            "audio": {"echoCancellation": True, "noiseSuppression": True, "autoGainControl": True},
            "video": {
                "width": {"ideal": 1280},
                "height": {"ideal": 720},
                "frameRate": {"ideal": 30},
            },
        }

        # Active media streams
        self.local_stream = None
        self.remote_streams: Dict[str, Any] = {}

        # Keep track of pending offers/answers
        self.pending_offers: Dict[str, dict] = {}
        self.pending_answers: Dict[str, dict] = {}

    def _generate_keys(self):
        """Generate encryption keys for secure communication."""
        # Generate a symmetric key for message encryption
        self.symmetric_key = os.urandom(32)  # 256-bit key for AES

        # Generate an asymmetric key pair for key exchange
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,  # 3072-bit RSA key for better security
            backend=default_backend(),
        )

        # Get public key in PEM format
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Generate HMAC key for message authentication
        self.hmac_key = os.urandom(32)  # 256-bit HMAC key

        # Initialize message counter for replay attack protection
        self.message_counter = 0

    async def initialize(self):
        """Initialize the WebRTC manager and connect to the signaling server."""
        await self._connect_to_signaling_server()

    async def _connect_to_signaling_server(self):
        """Connect to the WebSocket signaling server."""
        try:
            session = aiohttp.ClientSession()
            self.ws = await session.ws_connect(f"{self.signaling_url}{self.client_id}")

            # Start listening for messages
            asyncio.create_task(self._listen_to_signaling_server())

            logger.info("Connected to signaling server")
        except Exception as e:
            logger.error(f"Failed to connect to signaling server: {e}")
            # Implement reconnection logic here

    async def _listen_to_signaling_server(self):
        """Listen for incoming messages from the signaling server."""
        try:
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._handle_signaling_message(json.loads(msg.data))
                elif msg.type == aiohttp.WSMsgType.CLOSED:
                    logger.warning("Signaling server connection closed")
                    break
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"Signaling server error: {self.ws.exception()}")
                    break
        except Exception as e:
            logger.error(f"Error in signaling server listener: {e}")
        finally:
            # Try to reconnect
            await asyncio.sleep(5)
            await self._connect_to_signaling_server()

    async def _handle_signaling_message(self, message: dict):
        """Handle a message from the signaling server."""
        msg_type = message.get("type")
        from_id = message.get("from")

        if msg_type == "offer":
            await self._handle_offer(from_id, message)
        elif msg_type == "answer":
            await self._handle_answer(from_id, message)
        elif msg_type == "ice-candidate":
            await self._handle_ice_candidate(from_id, message)
        elif msg_type == "message":
            await self._handle_encrypted_message(from_id, message)

    async def _handle_offer(self, from_id: str, offer: dict):
        """Handle an incoming WebRTC offer."""
        contact = self.contacts.get(from_id)
        if not contact:
            logger.warning(f"Received offer from unknown contact: {from_id}")
            return

        # Create a new peer connection if one doesn't exist
        if not contact.peer_connection:
            await self._create_peer_connection(contact)

        # Set the remote description
        await contact.peer_connection.setRemoteDescription(
            RTCSessionDescription(sdp=offer["sdp"], type=offer["type"])
        )

        # Create and send an answer
        answer = await contact.peer_connection.createAnswer()
        await contact.peer_connection.setLocalDescription(answer)

        await self._send_signaling_message(
            to=from_id, message_type="answer", sdp=answer.sdp, type=answer.type
        )

        # Notify UI about incoming call
        is_video = any(t.track.kind == "video" for t in contact.peer_connection.getReceivers())
        for handler in self.call_handlers:
            handler(from_id, "incoming", is_video)

    async def _handle_answer(self, from_id: str, answer: dict):
        """Handle an incoming WebRTC answer."""
        contact = self.contacts.get(from_id)
        if not contact or not contact.peer_connection:
            logger.warning(f"Received answer from unknown contact or no peer connection: {from_id}")
            return

        # Set the remote description
        await contact.peer_connection.setRemoteDescription(
            RTCSessionDescription(sdp=answer["sdp"], type=answer["type"])
        )

    async def _handle_ice_candidate(self, from_id: str, candidate: dict):
        """Handle an incoming ICE candidate."""
        contact = self.contacts.get(from_id)
        if not contact or not contact.peer_connection:
            logger.warning(
                f"Received ICE candidate from unknown contact or no peer connection: {from_id}"
            )
            return

        try:
            await contact.peer_connection.addIceCandidate(
                RTCIceCandidate(
                    candidate=candidate["candidate"],
                    sdpMid=candidate["sdpMid"],
                    sdpMLineIndex=candidate["sdpMLineIndex"],
                )
            )
        except Exception as e:
            logger.error(f"Failed to add ICE candidate: {e}")

    async def _handle_encrypted_message(self, from_id: str, message: dict):
        """Handle an incoming encrypted message."""
        # Decrypt the message
        try:
            decrypted = self._decrypt_message(message["content"])

            # Notify message handlers
            for handler in self.message_handlers:
                handler(from_id, decrypted, message.get("message_id"))
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")

    async def _create_peer_connection(self, contact: Contact) -> RTCPeerConnection:
        """Create a new WebRTC peer connection."""
        pc = RTCPeerConnection(iceServers=self.ice_servers)
        contact.peer_connection = pc

        # Set up data channel if it doesn't exist
        if not contact.data_channel:
            contact.data_channel = pc.createDataChannel("messaging")
            contact.data_channel.on(
                "message", lambda msg: self._on_data_channel_message(contact.id, msg)
            )

        # Set up event handlers
        @pc.on("icecandidate")
        async def on_ice_candidate(event):
            if event.candidate:
                await self._send_signaling_message(
                    to=contact.id,
                    message_type="ice-candidate",
                    candidate=event.candidate.candidate,
                    sdpMid=event.candidate.sdpMid,
                    sdpMLineIndex=event.candidate.sdpMLineIndex,
                )

        @pc.on("track")
        def on_track(track):
            logger.info(f"Received track: {track.kind}")
            if track.kind == "video":
                # Handle video track
                if contact.id not in self.remote_streams:
                    self.remote_streams[contact.id] = {}
                self.remote_streams[contact.id]["video"] = track
            elif track.kind == "audio":
                # Handle audio track
                if contact.id not in self.remote_streams:
                    self.remote_streams[contact.id] = {}
                self.remote_streams[contact.id]["audio"] = track

            # Notify UI about the new track
            for handler in self.call_handlers:
                handler(contact.id, "track", track.kind == "video")

        @pc.on("connectionstatechange")
        async def on_connection_state_change():
            logger.info(f"Connection state changed: {pc.connectionState}")
            if pc.connectionState == "connected":
                contact.online = True
                for handler in self.connection_handlers:
                    handler(contact.id, True)
            elif pc.connectionState in ["failed", "disconnected", "closed"]:
                contact.online = False
                if contact.id in self.remote_streams:
                    del self.remote_streams[contact.id]
                for handler in self.connection_handlers:
                    handler(contact.id, False)

        return pc

    def _on_data_channel_message(self, contact_id: str, message: str):
        """Handle incoming data channel messages."""
        try:
            data = json.loads(message)
            if data.get("type") == "message":
                decrypted = self._decrypt_message(data["content"])
                for handler in self.message_handlers:
                    handler(contact_id, decrypted, data.get("message_id"))
        except Exception as e:
            logger.error(f"Error handling data channel message: {e}")

    async def _send_signaling_message(self, to: str, message_type: str, **kwargs):
        """Send a message through the signaling server."""
        if not self.ws:
            logger.error("Not connected to signaling server")
            return

        try:
            message = {"to": to, "from": self.client_id, "type": message_type, **kwargs}
            await self.ws.send_str(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send signaling message: {e}")

    def _encrypt_message(self, message: str, recipient_public_key_pem: bytes = None) -> dict:
        """Encrypt a message using hybrid encryption (RSA + AES).

        Args:
            message: The message to encrypt
            recipient_public_key_pem: Recipient's public key in PEM format

        Returns:
            dict: Dictionary containing encrypted message components
        """
        try:
            # Generate a random session key for AES
            session_key = os.urandom(32)
            iv = os.urandom(16)  # Initialization vector

            # Encrypt the message with AES-256-CBC
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(message.encode()) + padder.finalize()

            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()

            # If recipient's public key is provided, encrypt the session key with it
            if recipient_public_key_pem:
                public_key = load_pem_public_key(
                    recipient_public_key_pem, backend=default_backend()
                )
                encrypted_key = public_key.encrypt(
                    session_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
            else:
                # If no recipient key, use our own public key (for local storage)
                encrypted_key = self.public_key.encrypt(
                    session_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

            # Create HMAC for message authentication
            h = hmac.HMAC(self.hmac_key, hashes.SHA256())
            h.update(ciphertext)
            signature = h.finalize()

            # Increment message counter
            self.message_counter += 1

            return {
                "ciphertext": ciphertext.hex(),
                "iv": iv.hex(),
                "encrypted_key": encrypted_key.hex(),
                "signature": signature.hex(),
                "counter": self.message_counter,
                "timestamp": int(time.time()),
            }

        except Exception as e:
            logger.error(f"Message encryption failed: {e}")
            raise

    def _decrypt_message(self, encrypted_data: dict, sender_public_key_pem: bytes = None) -> str:
        """Decrypt a message using hybrid decryption.

        Args:
            encrypted_data: Dictionary containing encrypted message components
            sender_public_key_pem: Sender's public key in PEM format for verification

        Returns:
            str: Decrypted message
        """
        try:
            # Convert hex strings back to bytes
            ciphertext = bytes.fromhex(encrypted_data["ciphertext"])
            iv = bytes.fromhex(encrypted_data["iv"])
            encrypted_key = bytes.fromhex(encrypted_data["encrypted_key"])
            signature = bytes.fromhex(encrypted_data["signature"])

            # Verify HMAC
            h = hmac.HMAC(self.hmac_key, hashes.SHA256())
            h.update(ciphertext)
            try:
                h.verify(signature)
            except InvalidSignature:
                logger.error("HMAC verification failed - message may have been tampered with")
                raise ValueError("Message authentication failed")

            # Decrypt the session key with our private key
            session_key = self.private_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Decrypt the message with AES-256-CBC
            cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Unpad the decrypted data
            unpadder = sym_padding.PKCS7(128).unpadder()
            message = unpadder.update(padded_data) + unpadder.finalize()

            # Check for replay attacks (simple counter-based)
            if "counter" in encrypted_data:
                if encrypted_data["counter"] <= self.message_counter:
                    logger.warning(
                        f"Possible replay attack detected: counter={encrypted_data['counter']}"
                    )
                self.message_counter = max(self.message_counter, encrypted_data["counter"])

            return message.decode()

        except Exception as e:
            logger.error(f"Message decryption failed: {e}")
            raise

    # Public API
    async def add_contact(
        self, contact_id: str, name: str, public_key_pem: str, verify: bool = True
    ) -> bool:
        """Add a new contact with optional key verification.

        Args:
            contact_id: Unique identifier for the contact
            name: Display name for the contact
            public_key_pem: Contact's public key in PEM format
            verify: Whether to verify the public key (recommended)

        Returns:
            bool: True if contact was added successfully, False otherwise
        """
        if contact_id in self.contacts:
            logger.warning(f"Contact {contact_id} already exists")
            return False

        try:
            # Verify the public key format
            if verify:
                try:
                    # This will raise an exception if the key is invalid
                    load_pem_public_key(public_key_pem.encode(), backend=default_backend())
                except Exception as e:
                    logger.error(f"Invalid public key for contact {contact_id}: {e}")
                    return False

            # Add the contact
            self.contacts[contact_id] = Contact(
                id=contact_id, name=name, public_key=public_key_pem, last_seen=time.time()
            )

            # Notify any listeners that contacts were updated
            for handler in self.connection_handlers:
                handler(contact_id, "contact_added", True)

            logger.info(f"Added contact: {name} ({contact_id})")
            return True

        except Exception as e:
            logger.error(f"Failed to add contact {contact_id}: {e}")
            return False

    async def remove_contact(self, contact_id: str) -> bool:
        """Remove a contact."""
        if contact_id not in self.contacts:
            return False

        # Close any active connection
        contact = self.contacts[contact_id]
        if contact.peer_connection:
            await contact.peer_connection.close()

        del self.contacts[contact_id]
        if contact_id in self.remote_streams:
            del self.remote_streams[contact_id]

        return True

    async def send_message(self, contact_id: str, message: str) -> Optional[str]:
        """Send an encrypted message to a contact.

        Args:
            contact_id: ID of the contact to send the message to
            message: The message to send

        Returns:
            Optional[str]: Message ID if sent successfully, None otherwise
        """
        if contact_id not in self.contacts:
            logger.error(f"Contact {contact_id} not found")
            return None

        contact = self.contacts[contact_id]
        message_id = str(uuid.uuid4())

        try:
            # Encrypt the message with the recipient's public key
            encrypted = self._encrypt_message(message, contact.public_key.encode())

            # Add metadata
            message_data = {
                "type": "message",
                "content": encrypted,
                "message_id": message_id,
                "sender_id": self.client_id,
                "timestamp": int(time.time()),
            }

            # Try to send through WebRTC data channel if available
            if contact.peer_connection and contact.peer_connection.connectionState == "connected":
                if contact.data_channel and contact.data_channel.readyState == "open":
                    try:
                        contact.data_channel.send(json.dumps(message_data))
                        logger.info(f"Message sent to {contact.name} via WebRTC")
                        return message_id
                    except Exception as e:
                        logger.error(f"Failed to send message through WebRTC: {e}")

            # Fall back to signaling server if WebRTC is not available
            logger.info(f"Falling back to signaling server for message to {contact.name}")
            await self._send_signaling_message(
                to=contact_id, message_type="message", **message_data
            )

            return message_id

        except Exception as e:
            logger.error(f"Failed to send message to {contact.name}: {e}")
            return None

        # Fall back to signaling server
        await self._send_signaling_message(
            to=contact_id, message_type="message", content=encrypted, message_id=message_id
        )

        return message_id

    async def start_call(self, contact_id: str, with_video: bool = True) -> bool:
        """Start a call with a contact."""
        if contact_id not in self.contacts:
            logger.error(f"Contact {contact_id} not found")
            return False

        contact = self.contacts[contact_id]

        # Create a new peer connection if one doesn't exist
        if not contact.peer_connection:
            await self._create_peer_connection(contact)

        # Get local media streams
        try:
            constraints = {}
            if self.audio_enabled:
                constraints["audio"] = self.media_constraints["audio"]
            if with_video and self.video_enabled:
                constraints["video"] = self.media_constraints["video"]

            self.local_stream = await self._get_user_media(constraints)

            # Add tracks to the connection
            for track in self.local_stream.getTracks():
                contact.peer_connection.addTrack(track)

            # Create and send an offer
            offer = await contact.peer_connection.createOffer()
            await contact.peer_connection.setLocalDescription(offer)

            await self._send_signaling_message(
                to=contact_id, message_type="offer", sdp=offer.sdp, type=offer.type
            )

            return True

        except Exception as e:
            logger.error(f"Failed to start call: {e}")
            return False

    async def end_call(self, contact_id: str):
        """End an ongoing call."""
        if contact_id not in self.contacts:
            return

        contact = self.contacts[contact_id]

        # Close the peer connection
        if contact.peer_connection:
            await contact.peer_connection.close()
            contact.peer_connection = None

        # Remove any remote streams
        if contact_id in self.remote_streams:
            del self.remote_streams[contact_id]

        # Stop local media tracks
        if self.local_stream:
            for track in self.local_stream.getTracks():
                track.stop()
            self.local_stream = None

    async def _get_user_media(self, constraints: dict):
        """Get user media with the given constraints."""
        # This is a simplified version - in a real app, you'd use aiortc's media APIs
        # or a higher-level abstraction to get access to the webcam/microphone
        raise NotImplementedError("Media capture not implemented in this example")

    def add_message_handler(self, handler: Callable[[str, str, Optional[str]], None]):
        """Add a handler for incoming messages."""
        self.message_handlers.append(handler)

    def add_call_handler(self, handler: Callable[[str, str, bool], None]):
        """Add a handler for call-related events."""
        self.call_handlers.append(handler)

    def add_connection_handler(self, handler: Callable[[str, bool], None]):
        """Add a handler for connection state changes."""
        self.connection_handlers.append(handler)

    async def close(self):
        """Clean up resources."""
        # Close all peer connections
        for contact in list(self.contacts.values()):
            if contact.peer_connection:
                await contact.peer_connection.close()

        # Close the WebSocket connection
        if self.ws:
            await self.ws.close()

        # Clear state
        self.contacts.clear()
        self.remote_streams.clear()
        self.message_handlers.clear()
        self.call_handlers.clear()
        self.connection_handlers.clear()

    def __del__(self):
        """Ensure resources are cleaned up."""
        if hasattr(self, "ws") and self.ws:
            asyncio.create_task(self.ws.close())

        for contact in list(self.contacts.values()):
            if contact.peer_connection:
                asyncio.create_task(contact.peer_connection.close())
