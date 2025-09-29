"""
P2P Service for handling peer-to-peer messaging with end-to-end encryption.
"""

import json
import logging
import time
from typing import Awaitable, Callable, Dict, List, Optional
from uuid import uuid4

from app.crypto.encryption_manager import EncryptionManager
from app.db.database import db_session
from app.models.message import Message, MessageStatus
from app.webrtc.webrtc_manager import WebRTCConfig, WebRTCManager

logger = logging.getLogger(__name__)


class P2PService:
    """
    Service for managing P2P connections, message encryption, and delivery status.
    """

    def __init__(self, user_id: str, device_id: str):
        """
        Initialize the P2P service.

        Args:
            user_id: The current user's ID
            device_id: The current device's ID
        """
        self.user_id = user_id
        self.device_id = device_id

        # Initialize WebRTC manager with configuration
        webrtc_config = WebRTCConfig(
            stun_servers=[{"urls": ["stun:stun.l.google.com:19302"]}],
            turn_servers=[],  # Add TURN servers if needed for NAT traversal
            ice_transport_policy="all",
        )
        self.webrtc = WebRTCManager(webrtc_config)

        # Initialize encryption
        self.encryption = EncryptionManager()

        # Store message callbacks
        self.message_callbacks: List[Callable[[Dict], Awaitable[None]]] = []

        # Track message status
        self.message_status: Dict[str, MessageStatus] = {}

        # Track typing indicators
        self.typing_status: Dict[str, float] = {}  # peer_id -> timestamp

        # Track read receipts
        self.read_receipts: Dict[str, Dict[str, float]] = {}  # message_id -> {peer_id -> timestamp}

        # Register WebRTC callbacks
        self.webrtc.on_message = self._handle_webrtc_message
        self.webrtc.on_connection_state_change = self._handle_connection_state_change

    async def initialize(self):
        """Initialize the P2P service and establish connections."""
        # Initialize WebRTC
        await self.webrtc.initialize()
        logger.info("P2P Service initialized")

    async def connect_to_peer(self, peer_id: str, offer: Optional[dict] = None) -> Optional[dict]:
        """
        Connect to a peer with the given ID.

        Args:
            peer_id: The ID of the peer to connect to
            offer: Optional WebRTC offer (for the answering peer)

        Returns:
            WebRTC answer if this is the answering peer, else None
        """
        # If we're the offerer, create a data channel
        if offer is None:
            await self.webrtc.create_data_channel(peer_id, f"chat-{peer_id}")
            answer = await self.webrtc.create_offer(peer_id)
            return answer
        else:
            # We're the answerer
            answer = await self.webrtc.handle_offer(peer_id, offer)
            return answer

    async def send_message(self, peer_id: str, content: str, message_type: str = "text") -> str:
        """
        Send an encrypted message to a peer.

        Args:
            peer_id: The ID of the recipient peer
            content: The message content
            message_type: The type of message (text, image, etc.)

        Returns:
            The message ID
        """
        message_id = str(uuid4())

        # Create message object
        message = {
            "type": "message",
            "id": message_id,
            "from": self.user_id,
            "to": peer_id,
            "content": content,
            "timestamp": time.time(),
            "message_type": message_type,
            "status": "sending",
        }

        # Encrypt the message content
        try:
            encrypted_message = self.encryption.encrypt_message(
                peer_id, json.dumps(message).encode()
            )

            # Send via WebRTC
            await self.webrtc.send_message(
                peer_id, {"type": "encrypted_message", "data": encrypted_message.decode("utf-8")}
            )

            # Update message status
            self.message_status[message_id] = MessageStatus.SENT

            # Save to database
            self._save_message_to_db(message_id, peer_id, content, message_type, MessageStatus.SENT)

            return message_id

        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            self.message_status[message_id] = MessageStatus.FAILED
            raise

    async def send_typing_indicator(self, peer_id: str, is_typing: bool):
        """Send a typing indicator to a peer."""
        try:
            await self.webrtc.send_message(
                peer_id,
                {
                    "type": "typing",
                    "from": self.user_id,
                    "is_typing": is_typing,
                    "timestamp": time.time(),
                },
            )
        except Exception as e:
            logger.error(f"Failed to send typing indicator: {e}")

    async def send_read_receipt(self, peer_id: str, message_id: str):
        """Send a read receipt for a message."""
        try:
            await self.webrtc.send_message(
                peer_id,
                {
                    "type": "read_receipt",
                    "message_id": message_id,
                    "from": self.user_id,
                    "timestamp": time.time(),
                },
            )

            # Update local read status
            if message_id not in self.read_receipts:
                self.read_receipts[message_id] = {}
            self.read_receipts[message_id][peer_id] = time.time()

        except Exception as e:
            logger.error(f"Failed to send read receipt: {e}")

    async def request_message_history(
        self, peer_id: str, before: Optional[float] = None, limit: int = 50
    ):
        """Request message history from a peer."""
        try:
            await self.webrtc.send_message(
                peer_id,
                {
                    "type": "history_request",
                    "before": before,
                    "limit": limit,
                    "request_id": str(uuid4()),
                },
            )
        except Exception as e:
            logger.error(f"Failed to request message history: {e}")

    async def _handle_webrtc_message(self, peer_id: str, message: dict):
        """Handle incoming WebRTC messages."""
        try:
            message_type = message.get("type")

            if message_type == "encrypted_message":
                await self._handle_encrypted_message(peer_id, message["data"])
            elif message_type == "typing":
                await self._handle_typing_indicator(peer_id, message)
            elif message_type == "read_receipt":
                await self._handle_read_receipt(peer_id, message)
            elif message_type == "history_request":
                await self._handle_history_request(peer_id, message)
            elif message_type == "history_response":
                await self._handle_history_response(peer_id, message)

        except Exception as e:
            logger.error(f"Error handling WebRTC message: {e}", exc_info=True)

    async def _handle_encrypted_message(self, peer_id: str, encrypted_data: str):
        """Handle an incoming encrypted message."""
        try:
            # Decrypt the message
            decrypted_data = self.encryption.decrypt_message(peer_id, encrypted_data.encode())
            message = json.loads(decrypted_data.decode())

            # Update message status to delivered
            if "id" in message:
                self.message_status[message["id"]] = MessageStatus.DELIVERED

            # Send read receipt
            if "id" in message and message.get("type") == "message":
                await self.send_read_receipt(peer_id, message["id"])

            # Call message callbacks
            for callback in self.message_callbacks:
                try:
                    await callback(message)
                except Exception as e:
                    logger.error(f"Error in message callback: {e}")

        except Exception as e:
            logger.error(f"Failed to handle encrypted message: {e}")

    async def _handle_typing_indicator(self, peer_id: str, data: dict):
        """Handle incoming typing indicator."""
        is_typing = data.get("is_typing", False)
        timestamp = data.get("timestamp", time.time())

        if is_typing:
            self.typing_status[peer_id] = timestamp
        elif peer_id in self.typing_status:
            del self.typing_status[peer_id]

    async def _handle_read_receipt(self, peer_id: str, data: dict):
        """Handle incoming read receipt."""
        message_id = data.get("message_id")
        timestamp = data.get("timestamp", time.time())

        if message_id:
            if message_id not in self.read_receipts:
                self.read_receipts[message_id] = {}
            self.read_receipts[message_id][peer_id] = timestamp

            # Update message status in the database
            self._update_message_status(message_id, MessageStatus.READ, peer_id)

    async def _handle_history_request(self, peer_id: str, data: dict):
        """Handle incoming history request."""
        before = data.get("before")
        limit = min(data.get("limit", 50), 100)  # Max 100 messages
        request_id = data.get("request_id")

        # Fetch messages from the database
        messages = self._get_messages_from_db(peer_id, before, limit)

        # Send history response
        try:
            await self.webrtc.send_message(
                peer_id,
                {"type": "history_response", "request_id": request_id, "messages": messages},
            )
        except Exception as e:
            logger.error(f"Failed to send history response: {e}")

    async def _handle_history_response(self, peer_id: str, data: dict):
        """Handle incoming history response."""
        request_id = data.get("request_id")
        messages = data.get("messages", [])

        # Process received messages
        for message in messages:
            # Call message callbacks for each message
            for callback in self.message_callbacks:
                try:
                    await callback(message)
                except Exception as e:
                    logger.error(f"Error in history message callback: {e}")

    def _save_message_to_db(
        self, message_id: str, peer_id: str, content: str, message_type: str, status: MessageStatus
    ):
        """Save a message to the database."""
        try:
            message = Message(
                id=message_id,
                conversation_id=peer_id,  # Using peer_id as conversation_id for 1:1 chats
                sender_id=self.user_id,
                recipient_id=peer_id,
                content=content,
                message_type=message_type,
                status=status.value,
                timestamp=time.time(),
            )

            db_session.add(message)
            db_session.commit()

        except Exception as e:
            logger.error(f"Failed to save message to database: {e}")
            db_session.rollback()

    def _update_message_status(
        self, message_id: str, status: MessageStatus, peer_id: Optional[str] = None
    ):
        """Update the status of a message in the database."""
        try:
            message = db_session.query(Message).filter_by(id=message_id).first()
            if message:
                message.status = status.value

                # If this is a read receipt, update the read_at timestamp
                if status == MessageStatus.READ and peer_id:
                    message.read_at = time.time()

                db_session.commit()
        except Exception as e:
            logger.error(f"Failed to update message status: {e}")
            db_session.rollback()

    def _get_messages_from_db(
        self, peer_id: str, before: Optional[float] = None, limit: int = 50
    ) -> List[dict]:
        """Retrieve messages from the database."""
        try:
            query = db_session.query(Message).filter(
                ((Message.sender_id == self.user_id) & (Message.recipient_id == peer_id))
                | ((Message.sender_id == peer_id) & (Message.recipient_id == self.user_id))
            )

            if before:
                query = query.filter(Message.timestamp < before)

            messages = query.order_by(Message.timestamp.desc()).limit(limit).all()

            # Convert to dictionary format
            return [
                {
                    "id": msg.id,
                    "from": msg.sender_id,
                    "to": msg.recipient_id,
                    "content": msg.content,
                    "message_type": msg.message_type,
                    "timestamp": msg.timestamp,
                    "status": msg.status,
                }
                for msg in messages
            ]

        except Exception as e:
            logger.error(f"Failed to retrieve messages from database: {e}")
            return []

    def register_message_callback(self, callback: Callable[[dict], Awaitable[None]]):
        """Register a callback for incoming messages."""
        self.message_callbacks.append(callback)

    def unregister_message_callback(self, callback: Callable[[dict], Awaitable[None]]):
        """Unregister a message callback."""
        if callback in self.message_callbacks:
            self.message_callbacks.remove(callback)

    async def close(self):
        """Clean up resources."""
        await self.webrtc.close()
        db_session.remove()
