"""
Chat Manager for handling P2P messaging with end-to-end encryption.
"""

import json
import logging
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional
from uuid import uuid4

from app.crypto.encryption_manager import EncryptionManager
from app.db.database import db_session
from app.models.message import Message, MessageStatus
from app.webrtc.webrtc_manager import WebRTCConfig, WebRTCManager

logger = logging.getLogger(__name__)


class ChatManager:
    """
    Manages P2P chat functionality including encryption, message history, and read receipts.
    """

    def __init__(self, user_id: str, device_id: str):
        """
        Initialize the Chat Manager.

        Args:
            user_id: The current user's ID
            device_id: The current device's ID
        """
        self.user_id = user_id
        self.device_id = device_id

        # Initialize WebRTC manager
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

        # Track active conversations
        self.active_conversations: Dict[str, Dict] = {}  # peer_id -> conversation_data

        # Set up WebRTC event handlers
        self._setup_webrtc_handlers()

    def _setup_webrtc_handlers(self):
        """Set up WebRTC event handlers."""
        self.webrtc.on_message = self._handle_webrtc_message
        self.webrtc.on_connection_state_change = self._handle_connection_state_change
        self.webrtc.on_ice_candidate = self._handle_ice_candidate
        self.webrtc.on_data_channel = self._handle_data_channel

    async def initialize(self):
        """Initialize the chat manager."""
        await self.webrtc.initialize()
        logger.info(f"Chat Manager initialized for user {self.user_id}")

    async def connect_to_peer(self, peer_id: str, offer: Optional[dict] = None) -> Optional[dict]:
        """
        Connect to a peer with the given ID.

        Args:
            peer_id: The ID of the peer to connect to
            offer: Optional WebRTC offer (for the answering peer)

        Returns:
            WebRTC answer if this is the answering peer, else None
        """
        try:
            if offer is None:
                # We're the offerer - create a data channel
                await self.webrtc.create_data_channel(peer_id, "chat")
                answer = await self.webrtc.create_offer(peer_id)

                # Store the conversation
                self.active_conversations[peer_id] = {
                    "status": "connecting",
                    "last_active": time.time(),
                    "channels": {"chat"},
                }

                return answer
            else:
                # We're the answerer - handle the offer
                answer = await self.webrtc.handle_offer(peer_id, offer)

                # Store the conversation
                self.active_conversations[peer_id] = {
                    "status": "connected",
                    "last_active": time.time(),
                    "channels": set(),
                }

                return answer

        except Exception as e:
            logger.error(f"Failed to connect to peer {peer_id}: {e}", exc_info=True)
            raise

    async def send_message(self, peer_id: str, content: str, message_type: str = "text") -> str:
        """
        Send a message to a peer.

        Args:
            peer_id: The ID of the recipient peer
            content: The message content
            message_type: The type of message (text, image, etc.)

        Returns:
            The message ID
        """
        message_id = str(uuid4())

        try:
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

            # Encrypt the message
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
            self._save_message_to_db(
                message_id=message_id,
                peer_id=peer_id,
                content=content,
                message_type=message_type,
                status=MessageStatus.SENT,
                is_outgoing=True,
            )

            return message_id

        except Exception as e:
            logger.error(f"Failed to send message: {e}", exc_info=True)
            self.message_status[message_id] = MessageStatus.FAILED
            raise

    async def send_typing_indicator(self, peer_id: str, is_typing: bool):
        """
        Send a typing indicator to a peer.

        Args:
            peer_id: The ID of the peer to notify
            is_typing: Whether the user is typing
        """
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

            # Update local typing status
            if is_typing:
                self.typing_status[peer_id] = time.time()
            elif peer_id in self.typing_status:
                del self.typing_status[peer_id]

        except Exception as e:
            logger.error(f"Failed to send typing indicator: {e}", exc_info=True)

    async def send_read_receipt(self, peer_id: str, message_id: str):
        """
        Send a read receipt for a message.

        Args:
            peer_id: The ID of the peer who sent the message
            message_id: The ID of the message being acknowledged
        """
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

            # Update message status in database
            self._update_message_status(message_id, MessageStatus.READ, peer_id)

        except Exception as e:
            logger.error(f"Failed to send read receipt: {e}", exc_info=True)

    async def request_message_history(
        self, peer_id: str, before: Optional[float] = None, limit: int = 50
    ):
        """
        Request message history from a peer.

        Args:
            peer_id: The ID of the peer to request history from
            before: Optional timestamp to get messages before
            limit: Maximum number of messages to request
        """
        try:
            request_id = str(uuid4())

            await self.webrtc.send_message(
                peer_id,
                {
                    "type": "history_request",
                    "request_id": request_id,
                    "before": before,
                    "limit": limit,
                },
            )

            logger.info(f"Requested message history from {peer_id} (request_id: {request_id})")

        except Exception as e:
            logger.error(f"Failed to request message history: {e}", exc_info=True)

    async def _handle_webrtc_message(self, peer_id: str, message: dict):
        """
        Handle incoming WebRTC messages.

        Args:
            peer_id: The ID of the peer who sent the message
            message: The message data
        """
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

            # Send read receipt for non-system messages
            if message.get("type") == "message":
                await self.send_read_receipt(peer_id, message["id"])

                # Save to database
                self._save_message_to_db(
                    message_id=message["id"],
                    peer_id=peer_id,
                    content=message["content"],
                    message_type=message.get("message_type", "text"),
                    status=MessageStatus.DELIVERED,
                    is_outgoing=False,
                    timestamp=message.get("timestamp"),
                )

            # Call message callbacks
            for callback in self.message_callbacks:
                try:
                    await callback(message)
                except Exception as e:
                    logger.error(f"Error in message callback: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Failed to handle encrypted message: {e}", exc_info=True)

    async def _handle_typing_indicator(self, peer_id: str, data: dict):
        """Handle incoming typing indicator."""
        is_typing = data.get("is_typing", False)
        timestamp = data.get("timestamp", time.time())

        if is_typing:
            self.typing_status[peer_id] = timestamp
        elif peer_id in self.typing_status:
            del self.typing_status[peer_id]

        # Notify UI of typing status change
        await self._notify_typing_status(peer_id, is_typing)

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
        try:
            before = data.get("before")
            limit = min(data.get("limit", 50), 100)  # Max 100 messages
            request_id = data.get("request_id")

            # Fetch messages from the database
            messages = self._get_messages_from_db(peer_id, before, limit)

            # Send history response
            await self.webrtc.send_message(
                peer_id,
                {"type": "history_response", "request_id": request_id, "messages": messages},
            )

            logger.info(f"Sent {len(messages)} messages to {peer_id} (request_id: {request_id})")

        except Exception as e:
            logger.error(f"Error handling history request: {e}", exc_info=True)

    async def _handle_history_response(self, peer_id: str, data: dict):
        """Handle incoming history response."""
        try:
            request_id = data.get("request_id")
            messages = data.get("messages", [])

            logger.info(f"Received {len(messages)} messages in history response {request_id}")

            # Process received messages
            for message in messages:
                # Call message callbacks for each message
                for callback in self.message_callbacks:
                    try:
                        await callback(message)
                    except Exception as e:
                        logger.error(f"Error in history message callback: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Error handling history response: {e}", exc_info=True)

    def _save_message_to_db(
        self,
        message_id: str,
        peer_id: str,
        content: str,
        message_type: str,
        status: MessageStatus,
        is_outgoing: bool,
        timestamp: Optional[float] = None,
    ):
        """Save a message to the database."""
        try:
            message = Message(
                id=message_id,
                conversation_id=peer_id,  # Using peer_id as conversation_id for 1:1 chats
                sender_id=self.user_id if is_outgoing else peer_id,
                recipient_id=peer_id if is_outgoing else self.user_id,
                content=content,
                message_type=message_type,
                status=status.value,
                timestamp=timestamp or time.time(),
                is_outgoing=is_outgoing,
            )

            db_session.add(message)
            db_session.commit()

        except Exception as e:
            logger.error(f"Failed to save message to database: {e}", exc_info=True)
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
            logger.error(f"Failed to update message status: {e}", exc_info=True)
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
                    "is_outgoing": msg.is_outgoing,
                }
                for msg in messages
            ]

        except Exception as e:
            logger.error(f"Failed to retrieve messages from database: {e}", exc_info=True)
            return []

    async def _notify_typing_status(self, peer_id: str, is_typing: bool):
        """Notify registered callbacks of typing status changes."""
        typing_event = {
            "type": "typing_status",
            "peer_id": peer_id,
            "is_typing": is_typing,
            "timestamp": time.time(),
        }

        for callback in self.message_callbacks:
            try:
                await callback(typing_event)
            except Exception as e:
                logger.error(f"Error in typing status callback: {e}", exc_info=True)

    async def _handle_connection_state_change(self, peer_id: str, state: str):
        """Handle WebRTC connection state changes."""
        logger.info(f"Connection state for {peer_id} changed to {state}")

        # Update conversation status
        if peer_id in self.active_conversations:
            self.active_conversations[peer_id]["status"] = state
            self.active_conversations[peer_id]["last_active"] = time.time()

        # Notify UI of connection state change
        state_event = {
            "type": "connection_state",
            "peer_id": peer_id,
            "state": state,
            "timestamp": time.time(),
        }

        for callback in self.message_callbacks:
            try:
                await callback(state_event)
            except Exception as e:
                logger.error(f"Error in connection state callback: {e}", exc_info=True)

    async def _handle_ice_candidate(self, peer_id: str, candidate: dict):
        """Handle new ICE candidates."""
        logger.debug(f"New ICE candidate for {peer_id}: {candidate}")

        # Forward to signaling server or handle as needed
        candidate_event = {
            "type": "ice_candidate",
            "peer_id": peer_id,
            "candidate": candidate,
            "timestamp": time.time(),
        }

        for callback in self.message_callbacks:
            try:
                await callback(candidate_event)
            except Exception as e:
                logger.error(f"Error in ICE candidate callback: {e}", exc_info=True)

    async def _handle_data_channel(self, peer_id: str, channel: Any):
        """Handle new data channels."""
        channel_label = getattr(channel, "label", "unknown")
        logger.info(f"New data channel from {peer_id}: {channel_label}")

        # Update conversation channels
        if peer_id in self.active_conversations:
            self.active_conversations[peer_id]["channels"].add(channel_label)

        # Notify UI of new data channel
        channel_event = {
            "type": "data_channel",
            "peer_id": peer_id,
            "channel_label": channel_label,
            "timestamp": time.time(),
        }

        for callback in self.message_callbacks:
            try:
                await callback(channel_event)
            except Exception as e:
                logger.error(f"Error in data channel callback: {e}", exc_info=True)

    def register_message_callback(self, callback: Callable[[dict], Awaitable[None]]):
        """
        Register a callback for incoming messages and events.

        Args:
            callback: An async function that takes a message dictionary
        """
        if callback not in self.message_callbacks:
            self.message_callbacks.append(callback)

    def unregister_message_callback(self, callback: Callable[[dict], Awaitable[None]]):
        """Unregister a message callback."""
        if callback in self.message_callbacks:
            self.message_callbacks.remove(callback)

    async def close(self):
        """Clean up resources."""
        try:
            # Close all WebRTC connections
            await self.webrtc.close()

            # Clear all data structures
            self.message_callbacks.clear()
            self.message_status.clear()
            self.typing_status.clear()
            self.read_receipts.clear()
            self.active_conversations.clear()

            logger.info("Chat Manager shut down successfully")

        except Exception as e:
            logger.error(f"Error during shutdown: {e}", exc_info=True)
            raise
