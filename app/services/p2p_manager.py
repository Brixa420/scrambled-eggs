"""
P2P Connection Manager for handling direct peer-to-peer connections between users.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, Set

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


class P2PConnectionManager:
    """Manages P2P connections and message routing between users."""

    def __init__(self):
        self.active_connections: Dict[str, Set[Any]] = {}
        self.encryption_keys: Dict[str, bytes] = {}
        self.message_history: Dict[str, list] = {}
        self.typing_users: Dict[str, Set[str]] = {}  # room_id: set of user_ids
        self.read_receipts: Dict[str, Dict[str, datetime]] = (
            {}
        )  # message_id: {user_id: read_timestamp}

    async def connect(self, user_id: str, websocket: Any, room_id: str):
        """Register a new WebSocket connection."""
        if room_id not in self.active_connections:
            self.active_connections[room_id] = set()
            self.typing_users[room_id] = set()
            self.message_history[room_id] = []

        self.active_connections[room_id].add(websocket)

        # Generate or retrieve encryption key for this room
        if room_id not in self.encryption_keys:
            self.encryption_keys[room_id] = Fernet.generate_key()

        logger.info(f"User {user_id} connected to room {room_id}")

    async def disconnect(self, user_id: str, websocket: Any, room_id: str):
        """Remove a WebSocket connection."""
        if room_id in self.active_connections:
            self.active_connections[room_id].discard(websocket)
            if user_id in self.typing_users.get(room_id, set()):
                self.typing_users[room_id].remove(user_id)
                await self._broadcast_typing_status(room_id)

            if not self.active_connections[room_id]:
                del self.active_connections[room_id]
                del self.typing_users[room_id]
                del self.encryption_keys[room_id]

    async def _encrypt_message(self, room_id: str, message: str) -> bytes:
        """Encrypt a message using the room's encryption key."""
        fernet = Fernet(self.encryption_keys[room_id])
        return fernet.encrypt(message.encode())

    async def _decrypt_message(self, room_id: str, encrypted_message: bytes) -> str:
        """Decrypt a message using the room's encryption key."""
        fernet = Fernet(self.encryption_keys[room_id])
        return fernet.decrypt(encrypted_message).decode()

    async def send_message(self, sender_id: str, room_id: str, message: str):
        """Send an encrypted message to all connections in the room."""
        if room_id not in self.active_connections:
            return

        # Create message with metadata
        message_data = {
            "type": "message",
            "sender_id": sender_id,
            "content": message,
            "timestamp": datetime.utcnow().isoformat(),
            "message_id": f"msg_{len(self.message_history.get(room_id, [])) + 1}",
        }

        # Add to message history
        self.message_history.setdefault(room_id, []).append(message_data)

        # Encrypt the message content
        encrypted_content = await self._encrypt_message(room_id, json.dumps(message_data))

        # Send to all connections in the room
        for connection in self.active_connections[room_id]:
            try:
                await connection.send_bytes(encrypted_content)
            except Exception as e:
                logger.error(f"Error sending message: {e}")
                await self.disconnect(sender_id, connection, room_id)

    async def get_message_history(self, room_id: str, limit: int = 50) -> list:
        """Retrieve message history for a room."""
        messages = self.message_history.get(room_id, [])
        return messages[-limit:]

    async def set_typing_status(self, user_id: str, room_id: str, is_typing: bool):
        """Update user's typing status in a room."""
        if is_typing:
            self.typing_users[room_id].add(user_id)
        else:
            self.typing_users[room_id].discard(user_id)

        await self._broadcast_typing_status(room_id)

    async def _broadcast_typing_status(self, room_id: str):
        """Broadcast the current typing status to all users in the room."""
        typing_users = list(self.typing_users.get(room_id, set()))
        status_message = {"type": "typing_status", "typing_users": typing_users}

        for connection in self.active_connections.get(room_id, set()):
            try:
                await connection.send_json(status_message)
            except Exception as e:
                logger.error(f"Error sending typing status: {e}")

    async def mark_as_read(self, user_id: str, message_id: str):
        """Mark a message as read by a user."""
        if message_id not in self.read_receipts:
            self.read_receipts[message_id] = {}

        self.read_receipts[message_id][user_id] = datetime.utcnow()

        # Notify other users about the read receipt
        receipt = {
            "type": "read_receipt",
            "message_id": message_id,
            "user_id": user_id,
            "read_at": self.read_receipts[message_id][user_id].isoformat(),
        }

        # Find which room this message is in
        for room_id, messages in self.message_history.items():
            if any(msg.get("message_id") == message_id for msg in messages):
                for connection in self.active_connections.get(room_id, set()):
                    try:
                        await connection.send_json(receipt)
                    except Exception as e:
                        logger.error(f"Error sending read receipt: {e}")
                break


# Global instance
p2p_manager = P2PConnectionManager()
