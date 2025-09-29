"""
WebSocket connection manager for handling real-time communication.
"""

import asyncio
import logging
from typing import Dict, List, Set

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and message broadcasting."""

    def __init__(self):
        # channel_id -> {user_id -> WebSocket}
        self.active_connections: Dict[str, Dict[str, WebSocket]] = {}
        # user_id -> Set[channel_id]
        self.user_channels: Dict[str, Set[str]] = {}
        # For rate limiting
        self.typing_users: Dict[str, Dict[str, float]] = {}
        self.typing_timeout = 10  # seconds

    async def connect(self, websocket: WebSocket, channel_id: str, user_id: str):
        """Handle new WebSocket connection."""
        await websocket.accept()

        # Add to active connections
        if channel_id not in self.active_connections:
            self.active_connections[channel_id] = {}
        self.active_connections[channel_id][user_id] = websocket

        # Track user's channels
        if user_id not in self.user_channels:
            self.user_channels[user_id] = set()
        self.user_channels[user_id].add(channel_id)

        logger.info(f"User {user_id} connected to channel {channel_id}")

        # Notify others in the channel
        await self.broadcast_user_status(channel_id=channel_id, user_id=user_id, status="online")

    def disconnect(self, websocket: WebSocket, channel_id: str, user_id: str):
        """Handle WebSocket disconnection."""
        if channel_id in self.active_connections:
            if user_id in self.active_connections[channel_id]:
                del self.active_connections[channel_id][user_id]
                logger.info(f"User {user_id} disconnected from channel {channel_id}")

            # Remove channel from user's channels
            if user_id in self.user_channels and channel_id in self.user_channels[user_id]:
                self.user_channels[user_id].remove(channel_id)

                # If user is not in any channels, remove them completely
                if not self.user_channels[user_id]:
                    del self.user_channels[user_id]

                    # Notify all channels the user was in that they're now offline
                    # (This would need to be implemented with a proper presence system)

    async def broadcast_channel_message(self, channel_id: str, message: dict):
        """Broadcast a message to all connections in a channel."""
        if channel_id not in self.active_connections:
            return

        message_data = {"type": "message", "data": message}

        # Send to all connections in the channel
        tasks = []
        for user_id, connection in list(self.active_connections[channel_id].items()):
            try:
                tasks.append(connection.send_json(message_data))
            except Exception as e:
                logger.error(f"Error sending message to user {user_id}: {e}")
                self.disconnect(connection, channel_id, user_id)

        # Run all sends concurrently
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_user_status(self, channel_id: str, user_id: str, status: str):
        """Broadcast a user's status change to the channel."""
        if channel_id not in self.active_connections:
            return

        status_data = {
            "type": "user_status",
            "data": {"user_id": user_id, "status": status, "channel_id": channel_id},
        }

        # Send to all connections in the channel except the user who changed status
        tasks = []
        for uid, connection in list(self.active_connections[channel_id].items()):
            if uid == user_id:
                continue

            try:
                tasks.append(connection.send_json(status_data))
            except Exception as e:
                logger.error(f"Error sending status update to user {uid}: {e}")
                self.disconnect(connection, channel_id, uid)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def broadcast_typing(self, channel_id: str, user_id: str, username: str):
        """Broadcast a typing indicator to the channel."""
        if channel_id not in self.active_connections:
            return

        # Rate limit typing indicators (once every 2 seconds per user per channel)
        current_time = asyncio.get_event_loop().time()

        if channel_id not in self.typing_users:
            self.typing_users[channel_id] = {}

        last_typed = self.typing_users[channel_id].get(user_id, 0)
        if current_time - last_typed < 2.0:  # 2 second cooldown
            return

        self.typing_users[channel_id][user_id] = current_time

        # Clean up old typing users
        self.typing_users[channel_id] = {
            uid: ts
            for uid, ts in self.typing_users[channel_id].items()
            if current_time - ts < self.typing_timeout
        }

        typing_data = {
            "type": "typing",
            "data": {"user_id": user_id, "username": username, "channel_id": channel_id},
        }

        # Send to all connections in the channel except the user who is typing
        tasks = []
        for uid, connection in list(self.active_connections[channel_id].items()):
            if uid == user_id:
                continue

            try:
                tasks.append(connection.send_json(typing_data))
            except Exception as e:
                logger.error(f"Error sending typing indicator to user {uid}: {e}")
                self.disconnect(connection, channel_id, uid)

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def send_direct_message(self, user_id: str, message: dict):
        """Send a direct message to a specific user across all their connections."""
        if user_id not in self.user_channels:
            return

        message_data = {"type": "direct_message", "data": message}

        # Send to all of the user's connections
        tasks = []
        for channel_id in list(self.user_channels[user_id]):
            if (
                channel_id in self.active_connections
                and user_id in self.active_connections[channel_id]
            ):
                try:
                    tasks.append(
                        self.active_connections[channel_id][user_id].send_json(message_data)
                    )
                except Exception as e:
                    logger.error(f"Error sending DM to user {user_id}: {e}")
                    self.disconnect(
                        self.active_connections[channel_id][user_id], channel_id, user_id
                    )

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def get_online_users(self, channel_id: str) -> List[str]:
        """Get list of online user IDs in a channel."""
        if channel_id not in self.active_connections:
            return []
        return list(self.active_connections[channel_id].keys())

    def is_user_online(self, user_id: str) -> bool:
        """Check if a user is online in any channel."""
        return user_id in self.user_channels and bool(self.user_channels[user_id])
