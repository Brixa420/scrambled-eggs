"""
WebSocket handler for real-time chat functionality.
"""

import asyncio
import logging
from typing import Dict, Optional

from flask import request
from flask_socketio import Namespace, emit, join_room, leave_room

from app.extensions import socketio
from app.services.chat_manager import ChatManager

logger = logging.getLogger(__name__)


class ChatNamespace(Namespace):
    """
    WebSocket namespace for handling chat-related events.
    """

    def __init__(self, namespace=None):
        super().__init__(namespace)
        self.chat_managers: Dict[str, ChatManager] = {}
        self.user_sessions: Dict[str, str] = {}  # session_id -> user_id
        self.user_rooms: Dict[str, str] = {}  # user_id -> room_id

    def get_chat_manager(self, user_id: str) -> Optional[ChatManager]:
        """Get or create a ChatManager instance for a user."""
        if user_id not in self.chat_managers:
            try:
                # Create a new ChatManager for the user
                chat_manager = ChatManager(user_id, request.sid)
                self.chat_managers[user_id] = chat_manager

                # Register message callback
                chat_manager.register_message_callback(self._handle_chat_event)

                # Initialize the chat manager
                asyncio.create_task(chat_manager.initialize())

                logger.info(f"Created new ChatManager for user {user_id}")

            except Exception as e:
                logger.error(f"Failed to create ChatManager: {e}", exc_info=True)
                return None

        return self.chat_managers.get(user_id)

    def on_connect(self):
        """Handle WebSocket connection."""
        logger.info(f"Client connected: {request.sid}")

    def on_disconnect(self):
        """Handle WebSocket disconnection."""
        user_id = self.user_sessions.get(request.sid)
        if user_id:
            # Clean up chat manager
            if user_id in self.chat_managers:
                asyncio.create_task(self._cleanup_user(user_id))

            # Remove from user sessions
            del self.user_sessions[request.sid]

            # Leave all rooms
            if user_id in self.user_rooms:
                room_id = self.user_rooms[user_id]
                leave_room(room_id)
                del self.user_rooms[user_id]

        logger.info(f"Client disconnected: {request.sid} (user: {user_id or 'unknown'})")

    async def _cleanup_user(self, user_id: str):
        """Clean up resources for a user."""
        try:
            if user_id in self.chat_managers:
                await self.chat_managers[user_id].close()
                del self.chat_managers[user_id]
                logger.info(f"Cleaned up resources for user {user_id}")
        except Exception as e:
            logger.error(f"Error cleaning up user {user_id}: {e}", exc_info=True)

    def on_authenticate(self, data: dict):
        """Authenticate a WebSocket connection."""
        try:
            # Verify authentication token
            token = data.get("token")
            if not token:
                emit("error", {"message": "Authentication token is required"})
                return

            # Verify the token and get user info
            # This is a placeholder - implement your actual token verification
            user_id = self._verify_token(token)
            if not user_id:
                emit("error", {"message": "Invalid or expired token"})
                return

            # Store user session
            self.user_sessions[request.sid] = user_id

            # Create a room for the user
            room_id = f"user_{user_id}"
            join_room(room_id)
            self.user_rooms[user_id] = room_id

            # Initialize chat manager
            self.get_chat_manager(user_id)

            emit("authenticated", {"user_id": user_id})
            logger.info(f"User {user_id} authenticated on socket {request.sid}")

        except Exception as e:
            logger.error(f"Authentication error: {e}", exc_info=True)
            emit("error", {"message": "Authentication failed"})

    def _verify_token(self, token: str) -> Optional[str]:
        """
        Verify an authentication token and return the user ID.

        Args:
            token: The authentication token

        Returns:
            The user ID if the token is valid, None otherwise
        """
        # This is a placeholder - implement your actual token verification
        # For example, using Flask-JWT-Extended:
        # from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        # try:
        #     verify_jwt_in_request()
        #     return get_jwt_identity()
        # except:
        #     return None

        # For now, we'll just return the token as the user ID for testing
        return token

    def on_send_message(self, data: dict):
        """Handle sending a chat message."""
        try:
            user_id = self.user_sessions.get(request.sid)
            if not user_id:
                emit("error", {"message": "Not authenticated"})
                return

            peer_id = data.get("peer_id")
            content = data.get("content")
            message_type = data.get("message_type", "text")

            if not peer_id or not content:
                emit("error", {"message": "Peer ID and content are required"})
                return

            chat_manager = self.get_chat_manager(user_id)
            if not chat_manager:
                emit("error", {"message": "Failed to initialize chat"})
                return

            # Send the message
            asyncio.create_task(chat_manager.send_message(peer_id, content, message_type))

            emit("message_sent", {"peer_id": peer_id, "status": "sending"})

        except Exception as e:
            logger.error(f"Error sending message: {e}", exc_info=True)
            emit("error", {"message": "Failed to send message"})

    def on_typing_indicator(self, data: dict):
        """Handle typing indicators."""
        try:
            user_id = self.user_sessions.get(request.sid)
            if not user_id:
                return

            peer_id = data.get("peer_id")
            is_typing = data.get("is_typing", False)

            if not peer_id:
                return

            chat_manager = self.get_chat_manager(user_id)
            if chat_manager:
                asyncio.create_task(chat_manager.send_typing_indicator(peer_id, is_typing))

        except Exception as e:
            logger.error(f"Error handling typing indicator: {e}", exc_info=True)

    def on_read_receipt(self, data: dict):
        """Handle read receipts."""
        try:
            user_id = self.user_sessions.get(request.sid)
            if not user_id:
                return

            peer_id = data.get("peer_id")
            message_id = data.get("message_id")

            if not peer_id or not message_id:
                return

            chat_manager = self.get_chat_manager(user_id)
            if chat_manager:
                asyncio.create_task(chat_manager.send_read_receipt(peer_id, message_id))

        except Exception as e:
            logger.error(f"Error handling read receipt: {e}", exc_info=True)

    def on_request_history(self, data: dict):
        """Handle history requests."""
        try:
            user_id = self.user_sessions.get(request.sid)
            if not user_id:
                emit("error", {"message": "Not authenticated"})
                return

            peer_id = data.get("peer_id")
            before = data.get("before")
            limit = min(data.get("limit", 50), 100)

            if not peer_id:
                emit("error", {"message": "Peer ID is required"})
                return

            chat_manager = self.get_chat_manager(user_id)
            if chat_manager:
                asyncio.create_task(chat_manager.request_message_history(peer_id, before, limit))

        except Exception as e:
            logger.error(f"Error handling history request: {e}", exc_info=True)

    async def _handle_chat_event(self, event: dict):
        """
        Handle events from the ChatManager.

        This method is called by the ChatManager to notify the WebSocket handler
        about various chat events (messages, typing indicators, etc.).
        """
        try:
            event_type = event.get("type")

            if event_type == "message":
                # Forward the message to the appropriate room
                recipient_id = event.get("to")
                if recipient_id in self.user_rooms:
                    room_id = self.user_rooms[recipient_id]
                    emit("new_message", event, room=room_id)

            elif event_type == "typing_status":
                # Forward typing status to the appropriate room
                peer_id = event.get("peer_id")
                if peer_id in self.user_rooms:
                    room_id = self.user_rooms[peer_id]
                    emit("typing_status", event, room=room_id)

            elif event_type == "connection_state":
                # Forward connection state changes
                peer_id = event.get("peer_id")
                if peer_id in self.user_rooms:
                    room_id = self.user_rooms[peer_id]
                    emit("connection_state", event, room=room_id)

            elif event_type == "read_receipt":
                # Forward read receipts
                message_id = event.get("message_id")
                sender_id = event.get("from")
                if sender_id in self.user_rooms:
                    room_id = self.user_rooms[sender_id]
                    emit("read_receipt", event, room=room_id)

            # Add more event types as needed

        except Exception as e:
            logger.error(f"Error handling chat event: {e}", exc_info=True)


# Register the namespace with SocketIO
socketio.on_namespace(ChatNamespace("/chat"))
