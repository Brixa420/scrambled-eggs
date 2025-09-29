"""
WebSocket service for real-time moderation events.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from flask import request
from flask_jwt_extended import decode_token
from flask_socketio import SocketIO, join_room, leave_room, emit

from app.extensions import socketio
from app.models.user import User

logger = logging.getLogger(__name__)

class ModerationWebSocketService:
    """
    Service for handling real-time moderation events via WebSockets.
    """

    def __init__(self, socketio: SocketIO):
        """Initialize the Moderation WebSocket service."""
        self.socketio = socketio
        # Track connected users and their socket IDs
        self.active_users: Dict[str, Set[str]] = {}  # user_id: set(socket_ids)
        # Track moderation rooms (e.g., 'moderators', 'user:{user_id}')
        self.rooms: Dict[str, Set[str]] = {}  # room_name: set(socket_ids)
        # Track which users are moderators
        self.moderators: Set[str] = set()
        self._register_handlers()

    def _register_handlers(self):
        """Register WebSocket event handlers."""
        self.socketio.on_event('connect', self._handle_connect)
        self.socketio.on_event('disconnect', self._handle_disconnect)
        self.socketio.on_event('join_moderation_room', self._handle_join_moderation_room)
        self.socketio.on_event('leave_moderation_room', self._handle_leave_moderation_room)
        self.socketio.on_event('subscribe_to_user', self._handle_subscribe_to_user)
        self.socketio.on_event('unsubscribe_from_user', self._handle_unsubscribe_from_user)

    def _get_user_from_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get user information from JWT token.

        Args:
            token: JWT token from WebSocket connection

        Returns:
            User information if token is valid, None otherwise
        """
        try:
            # Decode the token without verifying the signature
            decoded = decode_token(token, allow_expired=True)
            return {
                'id': decoded.get('sub'),
                'is_admin': decoded.get('is_admin', False),
                'is_moderator': decoded.get('is_moderator', False),
                'username': decoded.get('username')
            }
        except Exception as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None

    def _add_user_connection(self, user_id: str, sid: str):
        """Add a WebSocket connection for a user."""
        if user_id not in self.active_users:
            self.active_users[user_id] = set()
        self.active_users[user_id].add(sid)
        logger.debug(f"User {user_id} connected. Active connections: {len(self.active_users[user_id])}")

    def _remove_user_connection(self, user_id: str, sid: str):
        """Remove a WebSocket connection for a user."""
        if user_id in self.active_users:
            self.active_users[user_id].discard(sid)
            if not self.active_users[user_id]:
                del self.active_users[user_id]
                # If no more connections for this user, remove from moderators if they were one
                if user_id in self.moderators:
                    self.moderators.remove(user_id)
            logger.debug(f"User {user_id} disconnected. Remaining connections: {len(self.active_users.get(user_id, []))}")

    def _join_room(self, room: str, sid: str):
        """Join a room."""
        if room not in self.rooms:
            self.rooms[room] = set()
        self.rooms[room].add(sid)
        join_room(room, sid=sid)
        logger.debug(f"Socket {sid} joined room {room}")

    def _leave_room(self, room: str, sid: str):
        """Leave a room."""
        if room in self.rooms:
            self.rooms[room].discard(sid)
            if not self.rooms[room]:
                del self.rooms[room]
        leave_room(room, sid=sid)
        logger.debug(f"Socket {sid} left room {room}")

    def _is_user_online(self, user_id: str) -> bool:
        """Check if a user has any active WebSocket connections."""
        return user_id in self.active_users and bool(self.active_users[user_id])

    def _handle_connect(self):
        """Handle new WebSocket connection."""
        token = request.args.get('token')
        if not token:
            logger.warning("No token provided for WebSocket connection")
            return False

        user = self._get_user_from_token(token)
        if not user:
            logger.warning(f"Invalid token for WebSocket connection: {token}")
            return False

        # Store the user ID in the socket's session
        socketio.server.environ[request.sid]['user'] = user
        self._add_user_connection(user['id'], request.sid)

        # If user is a moderator, add to moderators set and join moderation room
        if user.get('is_moderator') or user.get('is_admin'):
            self.moderators.add(user['id'])
            self._join_room('moderators', request.sid)
            logger.info(f"Moderator {user['username']} connected")
        else:
            logger.info(f"User {user['username']} connected")

        return True

    def _handle_disconnect(self):
        """Handle WebSocket disconnection."""
        user = socketio.server.environ.get(request.sid, {}).get('user')
        if user:
            user_id = user['id']
            self._remove_user_connection(user_id, request.sid)
            
            # Leave all rooms this socket was in
            for room in list(self.rooms.keys()):
                if request.sid in self.rooms[room]:
                    self._leave_room(room, request.sid)
            
            logger.info(f"User {user.get('username')} disconnected")

    def _handle_join_moderation_room(self, data: Dict[str, Any]):
        """Handle request to join a moderation room."""
        user = socketio.server.environ.get(request.sid, {}).get('user')
        if not user or not (user.get('is_moderator') or user.get('is_admin')):
            emit('error', {'message': 'Unauthorized'}, room=request.sid)
            return

        room = data.get('room')
        if not room:
            emit('error', {'message': 'Room not specified'}, room=request.sid)
            return

        self._join_room(f'moderation:{room}', request.sid)
        emit('room_joined', {'room': room}, room=request.sid)

    def _handle_leave_moderation_room(self, data: Dict[str, Any]):
        """Handle request to leave a moderation room."""
        room = data.get('room')
        if not room:
            emit('error', {'message': 'Room not specified'}, room=request.sid)
            return

        self._leave_room(f'moderation:{room}', request.sid)
        emit('room_left', {'room': room}, room=request.sid)

    def _handle_subscribe_to_user(self, data: Dict[str, Any]):
        """Handle request to subscribe to a user's moderation events."""
        user = socketio.server.environ.get(request.sid, {}).get('user')
        if not user or not (user.get('is_moderator') or user.get('is_admin')):
            emit('error', {'message': 'Unauthorized'}, room=request.sid)
            return

        target_user_id = data.get('user_id')
        if not target_user_id:
            emit('error', {'message': 'User ID not specified'}, room=request.sid)
            return

        room = f'user:{target_user_id}'
        self._join_room(room, request.sid)
        emit('subscribed_to_user', {'user_id': target_user_id}, room=request.sid)

    def _handle_unsubscribe_from_user(self, data: Dict[str, Any]):
        """Handle request to unsubscribe from a user's moderation events."""
        target_user_id = data.get('user_id')
        if not target_user_id:
            emit('error', {'message': 'User ID not specified'}, room=request.sid)
            return

        room = f'user:{target_user_id}'
        self._leave_room(room, request.sid)
        emit('unsubscribed_from_user', {'user_id': target_user_id}, room=request.sid)

    # Public API methods for sending events

    def notify_moderators(self, event: str, data: Dict[str, Any], room: str = None):
        """
        Send an event to all connected moderators.
        
        Args:
            event: Event name
            data: Event data
            room: Optional specific moderation room to notify
        """
        target_room = f'moderation:{room}' if room else 'moderators'
        self.socketio.emit(event, data, room=target_room)
        logger.debug(f"Sent {event} to {target_room}")

    def notify_user(self, user_id: str, event: str, data: Dict[str, Any]):
        """
        Send an event to a specific user.
        
        Args:
            user_id: ID of the user to notify
            event: Event name
            data: Event data
        """
        if user_id in self.active_users:
            for sid in self.active_users[user_id]:
                self.socketio.emit(event, data, room=sid)
            logger.debug(f"Sent {event} to user {user_id}")

    def broadcast_moderation_event(self, event: str, data: Dict[str, Any]):
        """
        Broadcast a moderation event to all connected clients.
        
        Args:
            event: Event name
            data: Event data
        """
        self.socketio.emit(event, data)
        logger.debug(f"Broadcasted {event} to all clients")

    def notify_content_review(self, content_id: str, content_type: str, review_data: Dict[str, Any]):
        """
        Notify moderators about content that needs review.
        
        Args:
            content_id: ID of the content
            content_type: Type of content (e.g., 'post', 'comment', 'image')
            review_data: Additional data about the content
        """
        self.notify_moderators('content_review_needed', {
            'content_id': content_id,
            'content_type': content_type,
            'timestamp': datetime.utcnow().isoformat(),
            **review_data
        })

    def notify_moderation_action(self, action_type: str, target_user_id: str, action_data: Dict[str, Any]):
        """
        Notify about a moderation action taken.
        
        Args:
            action_type: Type of action (e.g., 'warning', 'suspension', 'ban')
            target_user_id: ID of the user who was acted upon
            action_data: Details about the action
        """
        # Notify the target user
        self.notify_user(target_user_id, 'moderation_action_taken', {
            'action_type': action_type,
            'timestamp': datetime.utcnow().isoformat(),
            **action_data
        })
        
        # Notify moderators
        self.notify_moderators('moderation_action', {
            'action_type': action_type,
            'target_user_id': target_user_id,
            'timestamp': datetime.utcnow().isoformat(),
            **action_data
        })

    def notify_appeal_created(self, appeal_id: str, appeal_data: Dict[str, Any]):
        """
        Notify moderators about a new appeal.
        
        Args:
            appeal_id: ID of the appeal
            appeal_data: Details about the appeal
        """
        self.notify_moderators('appeal_created', {
            'appeal_id': appeal_id,
            'timestamp': datetime.utcnow().isoformat(),
            **appeal_data
        })

    def notify_appeal_updated(self, appeal_id: str, status: str, update_data: Dict[str, Any]):
        """
        Notify about an appeal status update.
        
        Args:
            appeal_id: ID of the appeal
            status: New status of the appeal
            update_data: Additional update details
        """
        target_user_id = update_data.get('user_id')
        if target_user_id:
            self.notify_user(target_user_id, 'appeal_updated', {
                'appeal_id': appeal_id,
                'status': status,
                'timestamp': datetime.utcnow().isoformat(),
                **update_data
            })
        
        self.notify_moderators('appeal_updated', {
            'appeal_id': appeal_id,
            'status': status,
            'timestamp': datetime.utcnow().isoformat(),
            **update_data
        })


# Initialize the WebSocket service
moderation_ws_service = ModerationWebSocketService(socketio)
