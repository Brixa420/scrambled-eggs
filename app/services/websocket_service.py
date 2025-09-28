"""
WebSocket service for real-time file sharing updates.
"""
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from flask import current_app
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_jwt_extended import decode_token

from app.extensions import socketio
from app.models.file import File, FileShare, FileAccessLog
from app.utils.security import get_jwt_identity

logger = logging.getLogger(__name__)

class WebSocketService:
    """
    Service for handling WebSocket connections and events.
    """
    
    def __init__(self, socketio: SocketIO):
        """Initialize the WebSocket service."""
        self.socketio = socketio
        self.active_users: Dict[str, List[str]] = {}  # user_id: [socket_ids]
        self.file_rooms: Dict[str, List[str]] = {}  # file_id: [user_ids]
        self._register_handlers()
    
    def _register_handlers(self):
        """Register WebSocket event handlers."""
        self.socketio.on_event('connect', self._handle_connect)
        self.socketio.on_event('disconnect', self._handle_disconnect)
        self.socketio.on_event('join_file_room', self._handle_join_file_room)
        self.socketio.on_event('leave_file_room', self._handle_leave_file_room)
        self.socketio.on_event('file_update', self._handle_file_update)
        self.socketio.on_event('file_share', self._handle_file_share)
    
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
            # In a real app, you should verify the signature and check expiration
            payload = decode_token(token)
            return {
                'id': payload['identity'],
                'username': payload.get('username', 'anonymous')
            }
        except Exception as e:
            logger.warning(f"Invalid token: {str(e)}")
            return None
    
    def _handle_connect(self):
        """Handle new WebSocket connection."""
        # Get the JWT token from the query string or headers
        token = request.args.get('token') or request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            logger.warning("WebSocket connection attempt without token")
            return False
        
        # Authenticate the user
        user = self._get_user_from_token(token)
        if not user:
            logger.warning(f"WebSocket authentication failed for token: {token[:10]}...")
            return False
        
        # Store the user's socket connection
        socket_id = request.sid
        user_id = user['id']
        
        if user_id not in self.active_users:
            self.active_users[user_id] = []
        
        if socket_id not in self.active_users[user_id]:
            self.active_users[user_id].append(socket_id)
        
        logger.info(f"User {user_id} connected (socket: {socket_id})")
        
        # Send a welcome message
        self.socketio.emit('connected', {
            'message': 'Connected to WebSocket server',
            'user_id': user_id,
            'socket_id': socket_id,
            'timestamp': datetime.utcnow().isoformat()
        }, room=socket_id)
        
        return True
    
    def _handle_disconnect(self):
        """Handle WebSocket disconnection."""
        socket_id = request.sid
        
        # Find the user associated with this socket
        user_id = None
        for uid, sockets in self.active_users.items():
            if socket_id in sockets:
                user_id = uid
                sockets.remove(socket_id)
                if not sockets:
                    del self.active_users[user_id]
                break
        
        if user_id:
            logger.info(f"User {user_id} disconnected (socket: {socket_id})")
            
            # Leave all file rooms
            for file_id, users in list(self.file_rooms.items()):
                if user_id in users:
                    users.remove(user_id)
                    if not users:
                        del self.file_rooms[file_id]
                    
                    # Notify other users in the room
                    self.socketio.emit('user_left', {
                        'user_id': user_id,
                        'file_id': file_id,
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=file_id)
    
    def _handle_join_file_room(self, data: Dict[str, Any]):
        """Handle joining a file room for real-time updates."""
        socket_id = request.sid
        file_id = data.get('file_id')
        
        if not file_id:
            logger.warning("Missing file_id in join_file_room event")
            return
        
        # Get the user ID from active connections
        user_id = None
        for uid, sockets in self.active_users.items():
            if socket_id in sockets:
                user_id = uid
                break
        
        if not user_id:
            logger.warning(f"Unauthorized attempt to join file room {file_id}")
            return
        
        # Verify the user has access to the file
        file = File.query.get(file_id)
        if not file:
            logger.warning(f"File not found: {file_id}")
            return
        
        if file.user_id != user_id and not file.is_public:
            # Check if the user has been shared the file
            share = FileShare.query.filter_by(
                file_id=file_id,
                shared_with=user_id
            ).first()
            
            if not share or (share.expires_at and share.expires_at < datetime.utcnow()):
                logger.warning(f"User {user_id} does not have access to file {file_id}")
                return
        
        # Join the file room
        join_room(file_id)
        
        # Update file_rooms tracking
        if file_id not in self.file_rooms:
            self.file_rooms[file_id] = []
        
        if user_id not in self.file_rooms[file_id]:
            self.file_rooms[file_id].append(user_id)
        
        logger.info(f"User {user_id} joined file room {file_id}")
        
        # Notify other users in the room
        self.socketio.emit('user_joined', {
            'user_id': user_id,
            'file_id': file_id,
            'timestamp': datetime.utcnow().isoformat()
        }, room=file_id, include_self=False)
        
        # Send the current file state
        self.socketio.emit('file_state', {
            'file_id': file_id,
            'data': file.to_dict(),
            'timestamp': datetime.utcnow().isoformat()
        }, room=socket_id)
    
    def _handle_leave_file_room(self, data: Dict[str, Any]):
        """Handle leaving a file room."""
        socket_id = request.sid
        file_id = data.get('file_id')
        
        if not file_id:
            return
        
        # Get the user ID from active connections
        user_id = None
        for uid, sockets in self.active_users.items():
            if socket_id in sockets:
                user_id = uid
                break
        
        if not user_id:
            return
        
        # Leave the file room
        leave_room(file_id)
        
        # Update file_rooms tracking
        if file_id in self.file_rooms and user_id in self.file_rooms[file_id]:
            self.file_rooms[file_id].remove(user_id)
            
            if not self.file_rooms[file_id]:
                del self.file_rooms[file_id]
        
        logger.info(f"User {user_id} left file room {file_id}")
        
        # Notify other users in the room
        self.socketio.emit('user_left', {
            'user_id': user_id,
            'file_id': file_id,
            'timestamp': datetime.utcnow().isoformat()
        }, room=file_id)
    
    def _handle_file_update(self, data: Dict[str, Any]):
        """Handle file update events."""
        socket_id = request.sid
        file_id = data.get('file_id')
        update_data = data.get('data', {})
        
        if not file_id or not update_data:
            return
        
        # Get the user ID from active connections
        user_id = None
        for uid, sockets in self.active_users.items():
            if socket_id in sockets:
                user_id = uid
                break
        
        if not user_id:
            logger.warning(f"Unauthorized attempt to update file {file_id}")
            return
        
        # Verify the user has permission to update the file
        file = File.query.get(file_id)
        if not file:
            logger.warning(f"File not found: {file_id}")
            return
        
        if file.user_id != user_id:
            # Check if the user has edit permission through a share
            share = FileShare.query.filter_by(
                file_id=file_id,
                shared_with=user_id,
                can_edit=True
            ).first()
            
            if not share or (share.expires_at and share.expires_at < datetime.utcnow()):
                logger.warning(f"User {user_id} does not have permission to update file {file_id}")
                return
        
        # Update the file in the database
        try:
            # Only allow certain fields to be updated
            allowed_updates = ['original_filename', 'is_public', 'expires_at', 'max_downloads']
            
            for field, value in update_data.items():
                if field in allowed_updates and hasattr(file, field):
                    setattr(file, field, value)
            
            file.updated_at = datetime.utcnow()
            db.session.commit()
            
            # Broadcast the update to all users in the file room
            self.socketio.emit('file_updated', {
                'file_id': file_id,
                'updated_by': user_id,
                'updates': update_data,
                'timestamp': datetime.utcnow().isoformat()
            }, room=file_id)
            
            # Log the update
            FileAccessLog.log_access(
                file_id=file_id,
                user_id=user_id,
                action='update',
                status='success',
                details=f"Updated fields: {', '.join(update_data.keys())}"
            )
            
        except Exception as e:
            logger.error(f"Failed to update file {file_id}: {str(e)}")
            db.session.rollback()
    
    def _handle_file_share(self, data: Dict[str, Any]):
        """Handle file sharing events."""
        socket_id = request.sid
        file_id = data.get('file_id')
        target_user_id = data.get('user_id')
        can_edit = data.get('can_edit', False)
        expires_at = data.get('expires_at')
        
        if not file_id or not target_user_id:
            logger.warning("Missing required fields in file_share event")
            return
        
        # Get the user ID from active connections
        user_id = None
        for uid, sockets in self.active_users.items():
            if socket_id in sockets:
                user_id = uid
                break
        
        if not user_id:
            logger.warning(f"Unauthorized attempt to share file {file_id}")
            return
        
        # Verify the user owns the file
        file = File.query.get(file_id)
        if not file or file.user_id != user_id:
            logger.warning(f"User {user_id} does not own file {file_id}")
            return
        
        # Create the share
        try:
            share = FileShare(
                file_id=file_id,
                shared_by=user_id,
                shared_with=target_user_id,
                can_edit=can_edit,
                expires_at=expires_at
            )
            
            db.session.add(share)
            db.session.commit()
            
            # Notify the target user if they're online
            if target_user_id in self.active_users:
                for target_socket_id in self.active_users[target_user_id]:
                    self.socketio.emit('file_shared', {
                        'file_id': file_id,
                        'shared_by': user_id,
                        'file_name': file.original_filename,
                        'can_edit': can_edit,
                        'expires_at': expires_at,
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=target_socket_id)
            
            # Log the share
            FileAccessLog.log_access(
                file_id=file_id,
                user_id=user_id,
                action='share',
                status='success',
                details=f"Shared with user {target_user_id} (edit: {can_edit})"
            )
            
        except Exception as e:
            logger.error(f"Failed to share file {file_id}: {str(e)}")
            db.session.rollback()
    
    def notify_file_upload(self, file_id: str, user_id: str, file_data: Dict[str, Any]):
        """
        Notify relevant users about a new file upload.
        
        Args:
            file_id: ID of the uploaded file
            user_id: ID of the user who uploaded the file
            file_data: File metadata
        """
        self.socketio.emit('file_uploaded', {
            'file_id': file_id,
            'uploaded_by': user_id,
            'file_data': file_data,
            'timestamp': datetime.utcnow().isoformat()
        }, room=f'user_{user_id}')
    
    def notify_file_download(self, file_id: str, user_id: str):
        """
        Notify file owner about a download.
        
        Args:
            file_id: ID of the downloaded file
            user_id: ID of the user who downloaded the file
        """
        file = File.query.get(file_id)
        if not file:
            return
        
        # Notify the file owner if they're online
        if file.user_id in self.active_users:
            for socket_id in self.active_users[file.user_id]:
                self.socketio.emit('file_downloaded', {
                    'file_id': file_id,
                    'downloaded_by': user_id,
                    'file_name': file.original_filename,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=socket_id)


# Initialize the WebSocket service
websocket_service = WebSocketService(socketio)
