""
Chat service for handling message operations.
"""
from datetime import datetime
from typing import List, Dict, Optional
from ..models.message import Message
from ..models.user import User
from ..extensions import db
from .encryption_service import EncryptionService
import logging

logger = logging.getLogger(__name__)

class ChatService:
    """Service for handling chat operations."""
    
    def __init__(self, encryption_service: EncryptionService = None):
        """Initialize the chat service with an optional encryption service."""
        self.encryption_service = encryption_service or EncryptionService()
    
    def send_message(self, user_id: int, content: str, room_id: Optional[int] = None, 
                    is_encrypted: bool = False) -> Message:
        """
        Send a new message.
        
        Args:
            user_id: ID of the user sending the message
            content: The message content
            room_id: Optional room ID for group chats
            is_encrypted: Whether the message should be encrypted
            
        Returns:
            The created Message object
        """
        try:
            message = Message(
                user_id=user_id,
                room_id=room_id,
                content=content,
                is_encrypted=is_encrypted,
                timestamp=datetime.utcnow()
            )
            
            if is_encrypted:
                message.content = self.encryption_service.encrypt(content.encode('utf-8'))
            
            db.session.add(message)
            db.session.commit()
            
            logger.info(f"Message {message.id} sent by user {user_id}")
            return message
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to send message: {str(e)}")
            raise
    
    def get_messages(self, limit: int = 50, before: datetime = None, 
                    room_id: Optional[int] = None) -> List[Dict]:
        """
        Retrieve messages with optional filtering.
        
        Args:
            limit: Maximum number of messages to return
            before: Only return messages before this timestamp
            room_id: Optional room ID to filter by
            
        Returns:
            List of message dictionaries
        """
        query = Message.query.order_by(Message.timestamp.desc())
        
        if room_id is not None:
            query = query.filter_by(room_id=room_id)
            
        if before:
            query = query.filter(Message.timestamp < before)
            
        messages = query.limit(limit).all()
        
        result = []
        for msg in messages:
            try:
                content = msg.content
                if msg.is_encrypted:
                    content = self.encryption_service.decrypt(content).decode('utf-8')
                
                result.append({
                    'id': msg.id,
                    'user_id': msg.user_id,
                    'username': msg.author.username,
                    'content': content,
                    'timestamp': msg.timestamp.isoformat(),
                    'is_encrypted': msg.is_encrypted,
                    'room_id': msg.room_id
                })
            except Exception as e:
                logger.error(f"Error processing message {msg.id}: {str(e)}")
                continue
                
        return result
    
    def delete_message(self, message_id: int, user_id: int) -> bool:
        """
        Delete a message if the user has permission.
        
        Args:
            message_id: ID of the message to delete
            user_id: ID of the user requesting deletion
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        message = Message.query.get_or_404(message_id)
        user = User.query.get(user_id)
        
        # Allow deletion if user is the author or an admin
        if message.user_id != user_id and not (user and user.is_admin):
            logger.warning(f"User {user_id} attempted to delete message {message_id} without permission")
            return False
            
        try:
            db.session.delete(message)
            db.session.commit()
            logger.info(f"Message {message_id} deleted by user {user_id}")
            return True
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to delete message {message_id}: {str(e)}")
            return False
    
    def get_active_users(self, minutes: int = 15) -> List[Dict]:
        """
        Get a list of users active in the last 'minutes' minutes.
        
        Args:
            minutes: Number of minutes to consider for activity
            
        Returns:
            List of active users with their details
        """
        from datetime import datetime, timedelta
        
        threshold = datetime.utcnow() - timedelta(minutes=minutes)
        
        # This assumes you have a last_seen field in your User model
        active_users = User.query.filter(User.last_seen >= threshold).all()
        
        return [{
            'id': user.id,
            'username': user.username,
            'last_seen': user.last_seen.isoformat(),
            'is_online': (datetime.utcnow() - user.last_seen).total_seconds() < 300  # 5 minutes
        } for user in active_users]
    
    def create_room(self, name: str, user_id: int, is_private: bool = False, 
                   password: str = None) -> Dict:
        """
        Create a new chat room.
        
        Args:
            name: Name of the room
            user_id: ID of the user creating the room
            is_private: Whether the room is private
            password: Optional password for the room
            
        Returns:
            Dictionary with room details
        """
        from ..models.room import Room
        
        try:
            room = Room(
                name=name,
                created_by=user_id,
                is_private=is_private,
                created_at=datetime.utcnow()
            )
            
            if password:
                room.set_password(password)
                
            db.session.add(room)
            db.session.commit()
            
            # Add the creator as a member
            self._add_room_member(room.id, user_id, is_admin=True)
            
            logger.info(f"Room {room.id} created by user {user_id}")
            return {
                'id': room.id,
                'name': room.name,
                'is_private': room.is_private,
                'created_at': room.created_at.isoformat(),
                'member_count': 1
            }
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Failed to create room: {str(e)}")
            raise
    
    def _add_room_member(self, room_id: int, user_id: int, is_admin: bool = False) -> None:
        """Add a user to a room (internal use)."""
        from ..models.room_member import RoomMember
        
        member = RoomMember(
            room_id=room_id,
            user_id=user_id,
            is_admin=is_admin,
            joined_at=datetime.utcnow()
        )
        
        db.session.add(member)
        db.session.commit()
        
    def get_room_messages(self, room_id: int, limit: int = 50, 
                         before: datetime = None) -> List[Dict]:
        """
        Get messages from a specific room.
        
        Args:
            room_id: ID of the room
            limit: Maximum number of messages to return
            before: Only return messages before this timestamp
            
        Returns:
            List of message dictionaries
        """
        return self.get_messages(limit=limit, before=before, room_id=room_id)
