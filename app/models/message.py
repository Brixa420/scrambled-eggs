"""
Message model for the chat functionality.
"""

import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..extensions import db
import re
from typing import List, Dict, Optional, Union
from datetime import datetime, timedelta


class MessageType(PyEnum):
    """Types of messages."""

    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    VIDEO = "video"
    AUDIO = "audio"
    ENCRYPTED = "encrypted"
    KEY_EXCHANGE = "key_exchange"
    SYSTEM = "system"


class MessageStatus(PyEnum):
    """Status of a message."""

    DRAFT = "draft"
    SENDING = "sending"
    SENT = "sent"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class Message(db.Model):
    """Message model for storing chat messages."""

    __tablename__ = "messages"
    
    # Core message fields
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    thread_id = Column(UUID(as_uuid=True), index=True)
    parent_id = Column(UUID(as_uuid=True), index=True)
    
    # Message content and metadata
    content = Column(Text, nullable=False)
    message_type = Column(Enum(MessageType), default=MessageType.TEXT, nullable=False)
    status = Column(Enum(MessageStatus), default=MessageStatus.SENT, nullable=False)
    
    # Edit tracking
    edit_count = Column(db.Integer, default=0, nullable=False)
    last_edited_at = Column(DateTime, nullable=True)
    last_edited_by = Column(UUID(as_uuid=True), nullable=True)
    edit_history = relationship("MessageEdit", back_populates="message", order_by="MessageEdit.edited_at.desc()")
    
    # Deletion tracking
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(UUID(as_uuid=True), nullable=True)
    deletion_reason = Column(String(255), nullable=True)
    
    # User and timing information
    sender_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    
    # Relationships
    edits = relationship("MessageEdit", back_populates="message", order_by="MessageEdit.edited_at.desc()")
    mentions = relationship("MessageMention", back_populates="message", cascade="all, delete-orphan")
    
    # Additional metadata
    metadata_ = Column('metadata', JSON, default=dict, nullable=False)
    
    # Indexes
    __table_args__ = (
        db.Index('idx_message_conversation_created', 'conversation_id', 'created_at'),
        db.Index('idx_message_sender', 'sender_id', 'created_at'),
    )
    
    # Constants
    MENTION_PATTERN = re.compile(r'@([\w.-]+)(?:\s|$)')
    URL_PATTERN = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        re.IGNORECASE
    )

    # Sender and recipient information
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    sender_device_id = Column(UUID(as_uuid=True))
    recipient_id = Column(UUID(as_uuid=True), nullable=False, index=True)

    # Message content
    content = Column(Text, nullable=False)
    original_content = Column(Text, nullable=True)  # For storing original content before edit
    edited = Column(Boolean, default=False, nullable=False)
    edited_at = Column(DateTime, nullable=True)
    deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    reactions = Column(
        JSON, default=dict, nullable=True
    )  # Store reactions as {'emoji': [user_ids]}
    mentions = Column(
        PG_ARRAY(UUID(as_uuid=True)), default=[], nullable=False
    )  # User IDs mentioned in the message
    content_type = Column(String(50), default="text/plain")
    message_type = Column(Enum(MessageType), default=MessageType.TEXT)

    # Encryption and security
    encryption_key_id = Column(UUID(as_uuid=True))
    iv = Column(Text)
    auth_tag = Column(Text)

    # Status and timestamps
    status = Column(Enum(MessageStatus), default=MessageStatus.DRAFT)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    edits = relationship(
        "MessageEdit", backref="message", lazy="dynamic", cascade="all, delete-orphan"
    )
    message_reactions = relationship(
        "MessageReaction", backref="message", lazy="dynamic", cascade="all, delete-orphan"
    )
    message_mentions = relationship(
        "MessageMention", backref="message", lazy="dynamic", cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Message {self.id}>"

    def edit(self, new_content: str, edited_by: UUID, reason: str = None) -> bool:
        """Edit the message content while preserving history.

        Args:
            new_content: The new content for the message
            edited_by: ID of the user making the edit
            reason: Optional reason for the edit

        Returns:
            bool: True if edit was successful, False otherwise
        """
        if not new_content or new_content == self.content:
            return False
            
        if self.is_deleted:
            return False

        # Create edit history
        edit = MessageEdit(
            message_id=self.id,
            previous_content=self.content,
            edited_by=edited_by,
            reason=reason
        )
        
        # Update message
        self.content = new_content
        self.edited = True
        self.edit_count += 1
        self.last_edited_at = datetime.utcnow()
        self.last_edited_by = edited_by
        self.updated_at = datetime.utcnow()
        
        db.session.add(edit)
        return True
    
    def can_edit(self, user_id: UUID, is_admin: bool = False) -> bool:
        """
        Check if a user can edit this message.
        
        Args:
            user_id: UUID of the user to check
            is_admin: Whether the user has admin privileges
            
        Returns:
            bool: True if the user can edit the message
        """
        if is_admin:
            return True
            
        # Only sender can edit
        if str(self.sender_id) != str(user_id):
            return False
            
        # Check edit cooldown (15 minutes)
        edit_cooldown = 900  # seconds
        time_since_creation = (datetime.utcnow() - self.created_at).total_seconds()
        
        # Allow unlimited edits within the cooldown period
        if time_since_creation <= edit_cooldown:
            return True
        
        # After cooldown, only allow edits if never edited before
        return self.edit_count == 0
    
    def delete_message(self, deleted_by: UUID, reason: str = None, hard_delete: bool = False) -> bool:
        """
        Delete the message (soft delete by default).
        
        Args:
            deleted_by: UUID of the user deleting the message
            reason: Optional reason for deletion
            hard_delete: If True, permanently delete the message (admin only)
            
        Returns:
            bool: True if successful, False otherwise
        """
        if self.is_deleted:
            return True
            
        if hard_delete:
            # Only allow hard delete for admins or system
            from ..models.user import User
            user = User.query.get(deleted_by)
            if not user or not user.is_admin:
                return False
                
            db.session.delete(self)
        else:
            # Store original content before deletion
            self.original_content = self.original_content or self.content
            
            # Soft delete
            self.is_deleted = True
            self.deleted_at = datetime.utcnow()
            self.deleted_by = deleted_by
            self.deletion_reason = reason
            self.updated_at = datetime.utcnow()
            
            # Clear sensitive content
            self.content = "[Message deleted]"
            
        return True
