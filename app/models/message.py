"""
Message model for the chat functionality.
"""
import uuid
from datetime import datetime, timedelta
from enum import Enum as PyEnum
from sqlalchemy import Column, String, Text, DateTime, Boolean, ForeignKey, JSON, Enum
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from ..extensions import db


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
    __tablename__ = 'messages'
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    thread_id = Column(UUID(as_uuid=True), index=True)
    parent_id = Column(UUID(as_uuid=True), index=True)
    
    # Sender and recipient information
    sender_id = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False, index=True)
    sender_device_id = Column(UUID(as_uuid=True))
    recipient_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    
    # Message content
    content = Column(Text, nullable=False)
    content_type = Column(String(50), default="text/plain")
    message_type = Column(Enum(MessageType), default=MessageType.TEXT)
    
    # Encryption and security
    encryption_algorithm = Column(String(50))
    encryption_key_id = Column(UUID(as_uuid=True))
    iv = Column(Text)
    auth_tag = Column(Text)
    
    # Status and timestamps
    status = Column(Enum(MessageStatus), default=MessageStatus.DRAFT)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    expires_at = Column(DateTime)
    deleted_at = Column(DateTime)
    
    # Additional data
    message_metadata = Column('metadata', JSON, default=dict)  # Renamed to avoid conflict with SQLAlchemy metadata
    file_attachments = Column(JSON, default=list)
    
    # Relationships
    sender = relationship('User', back_populates='messages')
    
    def __init__(self, **kwargs):
        super(Message, self).__init__(**kwargs)
        if not self.id:
            self.id = uuid.uuid4()
    
    def is_encrypted(self) -> bool:
        """Check if the message is encrypted."""
        return bool(self.encryption_algorithm)
    
    def is_expired(self) -> bool:
        """Check if the message has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at
    
    def to_dict(self) -> dict:
        """Convert message to dictionary."""
        return {
            'id': str(self.id),
            'conversation_id': str(self.conversation_id),
            'thread_id': str(self.thread_id),
            'parent_id': str(self.parent_id),
            'sender_id': str(self.sender_id),
            'recipient_id': str(self.recipient_id),
            'content': self.content,
            'content_type': self.content_type,
            'message_type': self.message_type.value if self.message_type else None,
            'status': self.status.value if self.status else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'is_encrypted': self.is_encrypted(),
            'is_expired': self.is_expired(),
            'metadata': self.message_metadata or {},
            'file_attachments': self.file_attachments or []
        }
