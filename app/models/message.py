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

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    thread_id = Column(UUID(as_uuid=True), index=True)
    parent_id = Column(UUID(as_uuid=True), index=True)

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
        if self.deleted:
            return False

        # Create edit history
        edit = MessageEdit(
            message_id=self.id, previous_content=self.content, edited_by=edited_by, reason=reason
        )
        db.session.add(edit)

        # Update message
        self.original_content = self.original_content or self.content
        self.content = new_content
        self.edited = True
        self.edited_at = datetime.utcnow()

        return True

    def is_expired(self) -> bool:
        """Check if the message has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def delete_message(self, deleted_by: UUID) -> bool:
        """
        Mark a message as deleted.

        Args:
            deleted_by: ID of the user deleting the message

        Returns:
            bool: True if deletion was successful, False otherwise
        """
        if self.deleted:
            return False

        # Store the original content before deletion
        self.original_content = self.original_content or self.content
        self.content = "[message deleted]"
        self.deleted = True
        self.deleted_at = datetime.utcnow()

        return True

    def to_dict(self) -> dict:
        """Convert message to dictionary."""
        return {
            "id": str(self.id),
            "conversation_id": str(self.conversation_id),
            "thread_id": str(self.thread_id),
            "parent_id": str(self.parent_id),
            "sender_id": str(self.sender_id),
            "recipient_id": str(self.recipient_id),
            "content": self.content,
            "content_type": self.content_type,
            "message_type": self.message_type.value if self.message_type else None,
            "status": self.status.value if self.status else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_encrypted": self.is_encrypted(),
            "is_expired": self.is_expired(),
            "metadata": self.message_metadata or {},
            "file_attachments": self.file_attachments or [],
        }
