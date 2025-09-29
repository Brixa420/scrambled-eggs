"""
Message mention model for tracking user mentions in messages.
"""
import uuid
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import Column, DateTime, ForeignKey, Enum, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..extensions import db

class MentionType(PyEnum):
    """Types of mentions."""
    USER = "user"
    CHANNEL = "channel"
    ROLE = "role"
    EVERYONE = "everyone"
    HERE = "here"

class MessageMention(db.Model):
    """Tracks user mentions in messages."""
    
    __tablename__ = "message_mentions"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id = Column(UUID(as_uuid=True), ForeignKey('messages.id'), nullable=False)
    mentioned_id = Column(UUID(as_uuid=True), nullable=False)  # ID of the mentioned user/role/channel
    mentioner_id = Column(UUID(as_uuid=True), nullable=False)  # ID of the user who mentioned
    mention_type = Column(Enum(MentionType), nullable=False, default=MentionType.USER)
    mentioned_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_notified = Column(Boolean, default=False, nullable=False)
    
    # Relationship
    message = relationship("Message", back_populates="mentions")
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            'id': str(self.id),
            'message_id': str(self.message_id),
            'mentioned_id': str(self.mentioned_id),
            'mentioner_id': str(self.mentioner_id),
            'mention_type': self.mention_type.value,
            'mentioned_at': self.mentioned_at.isoformat(),
            'is_notified': self.is_notified
        }
