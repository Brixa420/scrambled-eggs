"""
Message edit history model for tracking message edits.
"""
import uuid
from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from ..extensions import db

class MessageEdit(db.Model):
    """Tracks the edit history of messages."""
    
    __tablename__ = "message_edits"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id = Column(UUID(as_uuid=True), ForeignKey('messages.id'), nullable=False)
    editor_id = Column(UUID(as_uuid=True), nullable=False)  # User who made the edit
    previous_content = Column(Text, nullable=True)  # Store the previous content
    content = Column(Text, nullable=False)  # New content after edit
    edited_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    metadata_ = Column('metadata', JSON, default=dict)  # Additional metadata like edit reason
    
    # Relationship
    message = relationship("Message", back_populates="edits")
    
    def to_dict(self):
        """Convert the model to a dictionary."""
        return {
            'id': str(self.id),
            'message_id': str(self.message_id),
            'editor_id': str(self.editor_id),
            'previous_content': self.previous_content,
            'content': self.content,
            'edited_at': self.edited_at.isoformat(),
            'metadata': self.metadata_ or {}
        }
