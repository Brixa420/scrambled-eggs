"""
Link preview model for storing rich link previews.
"""
import uuid
import json
from datetime import datetime
from enum import Enum as PyEnum
from sqlalchemy import Column, DateTime, String, Text, Integer, Boolean, JSON
from sqlalchemy.dialects.postgresql import UUID

from ..extensions import db

class LinkPreviewStatus(PyEnum):
    """Status of a link preview."""
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCESS = "success"
    FAILED = "failed"

class LinkPreview(db.Model):
    """Stores rich preview data for URLs shared in messages."""
    
    __tablename__ = "link_previews"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    url = Column(String(2048), unique=True, nullable=False, index=True)
    title = Column(String(512), nullable=True)
    description = Column(Text, nullable=True)
    image_url = Column(String(2048), nullable=True)
    site_name = Column(String(255), nullable=True)
    status = Column(String(20), default=LinkPreviewStatus.PENDING.value, nullable=False)
    error = Column(Text, nullable=True)
    attempts = Column(Integer, default=0, nullable=False)
    metadata_ = Column('metadata', JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    def to_dict(self) -> dict:
        """Convert the model to a dictionary."""
        return {
            'id': str(self.id),
            'url': self.url,
            'title': self.title,
            'description': self.description,
            'image_url': self.image_url,
            'site_name': self.site_name,
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'metadata': self.metadata_
        }
    
    def __repr__(self):
        return f"<LinkPreview {self.url} ({self.status})>"
