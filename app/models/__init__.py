"""
Database models for the application.

This module initializes the database and imports all models.
"""
from ..extensions import db

# Import all models here to ensure they are registered with SQLAlchemy
from .user import User
from .message import Message
from .encryption_key import EncryptionKey
from .file import File
from .room import Room
from .contact import Contact

# This ensures that SQLAlchemy is aware of all models
__all__ = [
    'User', 
    'Message', 
    'EncryptionKey',
    'File',
    'Room',
    'Contact',
]

def init_models(app):
    """Initialize database models."""
    with app.app_context():
        # Create all database tables
        db.create_all()
