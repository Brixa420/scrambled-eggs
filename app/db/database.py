"""
Database manager for Scrambled Eggs application.
"""

import json
import os
from typing import List, Optional, TypeVar

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import String, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, scoped_session, sessionmaker
from sqlalchemy.sql import func

from app.models.contact import Contact, ContactStatus
from app.models.message import Message, MessageStatus, MessageType

Base = declarative_base()
T = TypeVar("T")

# Database connection URL
DB_PATH = os.path.expanduser("~/.scrambled_eggs/database.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
DATABASE_URL = f"sqlite:///{DB_PATH}"

# Create engine and session factory
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))


class DBModelMixin:
    """Mixin for database models with common functionality."""

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, (datetime, date)):
                value = value.isoformat()
            result[column.name] = value
        return result

    @classmethod
    def from_dict(cls, data: dict) -> "DBModelMixin":
        """Create model from dictionary."""
        return cls(**data)


class DBContact(Base, DBModelMixin):
    """Database model for contacts."""

    __tablename__ = "contacts"

    id = Column(String(36), primary_key=True, index=True)
    user_id = Column(String(36), index=True, nullable=False)
    name = Column(String(100), nullable=False)
    email = Column(String(255), nullable=True)
    public_key = Column(Text, nullable=False)
    status = Column(SQLEnum(ContactStatus), default=ContactStatus.OFFLINE)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    is_favorite = Column(Boolean, default=False)
    metadata_json = Column(Text, default="{}")

    @property
    def metadata(self) -> dict:
        """Get metadata as dictionary."""
        return json.loads(self.metadata_json or "{}")

    @metadata.setter
    def metadata(self, value: dict):
        """Set metadata from dictionary."""
        self.metadata_json = json.dumps(value or {})


class DBMessage(Base, DBModelMixin):
    """Database model for messages."""

    __tablename__ = "messages"

    id = Column(String(36), primary_key=True, index=True)
    conversation_id = Column(String(36), index=True, nullable=False)
    sender_id = Column(String(36), index=True, nullable=False)
    recipient_id = Column(String(36), index=True, nullable=False)
    content = Column(Text, nullable=False)
    message_type = Column(SQLEnum(MessageType), default=MessageType.TEXT)
    status = Column(SQLEnum(MessageStatus), default=MessageStatus.SENDING)
    timestamp = Column(DateTime, server_default=func.now())
    metadata_json = Column(Text, default="{}")

    @property
    def metadata(self) -> dict:
        """Get metadata as dictionary."""
        return json.loads(self.metadata_json or "{}")

    @metadata.setter
    def metadata(self, value: dict):
        """Set metadata from dictionary."""
        self.metadata_json = json.dumps(value or {})


class DatabaseManager:
    """Database manager for Scrambled Eggs application."""

    def __init__(self, session: Session = None):
        """Initialize database manager."""
        self.session = session or SessionLocal()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.session.close()

    # Contact operations

    def add_contact(self, contact: Contact) -> Contact:
        """Add a new contact."""
        db_contact = DBContact(
            id=contact.id,
            user_id=contact.user_id,
            name=contact.name,
            email=contact.email,
            public_key=contact.public_key,
            status=contact.status,
            last_seen=contact.last_seen,
            is_favorite=contact.is_favorite,
            metadata=contact.metadata,
        )
        self.session.add(db_contact)
        self.session.commit()
        return contact

    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """Get a contact by ID."""
        db_contact = self.session.query(DBContact).filter_by(id=contact_id).first()
        if not db_contact:
            return None
        return Contact(
            id=db_contact.id,
            user_id=db_contact.user_id,
            name=db_contact.name,
            email=db_contact.email,
            public_key=db_contact.public_key,
            status=db_contact.status,
            last_seen=db_contact.last_seen,
            is_favorite=db_contact.is_favorite,
            metadata=db_contact.metadata,
        )

    def get_contacts(self, user_id: str) -> List[Contact]:
        """Get all contacts for a user."""
        db_contacts = self.session.query(DBContact).filter_by(user_id=user_id).all()
        return [
            Contact(
                id=c.id,
                user_id=c.user_id,
                name=c.name,
                email=c.email,
                public_key=c.public_key,
                status=c.status,
                last_seen=c.last_seen,
                is_favorite=c.is_favorite,
                metadata=c.metadata,
            )
            for c in db_contacts
        ]

    def update_contact(self, contact_id: str, **updates) -> Optional[Contact]:
        """Update a contact."""
        db_contact = self.session.query(DBContact).filter_by(id=contact_id).first()
        if not db_contact:
            return None

        for key, value in updates.items():
            if hasattr(db_contact, key):
                setattr(db_contact, key, value)

        self.session.commit()
        return Contact(
            id=db_contact.id,
            user_id=db_contact.user_id,
            name=db_contact.name,
            email=db_contact.email,
            public_key=db_contact.public_key,
            status=db_contact.status,
            last_seen=db_contact.last_seen,
            is_favorite=db_contact.is_favorite,
            metadata=db_contact.metadata,
        )

    def delete_contact(self, contact_id: str) -> bool:
        """Delete a contact."""
        db_contact = self.session.query(DBContact).filter_by(id=contact_id).first()
        if not db_contact:
            return False

        self.session.delete(db_contact)
        self.session.commit()
        return True

    # Message operations

    def add_message(self, message: Message) -> Message:
        """Add a new message."""
        db_message = DBMessage(
            id=message.id,
            conversation_id=message.conversation_id,
            sender_id=message.sender_id,
            recipient_id=message.recipient_id,
            content=message.content,
            message_type=message.message_type,
            status=message.status,
            timestamp=message.timestamp,
            metadata=message.metadata,
        )
        self.session.add(db_message)
        self.session.commit()
        return message

    def get_message(self, message_id: str) -> Optional[Message]:
        """Get a message by ID."""
        db_message = self.session.query(DBMessage).filter_by(id=message_id).first()
        if not db_message:
            return None
        return self._convert_db_message(db_message)

    def get_messages(
        self, conversation_id: str, limit: int = 100, offset: int = 0
    ) -> List[Message]:
        """Get messages for a conversation."""
        db_messages = (
            self.session.query(DBMessage)
            .filter_by(conversation_id=conversation_id)
            .order_by(DBMessage.timestamp.desc())
            .limit(limit)
            .offset(offset)
            .all()
        )
        return [self._convert_db_message(m) for m in db_messages]

    def update_message_status(self, message_id: str, status: MessageStatus) -> Optional[Message]:
        """Update message status."""
        db_message = self.session.query(DBMessage).filter_by(id=message_id).first()
        if not db_message:
            return None

        db_message.status = status
        self.session.commit()
        return self._convert_db_message(db_message)

    def _convert_db_message(self, db_message: DBMessage) -> Message:
        """Convert DBMessage to Message model."""
        return Message(
            id=db_message.id,
            conversation_id=db_message.conversation_id,
            sender_id=db_message.sender_id,
            recipient_id=db_message.recipient_id,
            content=db_message.content,
            message_type=db_message.message_type,
            status=db_message.status,
            timestamp=db_message.timestamp,
            metadata=db_message.metadata,
        )


def init_db():
    """Initialize the database."""
    Base.metadata.create_all(bind=engine)


# Initialize the database when this module is imported
init_db()
