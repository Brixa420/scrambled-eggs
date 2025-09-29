"""
Database Models
--------------
Defines the database models for the P2P messaging system.
"""

import json
import os
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Contact:
    """Represents a contact in the user's address book."""

    id: str
    name: str
    public_key: str
    last_seen: Optional[datetime] = None
    online: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert the contact to a dictionary."""
        result = asdict(self)
        result["last_seen"] = self.last_seen.isoformat() if self.last_seen else None
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Contact":
        """Create a Contact from a dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            public_key=data["public_key"],
            last_seen=datetime.fromisoformat(data["last_seen"]) if data.get("last_seen") else None,
            online=data.get("online", False),
        )


@dataclass
class Message:
    """Represents a message in a conversation."""

    id: str
    conversation_id: str
    sender_id: str
    content: str
    timestamp: datetime
    is_encrypted: bool = True
    is_delivered: bool = False
    is_read: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert the message to a dictionary."""
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat()
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Message":
        """Create a Message from a dictionary."""
        return cls(
            id=data["id"],
            conversation_id=data["conversation_id"],
            sender_id=data["sender_id"],
            content=data["content"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            is_encrypted=data.get("is_encrypted", True),
            is_delivered=data.get("is_delivered", False),
            is_read=data.get("is_read", False),
        )


class Database:
    """Manages the SQLite database for the P2P messaging system."""

    def __init__(self, db_path: str = None):
        """Initialize the database.

        Args:
            db_path: Path to the SQLite database file. If None, uses a default path.
        """
        if db_path is None:
            db_dir = Path.home() / ".scrambled_eggs"
            db_dir.mkdir(exist_ok=True)
            db_path = str(db_dir / "messaging.db")

        self.db_path = db_path
        self.conn = None
        self._setup_database()

    def _setup_database(self):
        """Set up the database tables if they don't exist."""
        self.conn = sqlite3.connect(self.db_path)
        cursor = self.conn.cursor()

        # Create contacts table
        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS contacts (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            public_key TEXT NOT NULL,
            last_seen TEXT,
            online INTEGER DEFAULT 0
        )
        """
        )

        # Create messages table
        cursor.execute(
            """
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            is_encrypted INTEGER DEFAULT 1,
            is_delivered INTEGER DEFAULT 0,
            is_read INTEGER DEFAULT 0,
            FOREIGN KEY (sender_id) REFERENCES contacts(id)
        )
        """
        )

        # Create index for faster lookups
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id)"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)")

        self.conn.commit()

    # Contact methods
    def add_contact(self, contact: Contact) -> bool:
        """Add a new contact to the database."""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
            INSERT INTO contacts (id, name, public_key, last_seen, online)
            VALUES (?, ?, ?, ?, ?)
            """,
                (
                    contact.id,
                    contact.name,
                    contact.public_key,
                    contact.last_seen.isoformat() if contact.last_seen else None,
                    1 if contact.online else 0,
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Contact already exists
            return False

    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """Get a contact by ID."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM contacts WHERE id = ?", (contact_id,))
        row = cursor.fetchone()

        if row:
            return Contact(
                id=row[0],
                name=row[1],
                public_key=row[2],
                last_seen=datetime.fromisoformat(row[3]) if row[3] else None,
                online=bool(row[4]),
            )
        return None

    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts."""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM contacts")
        return [
            Contact(
                id=row[0],
                name=row[1],
                public_key=row[2],
                last_seen=datetime.fromisoformat(row[3]) if row[3] else None,
                online=bool(row[4]),
            )
            for row in cursor.fetchall()
        ]

    def update_contact(self, contact: Contact) -> bool:
        """Update an existing contact."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
        UPDATE contacts 
        SET name = ?, public_key = ?, last_seen = ?, online = ?
        WHERE id = ?
        """,
            (
                contact.name,
                contact.public_key,
                contact.last_seen.isoformat() if contact.last_seen else None,
                1 if contact.online else 0,
                contact.id,
            ),
        )
        self.conn.commit()
        return cursor.rowcount > 0

    def delete_contact(self, contact_id: str) -> bool:
        """Delete a contact by ID."""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM contacts WHERE id = ?", (contact_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    # Message methods
    def add_message(self, message: Message) -> bool:
        """Add a new message to the database."""
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                """
            INSERT INTO messages 
            (id, conversation_id, sender_id, content, timestamp, is_encrypted, is_delivered, is_read)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    message.id,
                    message.conversation_id,
                    message.sender_id,
                    message.content,
                    message.timestamp.isoformat(),
                    1 if message.is_encrypted else 0,
                    1 if message.is_delivered else 0,
                    1 if message.is_read else 0,
                ),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            # Message with this ID already exists
            return False

    def get_messages(
        self, conversation_id: str, limit: int = 100, offset: int = 0
    ) -> List[Message]:
        """Get messages for a conversation."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
        SELECT * FROM messages 
        WHERE conversation_id = ?
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
        """,
            (conversation_id, limit, offset),
        )

        return [
            Message(
                id=row[0],
                conversation_id=row[1],
                sender_id=row[2],
                content=row[3],
                timestamp=datetime.fromisoformat(row[4]),
                is_encrypted=bool(row[5]),
                is_delivered=bool(row[6]),
                is_read=bool(row[7]),
            )
            for row in cursor.fetchall()
        ]

    def mark_messages_as_read(self, conversation_id: str, sender_id: str):
        """Mark messages in a conversation as read."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
        UPDATE messages 
        SET is_read = 1 
        WHERE conversation_id = ? AND sender_id = ? AND is_read = 0
        """,
            (conversation_id, sender_id),
        )
        self.conn.commit()

    def mark_message_delivered(self, message_id: str):
        """Mark a message as delivered."""
        cursor = self.conn.cursor()
        cursor.execute(
            """
        UPDATE messages 
        SET is_delivered = 1 
        WHERE id = ?
        """,
            (message_id,),
        )
        self.conn.commit()

    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()

    def __del__(self):
        """Ensure the database connection is closed when the object is deleted."""
        self.close()
