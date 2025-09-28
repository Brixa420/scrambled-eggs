"""
Message Store
------------
Handles storage and retrieval of encrypted chat messages.
"""
import json
import sqlite3
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

@dataclass
class Message:
    """Represents a chat message."""
    message_id: str
    conversation_id: str
    sender_id: str
    recipient_id: str
    content: str  # Encrypted content
    timestamp: float
    is_encrypted: bool = True
    is_delivered: bool = False
    is_read: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the message to a dictionary."""
        return {
            'message_id': self.message_id,
            'conversation_id': self.conversation_id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'content': self.content,
            'timestamp': self.timestamp,
            'is_encrypted': self.is_encrypted,
            'is_delivered': self.is_delivered,
            'is_read': self.is_read,
            'date': datetime.fromtimestamp(self.timestamp).isoformat()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create a Message from a dictionary."""
        return cls(
            message_id=data['message_id'],
            conversation_id=data['conversation_id'],
            sender_id=data['sender_id'],
            recipient_id=data['recipient_id'],
            content=data['content'],
            timestamp=data.get('timestamp', time.time()),
            is_encrypted=data.get('is_encrypted', True),
            is_delivered=data.get('is_delivered', False),
            is_read=data.get('is_read', False)
        )

class MessageStore:
    """Manages storage and retrieval of encrypted chat messages."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize the message store.
        
        Args:
            db_path: Path to the SQLite database file. If None, uses a default path.
        """
        if db_path is None:
            db_dir = Path.home() / '.scrambled_eggs'
            db_dir.mkdir(exist_ok=True, parents=True)
            db_path = str(db_dir / 'messages.db')
        
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Initialize the database tables if they don't exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Create messages table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp REAL NOT NULL,
                is_encrypted INTEGER DEFAULT 1,
                is_delivered INTEGER DEFAULT 0,
                is_read INTEGER DEFAULT 0,
                metadata TEXT
            )
            ''')
            
            # Create indexes for faster lookups
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_conversation 
            ON messages(conversation_id, timestamp)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_sender 
            ON messages(sender_id, timestamp)
            ''')
            
            cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_messages_recipient 
            ON messages(recipient_id, timestamp)
            ''')
            
            conn.commit()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with the right settings."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def add_message(self, message: Message) -> bool:
        """Add a new message to the store.
        
        Args:
            message: The message to add
            
        Returns:
            bool: True if the message was added successfully
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO messages (
                    message_id, conversation_id, sender_id, recipient_id,
                    content, timestamp, is_encrypted, is_delivered, is_read
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    message.message_id,
                    message.conversation_id,
                    message.sender_id,
                    message.recipient_id,
                    message.content,
                    message.timestamp,
                    int(message.is_encrypted),
                    int(message.is_delivered),
                    int(message.is_read)
                ))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.IntegrityError:
            # Message already exists
            return False
        except Exception as e:
            print(f"Error adding message: {e}")
            return False
    
    def get_message(self, message_id: str) -> Optional[Message]:
        """Get a message by its ID.
        
        Args:
            message_id: The ID of the message to retrieve
            
        Returns:
            Optional[Message]: The message if found, None otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM messages WHERE message_id = ?', (message_id,))
            row = cursor.fetchone()
            
            if row:
                return Message(
                    message_id=row['message_id'],
                    conversation_id=row['conversation_id'],
                    sender_id=row['sender_id'],
                    recipient_id=row['recipient_id'],
                    content=row['content'],
                    timestamp=row['timestamp'],
                    is_encrypted=bool(row['is_encrypted']),
                    is_delivered=bool(row['is_delivered']),
                    is_read=bool(row['is_read'])
                )
            return None
    
    def get_conversation_messages(
        self, 
        conversation_id: str, 
        limit: int = 100,
        before: Optional[float] = None,
        after: Optional[float] = None
    ) -> List[Message]:
        """Get messages from a conversation.
        
        Args:
            conversation_id: The ID of the conversation
            limit: Maximum number of messages to return
            before: Only return messages before this timestamp
            after: Only return messages after this timestamp
            
        Returns:
            List[Message]: List of messages in the conversation, ordered by timestamp
        """
        query = '''
        SELECT * FROM messages 
        WHERE conversation_id = ?
        '''
        params = [conversation_id]
        
        if before is not None:
            query += ' AND timestamp < ?'
            params.append(before)
        
        if after is not None:
            query += ' AND timestamp > ?'
            params.append(after)
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            messages = []
            for row in cursor.fetchall():
                messages.append(Message(
                    message_id=row['message_id'],
                    conversation_id=row['conversation_id'],
                    sender_id=row['sender_id'],
                    recipient_id=row['recipient_id'],
                    content=row['content'],
                    timestamp=row['timestamp'],
                    is_encrypted=bool(row['is_encrypted']),
                    is_delivered=bool(row['is_delivered']),
                    is_read=bool(row['is_read'])
                ))
            
            return messages
    
    def mark_delivered(self, message_id: str) -> bool:
        """Mark a message as delivered.
        
        Args:
            message_id: The ID of the message to mark as delivered
            
        Returns:
            bool: True if the message was updated
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE messages 
            SET is_delivered = 1 
            WHERE message_id = ?
            ''', (message_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def mark_read(self, message_id: str) -> bool:
        """Mark a message as read.
        
        Args:
            message_id: The ID of the message to mark as read
            
        Returns:
            bool: True if the message was updated
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            UPDATE messages 
            SET is_read = 1 
            WHERE message_id = ?
            ''', (message_id,))
            conn.commit()
            return cursor.rowcount > 0
    
    def get_unread_count(self, user_id: str) -> int:
        """Get the number of unread messages for a user.
        
        Args:
            user_id: The ID of the user
            
        Returns:
            int: Number of unread messages
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
            SELECT COUNT(*) as count 
            FROM messages 
            WHERE recipient_id = ? AND is_read = 0
            ''', (user_id,))
            return cursor.fetchone()['count']
    
    def get_conversation_summaries(self, user_id: str) -> List[Dict[str, Any]]:
        """Get a summary of all conversations for a user.
        
        Args:
            user_id: The ID of the user
            
        Returns:
            List[Dict]: List of conversation summaries with last message and unread count
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Get the most recent message from each conversation
            cursor.execute('''
            WITH last_messages AS (
                SELECT 
                    conversation_id,
                    MAX(timestamp) as last_message_time
                FROM messages
                WHERE ? IN (sender_id, recipient_id)
                GROUP BY conversation_id
            )
            SELECT 
                m.conversation_id,
                m.sender_id,
                m.recipient_id,
                m.content,
                m.timestamp,
                m.is_read,
                m.is_encrypted,
                (SELECT COUNT(*) 
                 FROM messages 
                 WHERE conversation_id = m.conversation_id 
                 AND recipient_id = ? 
                 AND is_read = 0) as unread_count
            FROM messages m
            JOIN last_messages lm 
                ON m.conversation_id = lm.conversation_id 
                AND m.timestamp = lm.last_message_time
            WHERE ? IN (m.sender_id, m.recipient_id)
            ORDER BY m.timestamp DESC
            ''', (user_id, user_id, user_id))
            
            return [dict(row) for row in cursor.fetchall()]
