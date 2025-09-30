"""
Feedback Service

Handles collection, processing, and management of user feedback.
"""
import json
import time
import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union
from pathlib import Path
import sqlite3
from dataclasses import dataclass, asdict, field

class FeedbackType(Enum):
    BUG = "bug"
    FEATURE = "feature"
    GENERAL = "general"
    PERFORMANCE = "performance"
    SECURITY = "security"
    UI_UX = "ui_ux"

class FeedbackStatus(Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    WONT_FIX = "wont_fix"
    DUPLICATE = "duplicate"

@dataclass
class Feedback:
    id: str
    user_id: Optional[str]
    type: FeedbackType
    content: str
    status: FeedbackStatus = FeedbackStatus.OPEN
    metadata: Dict = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict:
        """Convert feedback to dictionary."""
        data = asdict(self)
        data['type'] = self.type.value
        data['status'] = self.status.value
        return data

class FeedbackService:
    def __init__(self, db_path: Optional[str] = None):
        """Initialize feedback service with database path.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path or "~/.brixa/feedback/feedback.db").expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize the feedback database."""
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    type TEXT NOT NULL,
                    content TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            
            # Create indexes
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_feedback_user_id ON feedback(user_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_feedback_status ON feedback(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_feedback_created_at ON feedback(created_at)
            """)
    
    def add_feedback(
        self,
        feedback_type: Union[FeedbackType, str],
        content: str,
        user_id: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> Feedback:
        """Add new feedback.
        
        Args:
            feedback_type: Type of feedback
            content: Feedback content
            user_id: Optional user ID
            metadata: Additional metadata
            
        Returns:
            Created feedback object
        """
        if not content:
            raise ValueError("Feedback content cannot be empty")
            
        if isinstance(feedback_type, str):
            feedback_type = FeedbackType(feedback_type.lower())
            
        feedback = Feedback(
            id=str(uuid.uuid4()),
            user_id=user_id,
            type=feedback_type,
            content=content.strip(),
            metadata=metadata or {}
        )
        
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO feedback 
                (id, user_id, type, content, status, metadata, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    feedback.id,
                    feedback.user_id,
                    feedback.type.value,
                    feedback.content,
                    feedback.status.value,
                    json.dumps(feedback.metadata),
                    feedback.created_at,
                    feedback.updated_at
                )
            )
        
        return feedback
    
    def get_feedback(
        self,
        feedback_id: str
    ) -> Optional[Feedback]:
        """Get feedback by ID.
        
        Args:
            feedback_id: Feedback ID
            
        Returns:
            Feedback object or None if not found
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, user_id, type, content, status, metadata, 
                       created_at, updated_at
                FROM feedback 
                WHERE id = ?
                """,
                (feedback_id,)
            )
            row = cursor.fetchone()
            
            if not row:
                return None
                
            return self._row_to_feedback(row)
    
    def list_feedback(
        self,
        user_id: Optional[str] = None,
        feedback_type: Optional[Union[FeedbackType, str]] = None,
        status: Optional[Union[FeedbackStatus, str]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Feedback]:
        """List feedback with optional filters.
        
        Args:
            user_id: Filter by user ID
            feedback_type: Filter by feedback type
            status: Filter by status
            limit: Maximum number of results
            offset: Pagination offset
            
        Returns:
            List of feedback objects
        """
        query = """
            SELECT id, user_id, type, content, status, metadata, 
                   created_at, updated_at
            FROM feedback
            WHERE 1=1
        """
        params = []
        
        if user_id is not None:
            query += " AND user_id = ?"
            params.append(user_id)
            
        if feedback_type is not None:
            if isinstance(feedback_type, FeedbackType):
                feedback_type = feedback_type.value
            query += " AND type = ?"
            params.append(feedback_type.lower())
            
        if status is not None:
            if isinstance(status, FeedbackStatus):
                status = status.value
            query += " AND status = ?"
            params.append(status.lower())
        
        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return [self._row_to_feedback(row) for row in cursor.fetchall()]
    
    def update_feedback_status(
        self,
        feedback_id: str,
        status: Union[FeedbackStatus, str],
        metadata: Optional[Dict] = None
    ) -> Optional[Feedback]:
        """Update feedback status.
        
        Args:
            feedback_id: Feedback ID
            status: New status
            metadata: Additional metadata to merge
            
        Returns:
            Updated feedback or None if not found
        """
        if isinstance(status, str):
            status = FeedbackStatus(status.lower())
            
        feedback = self.get_feedback(feedback_id)
        if not feedback:
            return None
            
        # Update metadata
        if metadata:
            feedback.metadata.update(metadata)
            
        # Update status and timestamp
        feedback.status = status
        feedback.updated_at = time.time()
        
        with sqlite3.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                UPDATE feedback 
                SET status = ?, metadata = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    feedback.status.value,
                    json.dumps(feedback.metadata),
                    feedback.updated_at,
                    feedback.id
                )
            )
            
        return feedback
    
    def _row_to_feedback(self, row: tuple) -> Feedback:
        """Convert database row to Feedback object."""
        return Feedback(
            id=row[0],
            user_id=row[1],
            type=FeedbackType(row[2]),
            content=row[3],
            status=FeedbackStatus(row[4]),
            metadata=json.loads(row[5]),
            created_at=row[6],
            updated_at=row[7]
        )

    def get_feedback_stats(self) -> Dict:
        """Get feedback statistics.
        
        Returns:
            Dictionary with feedback statistics
        """
        with sqlite3.connect(str(self.db_path)) as conn:
            cursor = conn.cursor()
            
            # Total feedback count
            cursor.execute("SELECT COUNT(*) FROM feedback")
            total = cursor.fetchone()[0]
            
            # Count by type
            cursor.execute("""
                SELECT type, COUNT(*) 
                FROM feedback 
                GROUP BY type
            """)
            by_type = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Count by status
            cursor.execute("""
                SELECT status, COUNT(*) 
                FROM feedback 
                GROUP BY status
            """)
            by_status = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Recent activity
            cursor.execute("""
                SELECT strftime('%Y-%m-%d', created_at, 'unixepoch') as day, 
                       COUNT(*) as count
                FROM feedback
                WHERE created_at >= ?
                GROUP BY day
                ORDER BY day DESC
                LIMIT 30
            """, (time.time() - (30 * 24 * 3600),))
            
            recent_activity = [
                {"date": row[0], "count": row[1]}
                for row in cursor.fetchall()
            ]
            
            return {
                "total": total,
                "by_type": by_type,
                "by_status": by_status,
                "recent_activity": recent_activity
            }
