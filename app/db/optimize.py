"""
Database optimization utilities for Scrambled Eggs.

This module provides functions to optimize database performance,
including index creation, query optimization, and caching setup.
"""
from typing import List, Optional
from sqlalchemy import text, Index, inspect
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger(__name__)

class DatabaseOptimizer:
    """Handles database optimization tasks."""
    
    def __init__(self, engine: Engine):
        """Initialize with a SQLAlchemy engine."""
        self.engine = engine
    
    def create_indexes(self) -> None:
        """Create recommended indexes for better query performance."""
        indexes = [
            # Message table indexes
            "CREATE INDEX IF NOT EXISTS idx_messages_conversation_timestamp ON messages(conversation_id, timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_messages_sender_recipient ON messages(sender_id, recipient_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_status ON messages(status)",
            
            # Contact table indexes
            "CREATE INDEX IF NOT EXISTS idx_contacts_user_contact ON contacts(user_id, contact_id)",
            "CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status)",
        ]
        
        with self.engine.connect() as conn:
            for idx in indexes:
                try:
                    conn.execute(text(idx))
                    conn.commit()
                    logger.info(f"Created index: {idx}")
                except Exception as e:
                    logger.error(f"Error creating index {idx}: {e}")
    
    def analyze_tables(self) -> None:
        """Run ANALYZE on all tables to update statistics."""
        with self.engine.connect() as conn:
            inspector = inspect(self.engine)
            for table_name in inspector.get_table_names():
                try:
                    conn.execute(text(f"ANALYZE {table_name}"))
                    conn.commit()
                    logger.info(f"Analyzed table: {table_name}")
                except Exception as e:
                    logger.error(f"Error analyzing table {table_name}: {e}")
    
    def optimize_queries(self) -> None:
        """Optimize common queries."""
        optimizations = [
            "PRAGMA journal_mode=WAL",  # Better concurrency
            "PRAGMA synchronous=NORMAL",  # Balance between safety and speed
            "PRAGMA cache_size=-2000",  # Use up to 2MB of memory for cache
            "PRAGMA temp_store=MEMORY",  # Store temp tables in memory
        ]
        
        with self.engine.connect() as conn:
            for opt in optimizations:
                try:
                    conn.execute(text(opt))
                    conn.commit()
                    logger.info(f"Applied optimization: {opt}")
                except Exception as e:
                    logger.error(f"Error applying optimization {opt}: {e}")


def setup_caching(session: Session) -> None:
    """Set up caching for frequently accessed data."""
    from sqlalchemy.orm import scoped_session, sessionmaker
    from sqlalchemy.orm.query import Query
    from functools import wraps
    import hashlib
    import pickle
    
    # Simple in-memory cache (replace with Redis in production)
    _cache = {}
    
    class CachingQuery(Query):
        """Custom Query class with caching support."""
        
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._cache_key = None
        
        def cache_key(self, key: str) -> 'CachingQuery':
            """Set the cache key for this query."""
            self._cache_key = key
            return self
        
        def all(self):
            """Override all() to use cache when possible."""
            if self._cache_key:
                cache_key = f"{self._cache_key}:{self.statement.compile()}"
                cache_key = hashlib.md5(cache_key.encode()).hexdigest()
                
                if cache_key in _cache:
                    return _cache[cache_key]
                
                result = super().all()
                _cache[cache_key] = result
                return result
            return super().all()
    
    # Configure the session to use our custom query class
    session_factory = sessionmaker(bind=session.bind, class_=CachingQuery)
    return scoped_session(session_factory)

def optimize_database() -> None:
    """Run all database optimizations."""
    from .database import engine, SessionLocal
    
    logger.info("Starting database optimization...")
    
    # Initialize optimizer
    optimizer = DatabaseOptimizer(engine)
    
    # Run optimizations
    optimizer.create_indexes()
    optimizer.analyze_tables()
    optimizer.optimize_queries()
    
    # Set up caching
    session = SessionLocal()
    try:
        setup_caching(session)
        logger.info("Database optimization completed successfully")
    except Exception as e:
        logger.error(f"Error during database optimization: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    optimize_database()
