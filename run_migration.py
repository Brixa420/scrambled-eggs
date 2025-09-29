""
Script to apply database migrations.
"""
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.resolve())
sys.path.insert(0, project_root)

from alembic.config import Config
from alembic import command
from sqlalchemy import create_engine
from app.db.base import Base
from app.core.config import settings

def run_migrations():
    """Run database migrations."""
    # Create the database engine
    engine = create_engine(settings.SQLALCHEMY_DATABASE_URI)
    
    # Create the migrations table if it doesn't exist
    with engine.connect() as connection:
        # Check if the user_two_factor table exists
        result = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='user_two_factor'"
        ).fetchone()
        
        if result:
            # Check if lockout_until column exists
            columns = [col[1] for col in connection.execute("PRAGMA table_info(user_two_factor)")]
            if 'lockout_until' not in columns:
                # Add the lockout_until column
                print("Adding lockout_until column to user_two_factor table...")
                connection.execute(
                    "ALTER TABLE user_two_factor ADD COLUMN lockout_until DATETIME"
                )
                print("Migration completed successfully!")
            else:
                print("lockout_until column already exists. No migration needed.")
        else:
            print("user_two_factor table does not exist. Creating tables...")
            Base.metadata.create_all(bind=engine)
            print("Database tables created successfully!")

if __name__ == "__main__":
    run_migrations()
