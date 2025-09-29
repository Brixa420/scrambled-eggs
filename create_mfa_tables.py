"""
Script to create MFA tables in the database.
"""
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = str(Path(__file__).parent.resolve())
sys.path.insert(0, project_root)

from app.db.base import Base, engine
from app.models.two_factor import UserTwoFactor, BackupCode, TwoFactorAttempt

def create_tables():
    """Create all tables defined in the models."""
    print("Creating MFA tables...")
    Base.metadata.create_all(bind=engine, tables=[
        UserTwoFactor.__table__,
        BackupCode.__table__,
        TwoFactorAttempt.__table__
    ])
    print("MFA tables created successfully!")

if __name__ == "__main__":
    create_tables()
