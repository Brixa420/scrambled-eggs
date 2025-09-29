"""
Simple database setup script for Scrambled Eggs.
"""

import os

from flask import Flask
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# Create a minimal Flask app
app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///app.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

from app.models.contact import Contact
from app.models.encryption_key import EncryptionKey
from app.models.message import Message
from app.models.room import Room

# Import models after db is defined to avoid circular imports
from app.models.user import User


def init_db():
    """Initialize the database."""
    with app.app_context():
        # Create all database tables
        db.create_all()
        print("Database tables created successfully!")


if __name__ == "__main__":
    init_db()
