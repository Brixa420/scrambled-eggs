#!/usr/bin/env python3
"""
Development server for Scrambled Eggs.
"""
import logging
import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))


def create_app():
    """Create and configure the Flask application."""
    from app import create_app as app_factory
    from app.extensions import socketio

    # Create the app
    app = app_factory()

    # Configure for development
    app.config.update(
        DEBUG=True,
        SECRET_KEY="dev-key-change-me",
        SQLALCHEMY_DATABASE_URI="sqlite:///scrambled-eggs.db",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        RATELIMIT_STORAGE_URL="memory://",
    )

    # Initialize SocketIO with the app
    socketio.init_app(app, cors_allowed_origins=[], async_mode="threading")

    return app, socketio


def create_tables(app):
    """Create database tables if they don't exist."""
    from app.extensions import db

    with app.app_context():
        print("Creating database tables...")
        db.create_all()
        print("Database tables created successfully!")


def run_server():
    """Run the development server."""
    app, socketio = create_app()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG)

    # Create database tables if they don't exist
    create_tables(app)

    # Run the application
    print("Starting Scrambled Eggs development server...")
    print("Press Ctrl+C to stop")

    # Run with SocketIO
    socketio.run(app, host="0.0.0.0", port=5000, debug=True, use_reloader=True, log_output=True)


if __name__ == "__main__":
    run_server()
