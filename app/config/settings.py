"""
Application settings for Scrambled Eggs.
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent.parent.parent

# Database settings
SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/scrambled_eggs.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Application settings
DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"
SECRET_KEY = os.getenv("SECRET_KEY", "dev-key-change-in-production")

# P2P Network settings
P2P_ENABLED = os.getenv("P2P_ENABLED", "True") == "True"
P2P_PORT = int(os.getenv("P2P_PORT", "5000"))
P2P_BOOTSTRAP_NODES = os.getenv("P2P_BOOTSTRAP_NODES", "").split(",")
P2P_MAX_PEERS = int(os.getenv("P2P_MAX_PEERS", "10"))

# Tor settings
TOR_ENABLED = os.getenv("TOR_ENABLED", "False") == "True"
TOR_SOCKS_PORT = int(os.getenv("TOR_SOCKS_PORT", "9050"))
TOR_CONTROL_PORT = int(os.getenv("TOR_CONTROL_PORT", "9051"))
TOR_PASSWORD = os.getenv("TOR_PASSWORD", None)

# Server settings
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "5000"))

# Security settings
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "change-this-in-production")
PASSWORD_SALT_ROUNDS = 10

# File upload settings
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size
ALLOWED_EXTENSIONS = {"txt", "pdf", "png", "jpg", "jpeg", "gif", "mp4", "mp3", "zip"}

# Logging settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(BASE_DIR, "logs", "scrambled-eggs.log")

# Ensure upload and log directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
