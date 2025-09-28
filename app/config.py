"""
Scrambled Eggs - Decentralized Server Configuration

This file contains all configuration settings for the Scrambled Eggs decentralized server.
"""
import os
import secrets
import logging
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# ========== Application Settings ==========
APP_NAME = os.getenv('APP_NAME', 'Scrambled Eggs')
DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
HOST = os.getenv('HOST', '0.0.0.0')
PORT = int(os.getenv('PORT', 5000))

# ========== Security Settings ==========
# Secret keys (generate new ones in production!)
SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', secrets.token_hex(32))
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_hex(32))

# Session settings
SESSION_COOKIE_NAME = 'scrambled_eggs_session'
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = int(os.getenv('SESSION_LIFETIME', 3600))  # 1 hour default

# CSRF Protection
CSRF_ENABLED = os.getenv('CSRF_ENABLED', 'True').lower() == 'true'
CSRF_SECRET_KEY = os.getenv('CSRF_SECRET_KEY', secrets.token_hex(32))

# Rate limiting
RATELIMIT_DEFAULT = os.getenv('RATELIMIT_DEFAULT', '200 per day, 50 per hour')
RATELIMIT_STORAGE_URL = os.getenv('RATELIMIT_STORAGE_URL', 'memory://')

# Security headers
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Content-Security-Policy': "default-src 'self'; "
                              "script-src 'self' 'unsafe-inline' 'unsafe-eval' cdn.jsdelivr.net; "
                              "style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
                              "img-src 'self' data: blob:; "
                              "font-src 'self' cdn.jsdelivr.net; "
                              "connect-src 'self' ws: wss:;"
}

# ========== Database Settings ==========
DATABASE_URI = os.getenv('DATABASE_URI', f'sqlite:///{BASE_DIR}/data/app.db')
DATABASE_POOL_SIZE = int(os.getenv('DATABASE_POOL_SIZE', 5))
DATABASE_MAX_OVERFLOW = int(os.getenv('DATABASE_MAX_OVERFLOW', 10))

# ========== Tor Configuration ==========
TOR_ENABLED = os.getenv('TOR_ENABLED', 'True').lower() == 'true'
TOR_SOCKS_PORT = int(os.getenv('TOR_SOCKS_PORT', '9050'))
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', '9051'))
TOR_PASSWORD = os.getenv('TOR_PASSWORD', secrets.token_hex(16))
TOR_USE_BRIDGES = os.getenv('TOR_USE_BRIDGES', 'False').lower() == 'true'
TOR_BRIDGE_LINES = os.getenv('TOR_BRIDGE_LINES', '').split(';') if os.getenv('TOR_BRIDGE_LINES') else []
TOR_HIDDEN_SERVICE_DIR = os.path.join(BASE_DIR, 'tor', 'hidden_service')
TOR_DATA_DIR = os.path.join(BASE_DIR, 'tor', 'data')

# ========== P2P Network Settings ==========
P2P_ENABLED = os.getenv('P2P_ENABLED', 'True').lower() == 'true'
P2P_PORT = int(os.getenv('P2P_PORT', 0))  # 0 = random port
P2P_BOOTSTRAP_NODES = os.getenv('P2P_BOOTSTRAP_NODES', '').split(',')
P2P_MAX_PEERS = int(os.getenv('P2P_MAX_PEERS', '50'))
P2P_DISCOVERY_INTERVAL = int(os.getenv('P2P_DISCOVERY_INTERVAL', '300'))  # 5 minutes
P2P_USE_DHT = os.getenv('P2P_USE_DHT', 'True').lower() == 'true'
P2P_DHT_BOOTSTRAP_NODES = [
    'router.bittorrent.com:6881',
    'dht.transmissionbt.com:6881',
    'router.utorrent.com:6881'
]

# ========== Storage Settings ==========
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'data', 'uploads')
TEMP_FOLDER = os.path.join(BASE_DIR, 'data', 'temp')
MAX_CONTENT_LENGTH = int(os.getenv('MAX_UPLOAD_SIZE', 16 * 1024 * 1024))  # 16MB default
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'tar', 'gz'}

# ========== Admin Settings ==========
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', secrets.token_hex(16))
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@example.com')

# ========== Email Configuration ==========
# Email server settings
MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
MAIL_PORT = int(os.getenv('MAIL_PORT', '587'))
MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
MAIL_USE_SSL = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
MAIL_USERNAME = os.getenv('MAIL_USERNAME', '')
MAIL_PASSWORD = os.getenv('MAIL_PASSWORD', '')
MAIL_DEFAULT_SENDER = os.getenv('MAIL_DEFAULT_SENDER', f'"{APP_NAME}" <noreply@example.com>')
MAIL_DEBUG = DEBUG
MAIL_SUPPRESS_SEND = os.getenv('MAIL_SUPPRESS_SEND', 'False').lower() == 'true'

# Email content settings
MAIL_APP_NAME = APP_NAME
MAIL_SUPPORT_EMAIL = os.getenv('MAIL_SUPPORT_EMAIL', 'support@example.com')
MAIL_ADMIN_EMAIL = os.getenv('MAIL_ADMIN_EMAIL', 'admin@example.com')
MAIL_FRONTEND_URL = os.getenv('FRONTEND_URL', f'http://{HOST}:{PORT}')

# ========== Tor Configuration ==========
# Tor connection settings
TOR_ENABLED = os.getenv('TOR_ENABLED', 'True').lower() == 'true'
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', '9051'))
TOR_SOCKS_PORT = int(os.getenv('TOR_SOCKS_PORT', '9050'))
TOR_BINARY_PATH = os.path.expanduser(os.getenv('TOR_BINARY_PATH', r'C:\Users\Admin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe'))
TOR_DATA_DIR = Path(os.path.expanduser(os.getenv('TOR_DATA_DIR', '~/.tor/scrambled-eggs')))

# Tor circuit settings
TOR_CIRCUIT_TIMEOUT = int(os.getenv('TOR_CIRCUIT_TIMEOUT', '600'))  # 10 minutes
TOR_MAX_CIRCUIT_DIRTINESS = int(os.getenv('TOR_MAX_CIRCUIT_DIRTINESS', '3600'))  # 1 hour
TOR_MAX_CIRCUITS_PER_PURPOSE = int(os.getenv('TOR_MAX_CIRCUITS_PER_PURPOSE', '3'))

# Tor connection retry settings
TOR_CONNECTION_RETRIES = int(os.getenv('TOR_CONNECTION_RETRIES', '3'))
TOR_RETRY_DELAY = int(os.getenv('TOR_RETRY_DELAY', '2'))  # seconds

# Email rate limiting
MAIL_RATE_LIMIT = os.getenv('MAIL_RATE_LIMIT', '100 per day, 10 per hour')

# ========== Monitoring & Alerts ==========
MONITORING_ENABLED = os.getenv('MONITORING_ENABLED', 'True').lower() == 'true'
METRICS_ENABLED = os.getenv('METRICS_ENABLED', 'True').lower() == 'true'
SENTRY_DSN = os.getenv('SENTRY_DSN', '')

# Alert settings
ALERT_EMAIL = os.getenv('ALERT_EMAIL', '')
ALERT_SLACK_WEBHOOK = os.getenv('ALERT_SLACK_WEBHOOK', '')
ALERT_TELEGRAM_BOT_TOKEN = os.getenv('ALERT_TELEGRAM_BOT_TOKEN', '')
ALERT_TELEGRAM_CHAT_ID = os.getenv('ALERT_TELEGRAM_CHAT_ID', '')

# ========== Backup Settings ==========
BACKUP_ENABLED = os.getenv('BACKUP_ENABLED', 'True').lower() == 'true'
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
BACKUP_RETENTION_DAYS = int(os.getenv('BACKUP_RETENTION_DAYS', '7'))
BACKUP_SCHEDULE = os.getenv('BACKUP_SCHEDULE', '0 3 * * *')  # Daily at 3 AM

# ========== Plugin System ==========
PLUGINS_ENABLED = os.getenv('PLUGINS_ENABLED', 'True').lower() == 'true'
PLUGINS_DIR = os.path.join(BASE_DIR, 'plugins')

# ========== Ensure Required Directories Exist ==========
for directory in [UPLOAD_FOLDER, TEMP_FOLDER, BACKUP_DIR, TOR_HIDDEN_SERVICE_DIR, TOR_DATA_DIR, PLUGINS_DIR]:
    os.makedirs(directory, exist_ok=True, mode=0o700)

# ========== Logging Configuration ==========
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_LEVEL = getattr(logging, LOG_LEVEL, logging.INFO)

logging.basicConfig(
    level=LOG_LEVEL,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(BASE_DIR, 'logs', 'scrambled-eggs.log'))
    ]
)

# Suppress overly verbose logs
logging.getLogger('urllib3').setLevel(logging.WARNING)
logging.getLogger('stem').setLevel(logging.WARNING)
logging.getLogger('PIL').setLevel(logging.WARNING)

# ========== Feature Flags ==========
FEATURE_P2P = os.getenv('FEATURE_P2P', 'True').lower() == 'true'
FEATURE_TOR = os.getenv('FEATURE_TOR', 'True').lower() == 'true'
FEATURE_WEBRTC = os.getenv('FEATURE_WEBRTC', 'True').lower() == 'true'
FEATURE_ENCRYPTED_STORAGE = os.getenv('FEATURE_ENCRYPTED_STORAGE', 'True').lower() == 'true'

# ========== Version Information ==========
VERSION = '1.0.0'
BUILD_NUMBER = os.getenv('BUILD_NUMBER', 'dev')
COMMIT_HASH = os.getenv('COMMIT_HASH', 'unknown')
