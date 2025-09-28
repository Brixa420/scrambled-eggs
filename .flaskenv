# Flask Application
FLASK_APP=web_app:create_app()
FLASK_ENV=development
SECRET_KEY=dev-secret-key-change-in-production

# Database
DATABASE_URL=sqlite:///app.db
SQLALCHEMY_DATABASE_URI=sqlite:///app.db
SQLALCHEMY_TRACK_MODIFICATIONS=False

# File Uploads
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=16777216  # 16MB

# Security
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600  # 1 hour

# Tor settings
TOR_ENABLED=True
TOR_SOCKS_PORT=9050

# Encryption
ENCRYPTION_KEY=change-this-in-production
KEY_ROTATION_DAYS=90

# Logging
LOG_LEVEL=INFO
LOG_FILE=logs/app.log
TOR_CONTROL_PORT=9051
TOR_PASSWORD=default_tor_password_change_me

# Email settings
MAIL_SERVER=localhost
MAIL_PORT=25
MAIL_USE_TLS=False
MAIL_USE_SSL=False
MAIL_USERNAME=None
MAIL_PASSWORD=None
MAIL_DEFAULT_SENDER=no-reply@scrambled-eggs.local

# Rate limiting
RATELIMIT_DEFAULT=200 per day, 50 per hour

# Session settings
SESSION_COOKIE_SECURE=False
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE='Lazy'
