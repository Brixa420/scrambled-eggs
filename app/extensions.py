"""
Flask extensions.
"""
import os
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail
from flask_assets import Environment
from flask_wtf.csrf import CSRFProtect

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
socketio = SocketIO()
migrate = Migrate()
bootstrap = Bootstrap()
csrf = CSRFProtect()
mail = Mail()
assets = Environment()

# Rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Configure login manager
login_manager.login_view = 'main.login'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'

def init_extensions(app):
    """Initialize Flask extensions with the application."""
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(
        app, 
        cors_allowed_origins=[],
        message_queue=app.config.get('REDIS_URL') or None,
        async_mode=app.config.get('SOCKETIO_ASYNC_MODE', 'eventlet')
    )
    migrate.init_app(app, db)
    bootstrap.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    
    # Configure email settings
    if app.config.get('MAIL_SUPPRESS_SEND'):
        app.logger.warning('Email sending is suppressed (MAIL_SUPPRESS_SEND=True)')
    else:
        app.logger.info(f'Email server configured: {app.config.get("MAIL_SERVER")}:{app.config.get("MAIL_PORT")}')
    
    limiter.init_app(app)
    assets.init_app(app)
    
    # Configure upload folder
    app.config['UPLOAD_FOLDER'] = app.config.get('UPLOAD_FOLDER', 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    # Configure session
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 1 day in seconds
    
    # Configure CSRF
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour
    
    return app
