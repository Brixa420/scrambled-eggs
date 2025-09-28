"""
Security package for the Scrambled Eggs application.

This package provides security-related functionality including:
- Authentication and authorization
- Password hashing and validation
- Input sanitization
- CSRF protection
- Rate limiting
- Secure file handling
- Multi-factor authentication (MFA)
- Security headers and middleware
- Audit logging
"""
from pathlib import Path
from typing import Optional, Dict, Any
from flask import Flask
import logging
from logging.handlers import RotatingFileHandler

# Import key components for easier access
from .config import get_config, Config, DevelopmentConfig, ProductionConfig, TestingConfig
from .auth import auth_manager, login_required, rate_limit, exempt_from_rate_limit
from .utils import security_utils
from .middleware import security_middleware
from .rate_limiter import rate_limiter_manager
from .audit_log import audit_logger
from .file_utils import file_utils, FileSecurityError
from .password_utils import password_utils, PasswordError, PasswordPolicyError
from .mfa import mfa, MFAError

# Version
__version__ = '1.0.0'

def init_app(app):
    """
    Initialize all security components with the Flask application.
    
    Args:
        app: The Flask application instance
    """
    # Initialize configuration
    app.config.from_object(get_config())
    
    # Initialize components
    security_middleware.init_app(app)
    rate_limiter_manager.init_app(app)
    auth_manager.init_app(app)
    audit_logger.init_app(app)
    
    # Set up logging
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        
        # Ensure the log directory exists
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Configure file handler
        file_handler = RotatingFileHandler(
            log_dir / 'scrambled_eggs.log',
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        
        # Add handlers to the app's logger
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Scrambled Eggs security initialization complete')
    
    return app

# Export commonly used functions and classes
__all__ = [
    # Core
    'get_config', 'Config', 'DevelopmentConfig', 'ProductionConfig', 'TestingConfig',
    'init_app',
    
    # Authentication & Authorization
    'auth_manager', 'login_required', 'rate_limit', 'exempt_from_rate_limit',
    
    # Utilities
    'security_utils', 'security_middleware', 'rate_limiter_manager', 'audit_logger',
    'file_utils', 'FileSecurityError', 'password_utils', 'PasswordError', 'PasswordPolicyError',
    'mfa', 'MFAError',
    
    # Version
    '__version__'
]
