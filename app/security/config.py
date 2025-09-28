""
Security configuration for the Scrambled Eggs application.
"""
import os
from datetime import timedelta

class SecurityConfig:
    # Session Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_REFRESH_EACH_REQUEST = True
    
    # Password Security
    PASSWORD_HASH_METHOD = 'pbkdf2:sha512'
    PASSWORD_SALT_LENGTH = 32
    PASSWORD_HASH_ITERATIONS = 100000
    
    # Rate Limiting
    RATE_LIMIT_DEFAULT = "200 per day;50 per hour"
    RATE_LIMIT_STRICT = "100 per day;10 per hour"
    RATE_LIMIT_API = "1000 per day;100 per hour"
    
    # CORS Configuration
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '').split(',')
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization']
    
    # Content Security Policy
    CSP_DEFAULT_SRC = ["'self'"]
    CSP_SCRIPT_SRC = ["'self'", "'unsafe-inline'", "'unsafe-eval'"]
    CSP_STYLE_SRC = ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"]
    CSP_IMG_SRC = ["'self'", "data:", "https:']
    CSP_FONT_SRC = ["'self'", "https://cdn.jsdelivr.net"]
    CSP_CONNECT_SRC = ["'self'", "https://api.scrambledeggs.com"]
    
    # Security Headers
    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp'
    }
    
    # Authentication
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', os.urandom(32).hex())
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # API Security
    API_KEY_HEADER = 'X-API-Key'
    API_KEY_LENGTH = 64
    
    # Logging
    SECURITY_LOGGING_LEVEL = 'INFO'
    LOG_SENSITIVE_DATA = False
    
    # Request Validation
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size
    
    # Secure Cookies
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    
    # Security Headers
    @classmethod
    def get_csp_policy(cls):
        """Generate Content Security Policy header."""
        return "; ".join([
            f"default-src {' '.join(cls.CSP_DEFAULT_SRC)}",
            f"script-src {' '.join(cls.CSP_SCRIPT_SRC)}",
            f"style-src {' '.join(cls.CSP_STYLE_SRC)}",
            f"img-src {' '.join(cls.CSP_IMG_SRC)}",
            f"font-src {' '.join(cls.CSP_FONT_SRC)}",
            f"connect-src {' '.join(cls.CSP_CONNECT_SRC)}",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'"
        ])
    
    @classmethod
    def init_app(cls, app):
        """Initialize security configuration with Flask app."""
        # Update app config with security settings
        for key, value in cls.__dict__.items():
            if key.isupper() and not key.startswith('_'):
                app.config[key] = value
        
        # Update CSP header with generated policy
        if 'Content-Security-Policy' not in cls.SECURITY_HEADERS:
            cls.SECURITY_HEADERS['Content-Security-Policy'] = cls.get_csp_policy()
        
        # Ensure required directories exist
        os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'), exist_ok=True)
        
        # Configure logging
        if not app.debug:
            import logging
            from logging.handlers import RotatingFileHandler
            
            # Create logs directory if it doesn't exist
            os.makedirs('logs', exist_ok=True)
            
            # Configure file handler
            file_handler = RotatingFileHandler(
                'logs/security.log',
                maxBytes=10240,
                backupCount=10
            )
            file_handler.setFormatter(logging.Formatter(
                '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
            ))
            file_handler.setLevel(logging.INFO)
            
            # Get security logger
            security_logger = logging.getLogger('security')
            security_logger.addHandler(file_handler)
            security_logger.setLevel(logging.INFO)
            
            # Log security events
            security_logger.info('Security system initialized')
