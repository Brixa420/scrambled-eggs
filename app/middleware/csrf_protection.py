"""
CSRF protection middleware for Flask applications.
"""
import hmac
import hashlib
from flask import request, current_app, session, abort
# Use hmac.compare_digest instead of removed safe_str_cmp
from werkzeug.security import safe_str_cmp as compare_digest

class CSRFProtect:
    """
    CSRF protection implementation for Flask.
    """
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the CSRF protection for the app."""
        app.config.setdefault('WTF_CSRF_ENABLED', True)
        app.config.setdefault('WTF_CSRF_SECRET_KEY', None)
        app.config.setdefault('WTF_CSRF_TIME_LIMIT', 3600)  # 1 hour
        app.config.setdefault('WTF_CSRF_SSL_STRICT', True)
        
        # Generate a CSRF secret key if not provided
        if app.config['WTF_CSRF_SECRET_KEY'] is None:
            app.config['WTF_CSRF_SECRET_KEY'] = os.urandom(24).hex()
        
        # Add CSRF token to Jinja2 globals
        app.jinja_env.globals['csrf_token'] = self._generate_csrf_token
        
        # Add before request handler
        app.before_request(self._csrf_protect)
        
    def _generate_csrf_token(self):
        """Generate a CSRF token and store it in the session."""
        if '_csrf_token' not in session:
            # Generate a new token if one doesn't exist
            session['_csrf_token'] = self._generate_token()
        return session['_csrf_token']
    
    def _generate_token(self):
        """Generate a secure token for CSRF protection."""
        return hmac.new(
            current_app.config['WTF_CSRF_SECRET_KEY'].encode('utf-8'),
            os.urandom(16),
            hashlib.sha256
        ).hexdigest()
    
    def _csrf_protect(self):
        """Protect against CSRF attacks."""
        if not current_app.config.get('WTF_CSRF_ENABLED', True):
            return
        
        # Skip CSRF protection for safe methods
        if request.method in {'GET', 'HEAD', 'OPTIONS', 'TRACE'}:
            return
        
        # Skip CSRF protection for API endpoints that use token auth
        if request.path.startswith('/api/'):
            # Check for API token in headers
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                return
        
        # Get the token from the form data or headers
        token = None
        
        # Check form data first
        if request.is_json:
            token = request.json.get('_csrf_token')
        else:
            token = request.form.get('_csrf_token')
        
        # If not in form data, check headers
        if not token:
            token = request.headers.get('X-CSRFToken')
        
        # Verify the token
        if not token or not self._verify_csrf_token(token):
            current_app.logger.warning('CSRF token is missing or invalid')
            abort(403, 'The CSRF token is missing or invalid.')
    
    def _verify_csrf_token(self, token):
        """Verify a CSRF token."""
        if not token:
            return False
        
        # Get the stored token from the session
        stored_token = session.get('_csrf_token')
        if not stored_token:
            return False
        
        # Compare the tokens in constant time
        return hmac.compare_digest(stored_token, token)

# Create an instance of the CSRF protection
csrf = CSRFProtect()
