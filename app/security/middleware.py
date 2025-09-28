""
Security middleware for the application.
"""
import re
from functools import wraps
from flask import request, g, current_app, jsonify
from werkzeug.security import safe_str_cmp
from .auth import AuthError

class SecurityHeadersMiddleware:
    """Middleware to add security-related HTTP headers."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with the Flask app."""
        self.app = app
        app.before_request(self._process_request)
        app.after_request(self._process_response)
        
        # Register error handlers
        @app.errorhandler(400)
        @app.errorhandler(401)
        @app.errorhandler(403)
        @app.errorhandler(404)
        @app.errorhandler(405)
        @app.errorhandler(429)
        @app.errorhandler(500)
        def handle_error(error):
            """Handle errors with proper security headers."""
            response = jsonify({
                'error': error.name.lower().replace(' ', '_'),
                'message': error.description,
                'status': error.code
            })
            response.status_code = error.code
            return self._add_security_headers(response)
    
    def _process_request(self):
        """Process the request for security checks."""
        # Add security context to request
        g.security = {
            'is_secure': request.is_secure,
            'ip': request.remote_addr,
            'user_agent': request.user_agent.string if request.user_agent else None,
            'content_type': request.content_type
        }
        
        # Check for suspicious user agents
        self._check_suspicious_user_agent()
        
        # Check for common attack patterns in request
        self._check_request_security()
    
    def _process_response(self, response):
        """Process the response to add security headers."""
        return self._add_security_headers(response)
    
    def _add_security_headers(self, response):
        """Add security headers to the response."""
        # Get security headers from config
        headers = current_app.config.get('SECURITY_HEADERS', {})
        
        # Add Content Security Policy if not already set
        if 'Content-Security-Policy' not in headers:
            headers['Content-Security-Policy'] = current_app.config.get('CSP_HEADER', "")
        
        # Add headers to response
        for header, value in headers.items():
            if value and header not in response.headers:
                response.headers[header] = value
        
        # Add security headers for API responses
        if request.path.startswith('/api/'):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            # Prevent MIME type sniffing
            if 'Content-Type' in response.headers and 'charset=' not in response.headers['Content-Type']:
                response.headers['Content-Type'] += '; charset=utf-8'
        
        return response
    
    def _check_suspicious_user_agent(self):
        """Check for suspicious user agents."""
        user_agent = g.security.get('user_agent', '').lower()
        if not user_agent:
            return
        
        suspicious_patterns = [
            r'nmap', r'sqlmap', r'nikto', r'nessus', r'openvas', 
            r'w3af', r'nikto', r'paros', r'burpsuite', r'hydra',
            r'medusa', r'nikto', r'wpscan', r'joomscan', r'dirbuster',
            r'gobuster', r'dirb', r'nikto', r'nikto', r'nikto'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent):
                current_app.logger.warning(
                    f"Suspicious user agent detected: {user_agent}",
                    extra={
                        'ip': g.security['ip'],
                        'path': request.path,
                        'method': request.method
                    }
                )
                break
    
    def _check_request_security(self):
        """Check the request for common attack patterns."""
        # Check for SQL injection patterns
        sql_patterns = [
            r'(?i)select\s+.*from',
            r'(?i)insert\s+into',
            r'(?i)update\s+.*set',
            r'(?i)delete\s+from',
            r'(?i)drop\s+table',
            r'(?i)exec\s+\w+',
            r'(?i)union\s+select',
            r'(?i)or\s+1\s*=\s*1',
            r'(?i)--',
            r'(?i)/\*.*\*/'
        ]
        
        # Check path and query parameters
        for value in list(request.args.values()) + [request.path]:
            if not isinstance(value, str):
                continue
                
            for pattern in sql_patterns:
                if re.search(pattern, value):
                    raise AuthError('Suspicious request detected', 400)
        
        # Check request body for JSON data
        if request.is_json:
            import json
            try:
                data = request.get_json()
                # Convert the entire JSON to a string for pattern matching
                data_str = json.dumps(data).lower()
                for pattern in sql_patterns:
                    if re.search(pattern, data_str):
                        raise AuthError('Suspicious request data', 400)
            except Exception:
                # If there's an error parsing JSON, it's not valid JSON
                pass


class CSRFProtection:
    """CSRF protection middleware."""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize CSRF protection with the Flask app."""
        self.app = app
        app.before_request(self._verify_csrf_token)
        app.after_request(self._set_csrf_cookie)
        
        # Add template global for CSRF token
        @app.context_processor
        def inject_csrf_token():
            return dict(csrf_token=self._generate_csrf_token())
    
    def _generate_csrf_token(self):
        """Generate a CSRF token for the current session."""
        if '_csrf_token' not in session:
            session['_csrf_token'] = os.urandom(24).hex()
        return session['_csrf_token']
    
    def _verify_csrf_token(self):
        """Verify the CSRF token for non-GET requests."""
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return
            
        # Skip CSRF check for API routes with proper authentication
        if request.path.startswith('/api/') and 'Authorization' in request.headers:
            return
            
        token = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        if not token or not safe_str_cmp(token, session.get('_csrf_token', '')):
            raise AuthError('Invalid CSRF token', 403)
    
    def _set_csrf_cookie(self, response):
        """Set the CSRF token cookie if it doesn't exist."""
        if not request.cookies.get('XSRF-TOKEN') and '_csrf_token' in session:
            response.set_cookie(
                'XSRF-TOKEN',
                session['_csrf_token'],
                httponly=False,  # Allow JavaScript to read the cookie
                secure=request.is_secure,
                samesite='Strict'
            )
        return response
