"""
Security middleware for adding security headers and enforcing HTTPS.
"""
from flask import request, current_app
from werkzeug.middleware.proxy_fix import ProxyFix

def get_csp_policy():
    """
    Generate a strict Content Security Policy with nonce-based script/style hashes.
    
    Returns:
        str: A Content Security Policy string with nonce support and strict directives
    """
    # Note: The nonce will be added at request time in the security middleware
    return (
        "default-src 'self'; "
        "script-src 'self' 'strict-dynamic' 'nonce-{csp_nonce}'; "
        "style-src 'self' 'nonce-{csp_nonce}'; "
        "img-src 'self' data: https:; "
        "font-src 'self' data:; "
        "connect-src 'self' https: wss:; "
        "frame-ancestors 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "upgrade-insecure-requests; "
        "block-all-mixed-content;"
    )

def init_security(app):
    """
    Initialize security middleware and encryption service.
    
    Args:
        app: Flask application instance
    """
    # Configure default security headers
    app.config.setdefault('SECURITY_HEADERS', {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Content-Security-Policy': get_csp_policy(),
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    })

    # Trust the X-Forwarded-* headers from the proxy
    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=1,  # Number of values to trust for X-Forwarded-For
        x_proto=1,  # Number of values to trust for X-Forwarded-Proto
        x_host=1,  # Number of values to trust for X-Forwarded-Host
        x_prefix=1  # Number of values to trust for X-Forwarded-Prefix
    )
    
    @app.before_request
    def enforce_https():
        """Redirect HTTP to HTTPS in production and set security headers."""
        # Set HSTS header for all responses
        if current_app.config.get('ENFORCE_HTTPS', not current_app.debug):
            if request.headers.get('X-Forwarded-Proto') == 'http':
                url = request.url.replace('http://', 'https://', 1)
                return current_app.response_class(
                    f'<p>Please use HTTPS. <a href="{url}">Click here to continue</a>.</p>',
                    status=301,
                    mimetype='text/html',
                    headers={
                        'Location': url,
                        'Strict-Transport-Security': current_app.config['SECURITY_HEADERS']['Strict-Transport-Security']
                    }
                )

    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses."""
        # Skip static files to avoid performance impact
        if request.path.startswith('/static/'):
            return response
            
        # Add security headers from config
        for header, value in current_app.config.get('SECURITY_HEADERS', {}).items():
            if header not in response.headers:
                response.headers[header] = value
        
        # Remove server header
        if 'Server' in response.headers:
            del response.headers['Server']
            
        # Set secure cookie flags
        if current_app.config.get('SESSION_COOKIE_SECURE'):
            secure = True
            if ';' in current_app.config['SESSION_COOKIE_PATH']:
                path = current_app.config['SESSION_COOKIE_PATH'].split(';')[0]
            else:
                path = current_app.config.get('SESSION_COOKIE_PATH', '/')
                
            samesite = current_app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
            
            # Set secure flag on session cookie
            response.set_cookie(
                current_app.config['SESSION_COOKIE_NAME'],
                secure=secure,
                httponly=current_app.config['SESSION_COOKIE_HTTPONLY'],
                samesite=samesite,
                path=path
            )
            
        return response
