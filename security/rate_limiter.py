"""Rate limiting for the application."""
import time
from functools import wraps
from typing import Callable, Optional, Dict, Any, Union, Tuple, List

from flask import request, jsonify, g, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from .utils import security_utils
from .config import get_config

# Initialize config
config = get_config()

# Initialize rate limiter
rate_limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[config.RATELIMIT_DEFAULT],
    storage_uri="memory://",  # In production, use Redis or another persistent storage
    strategy=config.RATELIMIT_STRATEGY,
    headers_enabled=True,
    storage_options={"socket_connect_timeout": 30},
    swallow_errors=True,
    key_prefix="scrambled_eggs_limiter"
)

class RateLimiter:
    """Rate limiting manager for the application."""
    
    def __init__(self, app=None):
        """Initialize the rate limiter."""
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the rate limiter with the Flask app."""
        # Configure rate limiter
        rate_limiter.init_app(app)
        
        # Register error handler for rate limit exceeded
        @app.errorhandler(429)
        def ratelimit_handler(e):
            return jsonify({
                'status': 'error',
                'message': 'Rate limit exceeded',
                'code': 'rate_limit_exceeded',
                'detail': str(e.description)
            }), 429
        
        # Add rate limit information to the response headers
        @app.after_request
        def inject_rate_limit_headers(response):
            if not hasattr(g, 'rate_limit'):
                return response
                
            # Add rate limit headers
            rate_limit = g.rate_limit
            response.headers['X-RateLimit-Limit'] = rate_limit.limit
            response.headers['X-RateLimit-Remaining'] = rate_limit.remaining
            response.headers['X-RateLimit-Reset'] = rate_limit.reset_at
            response.headers['X-RateLimit-Reset-Timestamp'] = rate_limit.reset_at * 1000  # JS timestamp in ms
            response.headers['X-RateLimit-Reset-Human'] = time.strftime(
                '%Y-%m-%dT%H:%M:%SZ',
                time.gmtime(rate_limit.reset_at)
            )
            
            return response
    
    @staticmethod
    def limit(limit_value: str, key_func: Optional[Callable] = None, **kwargs):
        """
        Decorator to rate limit a route.
        
        Args:
            limit_value: Rate limit string (e.g., '100 per day')
            key_func: Function to generate a key for rate limiting (defaults to remote address)
            **kwargs: Additional arguments to pass to the rate limiter
            
        Returns:
            Decorated function
        """
        if key_func is None:
            key_func = get_remote_address
        
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                # Apply rate limiting
                with rate_limiter.limit(limit_value, key_func=key_func, **kwargs):
                    return f(*args, **kwargs)
            return wrapper
        return decorator
    
    @staticmethod
    def exempt(f):
        """Exempt a route from rate limiting."""
        f._rate_limit_exempt = True
        return f
    
    @staticmethod
    def is_exempt(view_name: str) -> bool:
        """Check if a view is exempt from rate limiting."""
        view_func = current_app.view_functions.get(view_name)
        return hasattr(view_func, '_rate_limit_exempt')
    
    @staticmethod
    def get_rate_limit_headers() -> Dict[str, str]:
        """Get the rate limit headers for the current request."""
        if not hasattr(g, 'rate_limit'):
            return {}
            
        rate_limit = g.rate_limit
        return {
            'X-RateLimit-Limit': rate_limit.limit,
            'X-RateLimit-Remaining': rate_limit.remaining,
            'X-RateLimit-Reset': rate_limit.reset_at,
            'X-RateLimit-Reset-Timestamp': rate_limit.reset_at * 1000,  # JS timestamp in ms
            'X-RateLimit-Reset-Human': time.strftime(
                '%Y-%m-%dT%H:%M:%SZ',
                time.gmtime(rate_limit.reset_at)
            )
        }


# Create an instance for easy importing
rate_limiter_manager = RateLimiter()

# Rate limit decorators
rate_limit = rate_limiter.limit
exempt_from_rate_limit = RateLimiter.exempt
