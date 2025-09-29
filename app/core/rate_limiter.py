"""
Rate limiting utilities for API endpoints.
"""
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Tuple, Callable, Any

from fastapi import HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool

# In-memory store for rate limiting (replace with Redis in production)
_rate_limit_store: Dict[str, List[datetime]] = {}

class RateLimiter:
    """Rate limiter for API endpoints."""
    
    def __init__(self, times: int, seconds: int, scope: str = "default"):
        """
        Initialize rate limiter.
        
        Args:
            times: Maximum number of requests allowed in the time window
            seconds: Time window in seconds
            scope: Scope for the rate limit (e.g., 'mfa_verify', 'login')
        """
        self.times = times
        self.seconds = seconds
        self.scope = scope
    
    def _get_client_identifier(self, request: Request) -> str:
        """Get a unique identifier for the client (IP + user agent)."""
        client_host = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")
        return f"{self.scope}:{client_host}:{user_agent}"
    
    def _is_rate_limited(self, identifier: str) -> Tuple[bool, Optional[datetime]]:
        """Check if the client is rate limited."""
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=self.seconds)
        
        # Clean up old entries
        if identifier in _rate_limit_store:
            _rate_limit_store[identifier] = [
                t for t in _rate_limit_store[identifier] if t > window_start
            ]
        else:
            _rate_limit_store[identifier] = []
        
        # Check rate limit
        if len(_rate_limit_store[identifier]) >= self.times:
            return True, _rate_limit_store[identifier][0] + timedelta(seconds=self.seconds)
        
        # Add current request timestamp
        _rate_limit_store[identifier].append(now)
        return False, None
    
    async def __call__(self, request: Request):
        """Check rate limit for the current request."""
        identifier = self._get_client_identifier(request)
        is_limited, retry_after = await run_in_threadpool(self._is_rate_limited, identifier)
        
        if is_limited and retry_after:
            retry_seconds = max(1, int((retry_after - datetime.utcnow()).total_seconds()))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": "Too many requests",
                    "retry_after": retry_seconds,
                    "error": "rate_limit_exceeded"
                },
                headers={"Retry-After": str(retry_seconds)}
            )

# Common rate limiters
mfa_verify_limiter = RateLimiter(times=5, seconds=300, scope="mfa_verify")  # 5 attempts per 5 minutes
mfa_setup_limiter = RateLimiter(times=3, seconds=3600, scope="mfa_setup")  # 3 setup attempts per hour

# Decorator for rate limiting
def rate_limited(limiter: RateLimiter):
    """Decorator to apply rate limiting to a route."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            request = kwargs.get("request")
            if not request:
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break
            
            if not request:
                raise ValueError("Request object not found in arguments")
            
            await limiter(request)
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator
