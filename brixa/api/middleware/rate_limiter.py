""
Rate Limiter Middleware

This module provides rate limiting functionality for the API.
"""
import time
from typing import Dict, Tuple
from fastapi import Request, HTTPException, status
from fastapi.middleware import Middleware
from fastapi.middleware.base import BaseHTTPMiddleware
import logging
import re
from ..config import settings

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter for API endpoints."""
    
    def __init__(self):
        """Initialize the rate limiter."""
        self.rate_limit_config = self._parse_rate_limit(settings.RATE_LIMIT)
        self.requests: Dict[str, Tuple[int, float]] = {}
        
    def _parse_rate_limit(self, rate_limit: str) -> Tuple[int, int]:
        """
        Parse rate limit string (e.g., '100/minute' or '10/second').
        
        Args:
            rate_limit: Rate limit string in format 'number/unit'.
            
        Returns:
            Tuple of (max_requests, time_window_seconds).
            
        Raises:
            ValueError: If the rate limit string is invalid.
        """
        match = re.match(r'(\d+)/(\w+)', rate_limit)
        if not match:
            raise ValueError(f"Invalid rate limit format: {rate_limit}")
            
        max_requests = int(match.group(1))
        unit = match.group(2).lower()
        
        if unit in ('second', 'sec', 's'):
            time_window = 1
        elif unit in ('minute', 'min', 'm'):
            time_window = 60
        elif unit in ('hour', 'hr', 'h'):
            time_window = 3600
        else:
            raise ValueError(f"Unsupported time unit in rate limit: {unit}")
            
        return max_requests, time_window
    
    def is_rate_limited(self, client_id: str) -> Tuple[bool, int]:
        """
        Check if a client has exceeded the rate limit.
        
        Args:
            client_id: Unique identifier for the client.
            
        Returns:
            Tuple of (is_limited, remaining_requests).
        """
        current_time = time.time()
        max_requests, time_window = self.rate_limit_config
        
        if client_id not in self.requests:
            self.requests[client_id] = (1, current_time + time_window)
            return False, max_requests - 1
            
        count, reset_time = self.requests[client_id]
        
        if current_time > reset_time:
            self.requests[client_id] = (1, current_time + time_window)
            return False, max_requests - 1
            
        if count >= max_requests:
            return True, 0
            
        self.requests[client_id] = (count + 1, reset_time)
        return False, max_requests - count - 1

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to enforce rate limiting."""
    
    def __init__(self, app, rate_limiter: RateLimiter):
        """Initialize the middleware."""
        super().__init__(app)
        self.rate_limiter = rate_limiter
    
    async def dispatch(self, request: Request, call_next):
        """Process each request and apply rate limiting."""
        # Skip rate limiting for health check endpoint
        if request.url.path == "/health":
            return await call_next(request)
            
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check rate limit
        is_limited, remaining = self.rate_limiter.is_rate_limited(client_ip)
        
        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.rate_limiter.rate_limit_config[0])
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded",
                headers={"Retry-After": "60"},
            )
            
        return response

def get_rate_limiter() -> RateLimiter:
    """Get a rate limiter instance."""
    return RateLimiter()
