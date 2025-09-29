"""
Enhanced Rate Limiter Module

Implements adaptive rate limiting with IP reputation tracking and abuse prevention.
"""

import logging
import time
from functools import wraps
from typing import Any, Callable, Dict, Optional

from flask import current_app, jsonify, request

from app.extensions import redis_client as redis_client_global

# Create a local reference to the Redis client
redis_client = None


# Initialize Redis client when needed
def get_redis_client():
    global redis_client
    if redis_client is None and redis_client_global is not None:
        redis_client = redis_client_global
    return redis_client


logger = logging.getLogger(__name__)


class IPReputationTracker:
    """Tracks IP reputation and applies security measures."""

    def __init__(self, redis_client=None, prefix: str = "ip_reputation:"):
        self.redis = redis_client or get_redis_client()
        self.prefix = prefix

        if self.redis is None:
            current_app.logger.warning(
                "Redis client not available. Using in-memory storage for IP reputation tracking."
            )
            self.redis = {}
            self._use_dict = True
        else:
            self._use_dict = False

    def get_key(self, ip_address: str) -> str:
        """Generate a Redis key for IP reputation tracking."""
        return f"{self.prefix}{ip_address}"

    async def report_abuse(self, ip_address: str, severity: int = 1) -> None:
        """Report abusive behavior from an IP address."""
        try:
            key = self.get_key(ip_address)
            if self._use_dict:
                if key not in self.redis:
                    self.redis[key] = {}
                self.redis[key]["abuse_score"] = (
                    self.redis.get(key, {}).get("abuse_score", 0) + severity
                )
            else:
                await self.redis.hincrby(key, "abuse_score", amount=severity)
                await self.redis.expire(key, 86400)  # 24 hours TTL
        except Exception as e:
            logger.error(f"Error reporting abuse for {ip_address}: {e}")
            # Fallback to in-memory storage if Redis fails
            if not self._use_dict:
                self._use_dict = True
                self.redis = {}
                await self.report_abuse(ip_address, severity)

    async def get_reputation_score(self, ip_address: str) -> int:
        """Get the abuse score for an IP address."""
        try:
            key = self.get_key(ip_address)
            if self._use_dict:
                return int(self.redis.get(key, {}).get("abuse_score", 0))
            else:
                score = await self.redis.hget(key, "abuse_score")
                return int(score) if score else 0
        except Exception as e:
            logger.error(f"Error getting reputation for {ip_address}: {e}")
            return 0


class RateLimiter:
    """
    Enhanced Rate Limiter with IP reputation tracking and adaptive limits.
    Implements a sliding window rate limiter using Redis.
    """

    def __init__(
        self,
        redis_client,
        prefix: str = "rate_limit:",
        default_limits: Dict[str, Dict[str, int]] = None,
    ):
        """
        Initialize the rate limiter with configuration.

        Args:
            redis_client: Redis client instance
            prefix: Prefix for Redis keys
            default_limits: Default rate limits for different endpoints
        """
        self.redis = redis_client
        self.prefix = prefix
        self.ip_tracker = IPReputationTracker(redis_client)

        # Default rate limits (requests per minute)
        self.default_limits = default_limits or {
            "default": {"requests": 60, "window": 60},
            "login": {"requests": 5, "window": 60},
            "api": {"requests": 100, "window": 60},
            "high_risk": {"requests": 10, "window": 300},
        }

    def get_key(self, identifier: str, endpoint: str) -> str:
        """Generate a Redis key for rate limiting."""
        return f"{self.prefix}{endpoint}:{identifier}"

    def get_limits_for_endpoint(self, endpoint: str) -> Dict[str, int]:
        """Get rate limits for a specific endpoint."""
        # Check for endpoint-specific limits
        for prefix, limits in self.default_limits.items():
            if endpoint.startswith(prefix):
                return limits
        return self.default_limits["default"]

    async def is_rate_limited(
        self,
        identifier: str,
        endpoint: str,
        max_requests: Optional[int] = None,
        window_seconds: Optional[int] = None,
        request_data: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Check if a request should be rate limited with enhanced security.

        Args:
            identifier: Unique identifier for the client (e.g., IP or user ID)
            endpoint: The API endpoint being accessed
            max_requests: Override max requests (if None, uses default for endpoint)
            window_seconds: Override window in seconds (if None, uses default for endpoint)
            request_data: Additional request data for security analysis

        Returns:
            Dict with rate limiting information and security recommendations
        """
        # Get limits for this endpoint
        limits = self.get_limits_for_endpoint(endpoint)
        max_requests = max_requests or limits["requests"]
        window_seconds = window_seconds or limits["window"]

        # Check IP reputation
        abuse_score = await self.ip_tracker.get_reputation_score(identifier)

        # Apply stricter limits for suspicious IPs
        if abuse_score > 5:
            max_requests = max(1, max_requests // 2)
            window_seconds = min(300, window_seconds * 2)  # Longer cooldown

        # Check for suspicious patterns in request data
        if request_data and self._is_suspicious_request(request_data):
            await self.ip_tracker.report_abuse(identifier, severity=2)
            return {
                "limited": True,
                "reason": "suspicious_activity",
                "retry_after": window_seconds,
                "abuse_score": abuse_score + 2,
            }
        key = self.get_key(identifier, endpoint)
        now = int(time.time())

        # Use a pipeline for atomic operations
        async with self.redis.pipeline() as pipe:
            try:
                # Remove timestamps older than the window
                pipe.zremrangebyscore(key, "-inf", now - window_seconds)

                # Get the number of requests in the current window
                pipe.zcard(key)

                # Add the current timestamp
                pipe.zadd(key, {str(now): now})

                # Set expiration on the key
                pipe.expire(key, window_seconds)

                # Execute all commands
                _, request_count, _, _ = await pipe.execute()

                # Check if rate limit is exceeded
                remaining = max(0, max_requests - request_count)
                is_limited = request_count > max_requests

                return is_limited, remaining

            except Exception as e:
                # If Redis fails, fail open (don't block requests)
                print(f"Rate limiter error: {e}")
                return False, max_requests

    def limit(
        self,
        max_requests: int = 100,
        window_seconds: int = 60,
        get_identifier: Optional[Callable[[], str]] = None,
        error_message: str = "Rate limit exceeded",
    ):
        """
        Decorator to rate limit an endpoint.

        Args:
            max_requests: Maximum number of requests allowed in the time window
            window_seconds: Time window in seconds
            get_identifier: Function to get the client identifier (defaults to remote IP)
            error_message: Error message to return when rate limited
        """

        def decorator(f):
            @wraps(f)
            async def wrapped(*args, **kwargs):
                # Get client identifier
                if get_identifier:
                    identifier = get_identifier()
                else:
                    # Default to client IP
                    if request.headers.getlist("X-Forwarded-For"):
                        identifier = request.headers.getlist("X-Forwarded-For")[0].split(",")[0]
                    else:
                        identifier = request.remote_addr or "unknown"

                # Get endpoint from request
                endpoint = request.endpoint or "unknown"

                # Check rate limit
                is_limited, remaining = await self.is_rate_limited(
                    identifier, endpoint, max_requests, window_seconds
                )

                if is_limited:
                    return jsonify({"error": error_message, "retry_after": window_seconds}), 429

                # Add rate limit headers
                response = await f(*args, **kwargs)
                response.headers["X-RateLimit-Limit"] = str(max_requests)
                response.headers["X-RateLimit-Remaining"] = str(remaining)
                response.headers["X-RateLimit-Reset"] = str(int(time.time()) + window_seconds)

                return response

            return wrapped

        return decorator


# Create a global instance with default configuration
rate_limiter = RateLimiter(redis_client)


def rate_limit(max_requests=None, window_seconds=None):
    """
    Decorator for rate limiting Flask routes.

    Args:
        max_requests: Maximum number of requests allowed in the time window
        window_seconds: Time window in seconds

    Example:
        @app.route('/api/endpoint')
        @rate_limit(max_requests=60, window_seconds=60)
        async def my_endpoint():
            return jsonify({"status": "ok"})
    """

    def decorator(f):
        @wraps(f)
        async def wrapped(*args, **kwargs):
            # Get client identifier
            identifier = rate_limiter.get_client_identifier()
            endpoint = request.endpoint or "unknown"

            # Check rate limit
            result = await rate_limiter.is_rate_limited(
                identifier=identifier,
                endpoint=endpoint,
                max_requests=max_requests,
                window_seconds=window_seconds,
                request_data={
                    "method": request.method,
                    "path": request.path,
                    "args": request.args,
                    "json": request.get_json(silent=True) or {},
                },
            )

            if result["limited"]:
                return (
                    jsonify(
                        {
                            "error": "rate_limit_exceeded",
                            "message": "Too many requests",
                            "retry_after": result["retry_after"],
                            "abuse_score": result["abuse_score"],
                        }
                    ),
                    429,
                )

            # Add rate limit headers
            response = await f(*args, **kwargs)
            response.headers["X-RateLimit-Limit"] = str(
                max_requests or rate_limiter.get_limits_for_endpoint(endpoint)["requests"]
            )
            response.headers["X-RateLimit-Remaining"] = str(result["remaining"])
            response.headers["X-RateLimit-Reset"] = str(result["reset"])
            return response

        return wrapped

    return decorator
