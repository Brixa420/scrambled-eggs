import os
import time
from collections import defaultdict, deque
from functools import wraps

import redis
from flask import jsonify, request


class RateLimiter:
    def __init__(self, redis_url=None):
        self.redis = redis.Redis.from_url(redis_url) if redis_url else None
        # In-memory storage if Redis is not available (for development)
        self.local_storage = defaultdict(deque)
        self.use_redis = bool(redis_url)

    def limit(self, requests=100, window=60, key_func=None):
        """
        Decorator to rate limit API endpoints.

        Args:
            requests: Number of requests allowed per window
            window: Time window in seconds
            key_func: Function to generate a unique key for rate limiting
                     (default: uses client IP)
        """

        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                # Get client IP by default, or use custom key function
                if key_func:
                    identifier = key_func()
                else:
                    identifier = request.remote_addr or "unknown"

                key = f"rate_limit:{request.endpoint}:{identifier}"
                current_time = time.time()

                if self.use_redis:
                    try:
                        # Use Redis for rate limiting in production
                        with self.redis.pipeline() as pipe:
                            pipe.zremrangebyscore(key, 0, current_time - window)
                            pipe.zcard(key)
                            pipe.zadd(key, {str(current_time): current_time})
                            pipe.expire(key, window)
                            results = pipe.execute()

                        request_count = results[1]

                        if request_count > requests:
                            return (
                                jsonify(
                                    {
                                        "error": "Too many requests",
                                        "status_code": 429,
                                        "message": f"Rate limit exceeded. {requests} requests per {window} seconds allowed.",
                                    }
                                ),
                                429,
                            )

                    except redis.RedisError:
                        # Fallback to in-memory rate limiting if Redis fails
                        pass

                # In-memory rate limiting (for development or fallback)
                timestamps = self.local_storage[key]

                # Remove timestamps outside the current window
                while timestamps and timestamps[0] <= current_time - window:
                    timestamps.popleft()

                if len(timestamps) >= requests:
                    return (
                        jsonify(
                            {
                                "error": "Too many requests",
                                "status_code": 429,
                                "message": f"Rate limit exceeded. {requests} requests per {window} seconds allowed.",
                            }
                        ),
                        429,
                    )

                timestamps.append(current_time)
                self.local_storage[key] = timestamps

                return f(*args, **kwargs)

            return wrapped

        return decorator


# Initialize rate limiter with Redis URL from environment variables
rate_limiter = RateLimiter(redis_url=os.getenv("REDIS_URL"))
