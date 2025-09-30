"""
Redis configuration and session management.
"""
import json
import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import redis
from fastapi import Request, HTTPException, status
from jose import jwt
from pydantic import BaseModel, Field

from app.core.config import settings

# Initialize Redis connection
redis_client = redis.Redis(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    db=settings.REDIS_DB,
    password=settings.REDIS_PASSWORD or None,
    decode_responses=True,
    ssl=settings.REDIS_SSL
)

class SessionData(BaseModel):
    """Session data model."""
    user_id: int
    ip_address: str
    user_agent: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class SessionManager:
    """Manages user sessions using Redis."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.session_prefix = "session:"
        self.user_sessions_prefix = "user_sessions:"
    
    def _get_session_key(self, session_id: str) -> str:
        """Get the Redis key for a session."""
        return f"{self.session_prefix}{session_id}"
    
    def _get_user_sessions_key(self, user_id: int) -> str:
        """Get the Redis key for a user's sessions set."""
        return f"{self.user_sessions_prefix}{user_id}"

class SessionData(BaseModel):
    """Session data model."""
    user_id: int
    ip_address: str
    user_agent: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }

class SessionManager:
    """Manages user sessions using Redis."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.session_prefix = "session:"
        self.user_sessions_prefix = "user_sessions:"
    
    def _get_session_key(self, session_id: str) -> str:
        """Get the Redis key for a session."""
        return f"{self.session_prefix}{session_id}"
    
    def _get_user_sessions_key(self, user_id: int) -> str:
        """Get the Redis key for a user's sessions set."""
        return f"{self.user_sessions_prefix}{user_id}"
    
    async def create_session(
        self,
        user_id: int,
        request: Request,
        remember_me: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new session for the user.
        
        Args:
            user_id: The ID of the user
            request: The FastAPI request object
            remember_me: Whether to create a long-lived session
            metadata: Additional session metadata
            
        Returns:
            str: The session ID
        """
        # Generate a secure session ID
        session_id = jwt.encode(
            {
                "user_id": user_id,
                "created_at": datetime.utcnow().isoformat(),
                "jti": os.urandom(16).hex()
            },
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
        
        # Get client info
        ip_address = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Create session data
        session_data = SessionData(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
        
        # Calculate session expiration
        expires_in = settings.SESSION_LIFETIME_LONG if remember_me else settings.SESSION_LIFETIME
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Store session in Redis
        session_key = self._get_session_key(session_id)
        user_sessions_key = self._get_user_sessions_key(user_id)
        
        with self.redis.pipeline() as pipe:
            pipe.multi()
            
            # Store session data
            pipe.set(
                session_key,
                session_data.json(),
                ex=expires_in
            )
            
            # Add to user's sessions set
            pipe.sadd(user_sessions_key, session_id)
            pipe.expire(user_sessions_key, expires_in)
            
            # Execute transaction
            pipe.execute()
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Get session data by session ID.
        
        Args:
            session_id: The session ID
            
        Returns:
            Optional[SessionData]: The session data if found, None otherwise
        """
        session_key = self._get_session_key(session_id)
        session_json = self.redis.get(session_key)
        
        if not session_json:
            return None
            
        session_data = SessionData.parse_raw(session_json)
        
        # Update last activity
        session_data.last_activity = datetime.utcnow()
        self.redis.set(
            session_key,
            session_data.json(),
            ex=self.redis.ttl(session_key)  # Keep existing TTL
        )
        
        return session_data
    
    async def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session.
        
        Args:
            session_id: The session ID to revoke
            
        Returns:
            bool: True if the session was revoked, False if not found
        """
        session_key = self._get_session_key(session_id)
        session_json = self.redis.get(session_key)
        
        if not session_json:
            return False
            
        # Get user ID before deleting
        session_data = SessionData.parse_raw(session_json)
        user_sessions_key = self._get_user_sessions_key(session_data.user_id)
        
        with self.redis.pipeline() as pipe:
            pipe.multi()
            
            # Remove session
            pipe.delete(session_key)
            
            # Remove from user's sessions set
            pipe.srem(user_sessions_key, session_id)
            
            pipe.execute()
            
        return True
    
    async def revoke_all_sessions(self, user_id: int, current_session_id: Optional[str] = None) -> int:
        """
        Revoke all sessions for a user.
        
        Args:
            user_id: The user ID
            current_session_id: Optional current session ID to exclude from revocation
            
        Returns:
            int: Number of sessions revoked
        """
        user_sessions_key = self._get_user_sessions_key(user_id)
        session_ids = self.redis.smembers(user_sessions_key)
        
        if not session_ids:
            return 0
            
        # Filter out current session if provided
        if current_session_id:
            session_ids = [sid for sid in session_ids if sid != current_session_id]
            
        if not session_ids:
            return 0
            
        # Delete all sessions
        session_keys = [self._get_session_key(sid) for sid in session_ids]
        
        with self.redis.pipeline() as pipe:
            pipe.multi()
            
            # Delete sessions
            for key in session_keys:
                pipe.delete(key)
                
            # Clear user's sessions set
            pipe.delete(user_sessions_key)
            
            pipe.execute()
            
        return len(session_ids)
    
    async def get_user_sessions(self, user_id: int) -> list[SessionData]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: The user ID
            
        Returns:
            list[SessionData]: List of active sessions
        """
        user_sessions_key = self._get_user_sessions_key(user_id)
        session_ids = self.redis.smembers(user_sessions_key)
        
        sessions = []
        for session_id in session_ids:
            session_data = await self.get_session(session_id)
            if session_data:
                sessions.append(session_data)
                
        return sessions
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Note: Redis will automatically clean up expired keys,
        but this method can be used to clean up the user_sessions sets.
        
        Returns:
            int: Number of sessions cleaned up
        """
        # This is a basic implementation. In production, you might want to use SCAN
        # for large datasets to avoid blocking Redis.
        user_keys = self.redis.keys(f"{self.user_sessions_prefix}*")
        cleaned_up = 0
        
        for key in user_keys:
            session_ids = self.redis.smembers(key)
            valid_sessions = []
            
            for session_id in session_ids:
                if self.redis.exists(self._get_session_key(session_id)):
                    valid_sessions.append(session_id)
            
            # Update the set with only valid sessions
            if len(valid_sessions) < len(session_ids):
                with self.redis.pipeline() as pipe:
                    pipe.multi()
                    pipe.delete(key)
                    if valid_sessions:
                        pipe.sadd(key, *valid_sessions)
                        # Get TTL from the first valid session
                        first_session_key = self._get_session_key(valid_sessions[0])
                        ttl = self.redis.ttl(first_session_key)
                        if ttl > 0:
                            pipe.expire(key, ttl)
                    pipe.execute()
                    
                cleaned_up += (len(session_ids) - len(valid_sessions))
                
        return cleaned_up

# Create a global session manager instance
session_manager = SessionManager(redis_client)
