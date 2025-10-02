""
Session management service for handling user sessions.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from jose import jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.session import Session as SessionModel
from app.models.user import User

class SessionService:
    """Service for managing user sessions."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_session(
        self,
        user: User,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        remember_me: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SessionModel:
        """
        Create a new session for the user.
        
        Args:
            user: The user to create the session for
            user_agent: The user agent string from the request
            ip_address: The IP address of the client
            remember_me: Whether to create a long-lived session
            metadata: Additional session metadata
            
        Returns:
            Session: The created session
        """
        # Calculate expiration time
        expires_in = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600 if remember_me else settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        # Generate tokens
        access_token = self._create_access_token(user.id, expires_in=expires_in)
        refresh_token = self._create_refresh_token(user.id)
        
        # Create session
        session = SessionModel(
            user_id=user.id,
            session_token=access_token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
            metadata=metadata or {}
        )
        
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        
        return session
    
    def get_session(self, token: str) -> Optional[SessionModel]:
        """
        Get a session by its token.
        
        Args:
            token: The session token
            
        Returns:
            Optional[Session]: The session if found and active, None otherwise
        """
        return self.db.query(SessionModel).filter(
            SessionModel.session_token == token,
            SessionModel.is_active == True,
            SessionModel.expires_at > datetime.utcnow()
        ).first()
    
    def refresh_session(self, refresh_token: str) -> Optional[SessionModel]:
        """
        Refresh an existing session.
        
        Args:
            refresh_token: The refresh token
            
        Returns:
            Optional[Session]: The refreshed session if successful, None otherwise
        """
        try:
            # Verify refresh token
            payload = jwt.decode(
                refresh_token,
                settings.SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            user_id = int(payload.get("sub"))
            
            # Find and validate session
            session = self.db.query(SessionModel).filter(
                SessionModel.refresh_token == refresh_token,
                SessionModel.is_active == True,
                SessionModel.expires_at > datetime.utcnow()
            ).first()
            
            if not session or session.user_id != user_id:
                return None
                
            # Create new tokens
            expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
            new_access_token = self._create_access_token(user_id, expires_in=expires_in)
            
            # Update session
            session.session_token = new_access_token
            session.expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
            
            self.db.commit()
            self.db.refresh(session)
            
            return session
            
        except (jwt.JWTError, ValueError):
            return None
    
    def revoke_session(self, token: str) -> bool:
        """
        Revoke a session by its token.
        
        Args:
            token: The session token to revoke
            
        Returns:
            bool: True if session was found and revoked, False otherwise
        """
        session = self.db.query(SessionModel).filter(
            SessionModel.session_token == token
        ).first()
        
        if not session:
            return False
            
        session.is_active = False
        self.db.commit()
        
        return True
    
    def revoke_all_sessions(self, user_id: int, exclude_token: Optional[str] = None) -> int:
        """
        Revoke all sessions for a user.
        
        Args:
            user_id: The user ID
            exclude_token: Optional session token to exclude from revocation
            
        Returns:
            int: Number of sessions revoked
        """
        query = self.db.query(SessionModel).filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True
        )
        
        if exclude_token:
            query = query.filter(SessionModel.session_token != exclude_token)
            
        sessions = query.all()
        
        for session in sessions:
            session.is_active = False
            
        self.db.commit()
        
        return len(sessions)
    
    def get_user_sessions(self, user_id: int) -> List[SessionModel]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: The user ID
            
        Returns:
            List[Session]: List of active sessions
        """
        return self.db.query(SessionModel).filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True,
            SessionModel.expires_at > datetime.utcnow()
        ).all()
    
    def _create_access_token(self, user_id: int, expires_in: int) -> str:
        """Create an access token."""
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        to_encode = {
            "sub": str(user_id),
            "exp": expires_at,
            "type": "access"
        }
        return jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
    
    def _create_refresh_token(self, user_id: int) -> str:
        """Create a refresh token."""
        expires_in = settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600
        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        to_encode = {
            "sub": str(user_id),
            "exp": expires_at,
            "type": "refresh"
        }
        return jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
