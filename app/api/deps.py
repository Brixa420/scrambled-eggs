"""Dependencies for FastAPI endpoints."""
from typing import Generator, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.models import User, Session as SessionModel
from app.services.session_service import SessionService

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

def get_db() -> Generator:
    """Get database session."""
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """
    Get the current user from the token.
    
    Args:
        db: Database session
        token: OAuth2 token from the Authorization header
        
    Returns:
        User: The authenticated user
        
    Raises:
        HTTPException: If the token is invalid or the user doesn't exist
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Verify token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM]
        )
        
        # Check token type
        if payload.get("type") != "access":
            raise credentials_exception
            
        # Get user ID from token
        user_id = payload.get("sub")
        if not user_id:
            raise credentials_exception
            
        # Get session from database
        session_service = SessionService(db)
        session = session_service.get_session(token)
        if not session:
            raise credentials_exception
            
        # Get user from database
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return user
        
    except (jwt.JWTError, ValidationError):
        raise credentials_exception

def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get the current active user.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        User: The active user
        
    Raises:
        HTTPException: If the user is inactive
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def get_current_active_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Get the current active superuser.
    
    Args:
        current_user: The current authenticated user
        
    Returns:
        User: The active superuser
        
    Raises:
        HTTPException: If the user is not a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user doesn't have enough privileges"
        )
    return current_user

def get_session_service(
    db: Session = Depends(get_db)
) -> SessionService:
    """
    Get a session service instance.
    
    Args:
        db: Database session
        
    Returns:
        SessionService: A session service instance
    """
    return SessionService(db)
