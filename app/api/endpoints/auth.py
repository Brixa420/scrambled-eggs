"""
Authentication and session management API endpoints.
"""
from datetime import timedelta, datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token, get_password_hash
from app.crud import crud_user
from app.db.session import get_db
from app.models.session import Session as SessionModel
from app.models.user import User
from app.schemas.session import Session as SessionSchema, SessionCreate, SessionUpdate
from app.schemas.token import Token, TokenPayload
from app.schemas.user import UserCreate, UserInDB, UserResponse
from app.services.auth import auth_service, two_factor_auth
from app.services.session_service import SessionService
from app.api.deps import get_current_user, get_session_service
from app.utils import (
    generate_password_reset_token,
    send_reset_password_email,
    verify_password_reset_token,
)

router = APIRouter()

@router.post("/register", response_model=UserResponse)
async def register_user(
    *,
    request: Request,
    db: Session = Depends(get_db),
    user_in: UserCreate,
    session_service: SessionService = Depends(get_session_service),
) -> Any:
    """
    Create new user and create initial session.
    """
    # Check if user already exists
    user = crud_user.user.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The user with this email already exists in the system.",
        )
    
    # Create user
    user = crud_user.user.create(db, obj_in=user_in)
    
    # Initialize 2FA settings
    two_factor = two_factor_auth.initialize_user_2fa(db, user.id)
    
    # Create initial session
    user_agent = request.headers.get("user-agent")
    ip_address = request.client.host if request.client else None
    
    session = session_service.create_session(
        user=user,
        user_agent=user_agent,
        ip_address=ip_address,
        remember_me=False
    
    # TODO: Send welcome email with verification link
    
    return user

@router.post("/login", response_model=Dict[str, Any])
async def login(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    session_service: SessionService = Depends(get_session_service),
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    # Authenticate user
    user = auth_service.authenticate(
        db, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "bearer"},
        )
    
    # Check if account is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    
    # Check if 2FA is required
    if user.is_2fa_enabled:
        # Generate a temporary token for 2FA verification
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        token_data = {
            "sub": str(user.id),
            "type": "2fa_required",
            "method": "totp"  # Default method
        }
        access_token = create_access_token(
            data=token_data,
            expires_delta=access_token_expires
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "requires_2fa": True,
            "methods_available": ["totp"],
        }
    
    # If 2FA is not required, create a new session
    remember_me = form_data.scopes and "remember_me" in form_data.scopes
    user_agent = request.headers.get("user-agent")
    ip_address = request.client.host if request.client else None
    
    session = session_service.create_session(
        user=user,
        user_agent=user_agent,
        ip_address=ip_address,
        remember_me=remember_me
    )
    
    # Set secure, HTTP-only cookie
    response.set_cookie(
        key="session_token",
        value=f"Bearer {session.session_token}",
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.SESSION_LIFETIME if remember_me else None,
        expires=session.expires_at if remember_me else None
    )
    
    return {
        "access_token": session.session_token,
        "refresh_token": session.refresh_token,
        "token_type": "bearer",
        "user": user,
        "expires_at": session.expires_at.isoformat(),
    }es_delta=access_token_expires,
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "two_factor_required": False,
    }

@router.post("/verify-2fa")
async def verify_2fa(
    *,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    code: str,
    method: str = "totp",
    current_user: User = Depends(get_current_user),
    session_service: SessionService = Depends(get_session_service),
) -> Any:
    """
    Verify 2FA code and create a new session.
    """
    if not current_user.is_2fa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this account",
        )
    
    # Verify 2FA code
    if not two_factor_auth.verify_2fa_code(db, current_user.id, code, method):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid 2FA code",
        )
    
    # Create a new session
    user_agent = request.headers.get("user-agent")
    ip_address = request.client.host if request.client else None
    
    # Check if this is a remember me request
    remember_me = False
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM]
            )
            remember_me = payload.get("scope", "") == "remember_me"
        except (jwt.JWTError, IndexError):
            pass
    
    session = session_service.create_session(
        user=current_user,
        user_agent=user_agent,
        ip_address=ip_address,
        remember_me=remember_me
    )
    
    # Set secure, HTTP-only cookie
    response.set_cookie(
        key="session_token",
        value=f"Bearer {session.session_token}",
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.SESSION_LIFETIME if remember_me else None,
        expires=session.expires_at if remember_me else None
    )
    
    return {
        "access_token": session.session_token,
        "refresh_token": session.refresh_token,
        "token_type": "bearer",
        "user": current_user,
        "expires_at": session.expires_at.isoformat(),
    }

@router.get("/me", response_model=UserResponse)
def read_user_me(
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Get current user.
    """
    return current_user

@router.post("/password-recovery/{email}")
def recover_password(email: str, db: Session = Depends(get_db)) -> Any:
    """
    Password Recovery
    """
    user = crud_user.user.get_by_email(db, email=email)
    
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    
    password_reset_token = generate_password_reset_token(email=email)
    send_reset_password_email(
        email_to=user.email, email=email, token=password_reset_token
    )
    
    return {"msg": "Password recovery email sent"}

@router.post("/reset-password/")
def reset_password(
    token: str = Body(...),
    new_password: str = Body(...),
    db: Session = Depends(get_db),
) -> Any:
    """
    Reset password
    """
    email = verify_password_reset_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid token")
    
    user = crud_user.user.get_by_email(db, email=email)
    if not user:
        raise HTTPException(
            status_code=404,
            detail="The user with this email does not exist in the system.",
        )
    
    # Update password
    user_in = UserUpdate(password=new_password)
    user = crud_user.user.update(db, db_obj=user, obj_in=user_in)
    
    return {"msg": "Password updated successfully"}
