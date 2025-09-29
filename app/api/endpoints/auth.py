"""
Authentication API endpoints for user registration, login, and 2FA.
"""
from datetime import timedelta
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ...core.config import settings
from ...core.security import create_access_token, get_current_user
from ...crud import crud_user
from ...db.session import get_db
from ...models.user import User
from ...schemas.token import Token, TokenPayload
from ...schemas.user import UserCreate, UserInDB, UserResponse
from ...services.auth import auth_service, two_factor_auth
from ...utils import (
    generate_password_reset_token,
    send_reset_password_email,
    verify_password_reset_token,
)

router = APIRouter()

@router.post("/register", response_model=UserResponse)
def register_user(
    *,
    db: Session = Depends(get_db),
    user_in: UserCreate,
) -> Any:
    """
    Create new user.
    """
    user = crud_user.user.get_by_email(db, email=user_in.email)
    if user:
        raise HTTPException(
            status_code=400,
            detail="The user with this email already exists in the system.",
        )
    
    # Create user
    user = crud_user.user.create(db, obj_in=user_in)
    
    # Initialize 2FA settings
    two_factor = two_factor_auth.initialize_user_2fa(db, user.id)
    
    # TODO: Send welcome email with verification link
    
    return user

@router.post("/login", response_model=Token)
async def login(
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
    """
    OAuth2 compatible token login, get an access token for future requests.
    """
    user = crud_user.user.authenticate(
        db, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not crud_user.user.is_active(user):
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # Check if 2FA is required
    if user.two_factor and user.two_factor.is_active():
        # Generate a 2FA token instead of a full access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_2FA_EXPIRE_MINUTES)
        token_payload = TokenPayload(
            sub=str(user.id),
            two_fa_required=True,
        )
        access_token = create_access_token(
            data=token_payload.dict(),
            expires_delta=access_token_expires,
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "two_factor_required": True,
            "two_factor_methods": user.two_factor.get_enabled_methods(),
        }
    
    # If no 2FA required, generate a full access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token_payload = TokenPayload(
        sub=str(user.id),
        two_fa_required=False,
    )
    access_token = create_access_token(
        data=token_payload.dict(),
        expires_delta=access_token_expires,
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "two_factor_required": False,
    }

@router.post("/login/2fa")
async def verify_2fa(
    *,
    db: Session = Depends(get_db),
    code: str,
    method: str = "totp",
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Verify 2FA code and return a full access token.
    """
    if not current_user.two_factor or not current_user.two_factor.is_active():
        raise HTTPException(
            status_code=400,
            detail="2FA is not enabled for this account",
        )
    
    # Verify the 2FA code
    verified = two_factor_auth.verify_2fa_code(
        db=db,
        user=current_user,
        code=code,
        method=method,
    )
    
    if not verified:
        raise HTTPException(
            status_code=400,
            detail="Invalid verification code",
        )
    
    # Generate a full access token
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    token_payload = TokenPayload(
        sub=str(current_user.id),
        two_fa_verified=True,
    )
    access_token = create_access_token(
        data=token_payload.dict(),
        expires_delta=access_token_expires,
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "two_factor_verified": True,
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
