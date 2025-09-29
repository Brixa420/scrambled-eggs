"""
MFA API Endpoints

Handles all MFA-related API requests.
"""
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app import crud, models, schemas
from app.api import deps
from app.core import security
from app.core.config import settings
from app.core.rate_limiter import mfa_verify_limiter, mfa_setup_limiter, rate_limited
from app.models.user import User
from app.schemas.mfa import (
    BackupCodeResponse,
    MfaDisableRequest,
    MfaSetupRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    MfaVerifyRequest,
    MfaVerifyResponse,
    TwoFactorMethod,
    TwoFactorStatus,
)
from app.services import mfa_service

router = APIRouter()


@router.post("/setup", response_model=MfaSetupResponse)
@rate_limited(mfa_setup_limiter)
async def setup_mfa(
    *,
    db: Session = Depends(deps.get_db),
    request: Request,
    mfa_in: MfaSetupRequest,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Set up multi-factor authentication.
    
    - **method**: The 2FA method to set up (totp or sms)
    - **phone_number**: Required if method is 'sms'
    """
    # Check if MFA is already active
    if current_user.two_factor and current_user.two_factor.status == TwoFactorStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already active for this account",
        )
    
    # Call the MFA service to handle setup
    return mfa_service.MFAService.setup_mfa(
        db=db,
        user=current_user,
        method=mfa_in.method,
        request=request,
        phone_number=mfa_in.phone_number,
    )


@router.post("/verify", response_model=MfaVerifyResponse)
@rate_limited(mfa_verify_limiter)
async def verify_mfa(
    *,
    db: Session = Depends(deps.get_db),
    request: Request,
    mfa_in: MfaVerifyRequest,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Verify MFA setup or login.
    
    - **code**: The verification code from the authenticator app or SMS
    - **method**: The 2FA method to verify (totp, sms, or backup)
    - **device_name**: Optional name for the device (for remember me)
    - **remember_me**: Whether to remember this device for 30 days
    
    Returns:
    - 200: MFA verification successful
    - 400: Invalid verification code
    - 403: Account locked due to too many failed attempts
    - 429: Too many requests (rate limited)
    """
    # Check if account is locked out
    lockout_until = mfa_service.MFAService.check_account_lockout(db, current_user)
    if lockout_until:
        retry_after = int((lockout_until - datetime.utcnow()).total_seconds())
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "message": "Account locked due to too many failed attempts",
                "retry_after": retry_after,
                "remaining_attempts": 0
            },
            headers={"Retry-After": str(retry_after)}
        )
    
    try:
        # Call the MFA service to handle verification
        result = mfa_service.MFAService.verify_mfa(
            db=db,
            user=current_user,
            code=mfa_in.code,
            method=mfa_in.method,
            request=request,
            device_name=mfa_in.device_name,
            remember_me=mfa_in.remember_me,
        )
        
        # Reset failed attempts on successful verification
        mfa_service.MFAService.reset_failed_attempts(db, current_user)
        return result
        
    except HTTPException as e:
        if e.status_code == status.HTTP_400_BAD_REQUEST:
            # Handle failed verification attempt
            is_locked = mfa_service.MFAService.handle_failed_attempt(
                db=db,
                user=current_user,
                method=mfa_in.method,
                code=mfa_in.code,
                request=request
            )
            
            if is_locked:
                lockout_until = mfa_service.MFAService.check_account_lockout(db, current_user)
                retry_after = int((lockout_until - datetime.utcnow()).total_seconds())
                
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "message": "Account locked due to too many failed attempts",
                        "retry_after": retry_after,
                        "remaining_attempts": 0
                    },
                    headers={"Retry-After": str(retry_after)}
                )
            else:
                # Get remaining attempts
                mfa_setup = crud.mfa.get_mfa_setup(db, user_id=current_user.id)
                remaining_attempts = mfa_service.MFAService.MAX_FAILED_ATTEMPTS - mfa_setup.failed_attempts
                
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "message": "Invalid verification code",
                        "remaining_attempts": remaining_attempts
                    }
                )
        raise


@router.get("/status", response_model=MfaStatusResponse)
async def get_mfa_status(
    *,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Get the current MFA status for the authenticated user.
    """
    if not current_user.two_factor:
        return MfaStatusResponse(
            enabled=False,
            methods=[],
            backup_codes=False,
        )
    
    return MudaStatusResponse(
        enabled=current_user.two_factor.status == TwoFactorStatus.ACTIVE,
        methods=current_user.two_factor.get_enabled_methods(),
        backup_codes=any(not code.used for code in current_user.two_factor.backup_codes),
        phone_number=current_user.two_factor.phone_number,
    )


@router.post("/backup-codes", response_model=BackupCodeResponse)
async def regenerate_backup_codes(
    *,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Regenerate backup codes for the authenticated user.
    """
    if not current_user.two_factor or current_user.two_factor.status != TwoFactorStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not active for this account",
        )
    
    return mfa_service.MFAService.regenerate_backup_codes(db=db, user=current_user)


@router.post("/disable")
async def disable_mfa(
    *,
    db: Session = Depends(deps.get_db),
    mfa_in: MfaDisableRequest,
    current_user: models.User = Depends(deps.get_current_active_user),
) -> Any:
    """
    Disable MFA for the authenticated user.
    
    - **password**: User's password for verification
    """
    # Verify password first
    if not security.verify_password(mfa_in.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password",
        )
    
    # Call the MFA service to disable MFA
    mfa_service.MFAService.disable_mfa(db=db, user=current_user)
    
    return {"message": "MFA has been disabled for your account"}
