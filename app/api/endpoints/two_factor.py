"""
Two-Factor Authentication API endpoints.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.session import get_db
from app.models.user import User
from app.schemas.token import (
    TwoFactorSetupResponse,
    TwoFactorStatusResponse,
    TwoFactorVerifyRequest
)
from app.services.auth.two_factor_service import get_two_factor_service

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

@router.get("/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Set up 2FA for the current user.
    
    Returns a TOTP secret and QR code for setting up an authenticator app.
    """
    two_factor_service = get_two_factor_service(db)
    setup_data = two_factor_service.setup_totp(current_user.id)
    
    # Generate backup codes if not already set
    if two_factor_service.get_2fa_status(current_user.id)["backup_codes_remaining"] == 0:
        backup_codes = two_factor_service.generate_backup_codes(current_user.id)
    else:
        backup_codes = []
    
    return {
        "secret": setup_data["secret"],
        "qr_code": setup_data["qr_code"],
        "backup_codes": backup_codes
    }

@router.post("/verify")
async def verify_2fa_setup(
    request: TwoFactorVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify 2FA setup with a TOTP code.
    
    After setting up 2FA, the user must verify their authenticator app
    by providing a valid TOTP code.
    """
    two_factor_service = get_two_factor_service(db)
    
    if not two_factor_service.verify_totp_setup(current_user.id, request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code"
        )
    
    return {"message": "2FA has been successfully enabled"}

@router.post("/enable/sms")
async def enable_sms_2fa(
    phone_number: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enable SMS-based 2FA for the current user.
    
    The user must provide a valid phone number where verification codes will be sent.
    """
    two_factor_service = get_two_factor_service(db)
    
    if not two_factor_service.setup_sms(current_user.id, phone_number):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to enable SMS 2FA"
        )
    
    # Send initial verification code
    two_factor_service.send_sms_code(current_user.id)
    
    return {"message": "SMS 2FA has been enabled. Check your phone for a verification code."}

@router.post("/send-sms")
async def send_sms_code(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Send a new SMS verification code.
    
    This can be used to request a new code if the previous one expired.
    """
    two_factor_service = get_two_factor_service(db)
    
    if not two_factor_service.send_sms_code(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to send SMS code. Make sure you have a valid phone number set up."
        )
    
    return {"message": "SMS code sent successfully"}

@router.post("/verify-sms")
async def verify_sms_code(
    request: TwoFactorVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify an SMS code for 2FA.
    """
    two_factor_service = get_two_factor_service(db)
    
    if not two_factor_service.verify_sms_code(current_user.id, request.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code"
        )
    
    return {"message": "SMS code verified successfully"}

@router.get("/backup-codes", response_model=List[str])
async def get_backup_codes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Generate new backup codes for 2FA.
    
    This will replace any existing backup codes.
    """
    two_factor_service = get_two_factor_service(db)
    return two_factor_service.generate_backup_codes(current_user.id)

@router.get("/status", response_model=TwoFactorStatusResponse)
async def get_2fa_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the 2FA status for the current user.
    
    Returns information about enabled 2FA methods and remaining backup codes.
    """
    two_factor_service = get_two_factor_service(db)
    return two_factor_service.get_2fa_status(current_user.id)

@router.post("/disable")
async def disable_2fa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Disable 2FA for the current user.
    
    This will remove all 2FA settings and backup codes.
    """
    two_factor_service = get_two_factor_service(db)
    
    # Get the user's 2FA settings
    user = db.query(User).filter(User.id == current_user.id).first()
    if not user or not user.two_factor:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this account"
        )
    
    # Delete all 2FA data
    db.delete(user.two_factor)
    db.commit()
    
    return {"message": "2FA has been disabled"}
