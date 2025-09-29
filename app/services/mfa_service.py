"""
Multi-Factor Authentication Service

Handles all MFA-related operations including TOTP setup, verification, and backup codes.
"""
import base64
import os
import pyotp
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.two_factor import (
    BackupCode,
    TwoFactorAttempt,
    TwoFactorMethod,
    TwoFactorStatus,
    UserTwoFactor,
)
from app.models.user import User
from app.schemas.mfa import (
    MfaSetupRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    MfaVerifyResponse,
    BackupCodeResponse,
)


class MFAService:
    """Service for handling Multi-Factor Authentication operations."""
    
    # Lockout settings
    MAX_FAILED_ATTEMPTS = 5  # Max failed attempts before lockout
    LOCKOUT_MINUTES = 15     # Lockout duration in minutes
    FAILED_ATTEMPT_WINDOW = 5  # Time window for counting failed attempts (minutes)

    @staticmethod
    def generate_totp_secret() -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        """Generate the provisioning URI for the TOTP secret."""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=email, issuer_name=settings.APP_NAME
        )

    @staticmethod
    def verify_totp_code(secret: str, code: str) -> bool:
        """Verify a TOTP code."""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    @staticmethod
    def generate_backup_codes(count: int = 10) -> List[Tuple[str, str]]:
        """Generate backup codes.
        
        Returns a list of tuples containing (code, hashed_code).
        """
        codes = []
        for _ in range(count):
            # Generate a random 8-character alphanumeric code with dashes for readability
            import random
            import string
            code = "".join(
                random.choices(
                    string.ascii_uppercase + string.digits, k=8
                )
            )
            code = f"{code[:4]}-{code[4:]}"  # Format as XXXX-XXXX
            hashed_code = get_password_hash(code)
            codes.append((code, hashed_code))
        return codes

    @classmethod
    def setup_mfa(
        cls, db: Session, user: User, method: TwoFactorMethod, request: MfaSetupRequest
    ) -> MfaSetupResponse:
        """Set up MFA for a user."""
        # Check if user already has 2FA configured
        two_factor = (
            db.query(UserTwoFactor)
            .filter(UserTwoFactor.user_id == user.id)
            .first()
        )

        if not two_factor:
            two_factor = UserTwoFactor(user_id=user.id)
            db.add(two_factor)

        if method == TwoFactorMethod.TOTP:
            # Generate new TOTP secret if not provided (initial setup)
            if not two_factor.totp_secret:
                two_factor.totp_secret = cls.generate_totp_secret()
                two_factor.totp_enabled = False  # Will be enabled after verification
                db.commit()

            # Generate provisioning URI for the authenticator app
            provisioning_uri = cls.get_totp_uri(two_factor.totp_secret, user.email)
            
            return MfaSetupResponse(
                method=TwoFactorMethod.TOTP,
                status=two_factor.status,
                secret=two_factor.totp_secret,
                provisioning_uri=provisioning_uri,
                qr_code_url=f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={provisioning_uri}",
            )
        
        elif method == TwoFactorMethod.SMS:
            # For SMS, we need a phone number
            if not request.phone_number:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Phone number is required for SMS 2FA",
                )
            
            # In a real app, you would send an SMS with a verification code here
            two_factor.phone_number = request.phone_number
            two_factor.sms_enabled = False  # Will be enabled after verification
            two_factor.status = TwoFactorStatus.PENDING
            db.commit()
            
            return MfaSetupResponse(
                method=TwoFactorMethod.SMS,
                status=two_factor.status,
                phone_number=two_factor.phone_number,
            )
        
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported 2FA method: {method}",
            )

    @classmethod
    def check_account_lockout(cls, db: Session, user: User) -> Optional[datetime]:
        """Check if the account is locked out and return lockout expiration if so."""
        if not user.two_factor:
            return None
            
        # Check if account is locked
        if user.two_factor.status == TwoFactorStatus.LOCKED:
            # Check if lockout period has expired
            lockout_expires = user.two_factor.lockout_until
            if lockout_expires and lockout_expires > datetime.utcnow():
                return lockout_expires
            else:
                # Reset lockout if expired
                user.two_factor.status = TwoFactorStatus.ACTIVE
                user.two_factor.failed_attempts = 0
                user.two_factor.lockout_until = None
                db.commit()
                return None
        return None
    
    @classmethod
    def handle_failed_attempt(cls, db: Session, user: User, method: str, code: str, request: Request) -> Tuple[bool, Optional[datetime]]:
        """Handle a failed MFA attempt and return whether the account is now locked."""
        if not user.two_factor:
            return False, None
            
        # Record the failed attempt
        attempt = TwoFactorAttempt(
            user_id=user.id,
            method=method,
            code=code,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            success=False,
            created_at=datetime.utcnow()
        )
        db.add(attempt)
        
        # Update failed attempts counter
        user.two_factor.failed_attempts += 1
        
        # Check if we should lock the account
        if user.two_factor.failed_attempts >= cls.MAX_FAILED_ATTEMPTS:
            lockout_until = datetime.utcnow() + timedelta(minutes=cls.LOCKOUT_MINUTES)
            user.two_factor.status = TwoFactorStatus.LOCKED
            user.two_factor.lockout_until = lockout_until
            db.commit()
            return True, lockout_until
            
        db.commit()
        return False, None
    
    @classmethod
    def reset_failed_attempts(cls, db: Session, user: User) -> None:
        """Reset failed attempts counter after successful verification."""
        if user.two_factor and user.two_factor.failed_attempts > 0:
            user.two_factor.failed_attempts = 0
            user.two_factor.lockout_until = None
            db.commit()
    
    @classmethod
    def verify_mfa(
        cls, db: Session, user: User, method: TwoFactorMethod, request: MfaVerifyRequest
    ) -> MfaVerifyResponse:
        """Verify MFA setup or login attempt."""
        two_factor = (
            db.query(UserTwoFactor)
            .filter(UserTwoFactor.user_id == user.id)
            .first()
        )

        if not two_factor:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is not set up for this user",
            )

        # Check for too many failed attempts
        if two_factor.failed_attempts >= settings.MFA_MAX_ATTEMPTS:
            two_factor.status = TwoFactorStatus.LOCKED
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed attempts. Account temporarily locked.",
            )

        # Verify the code based on the method
        try:
            if method == TwoFactorMethod.TOTP:
                if not user.two_factor.totp_secret:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="TOTP is not set up for this account",
        
        elif method == TwoFactorMethod.BACKUP:
            # Check backup codes
            backup_code = (
                db.query(BackupCode)
                .filter(
                    BackupCode.user_two_factor_id == two_factor.id,
                    BackupCode.used == False,
                )
                .first()
            )
            
            if backup_code:
                # In a real app, you would verify the hashed code
                # For now, we'll just check if the code exists
                is_valid = True
                backup_code.used = True
                backup_code.used_at = datetime.utcnow()
                db.add(backup_code)
        
        # Update attempt tracking
        attempt = TwoFactorAttempt(
            user_id=user.id,
            method=method,
            code=request.code,
            ip_address=request.client_host,
            user_agent=request.user_agent,
            success=is_valid,
        )
        db.add(attempt)
        
        if is_valid:
            two_factor.failed_attempts = 0
            two_factor.last_verified = datetime.utcnow()
            two_factor.updated_at = datetime.utcnow()
            
            # If this was a setup verification, generate backup codes if not already present
            if method in [TwoFactorMethod.TOTP, TwoFactorMethod.SMS] and not two_factor.backup_codes:
                backup_codes = cls.generate_backup_codes()
                for code, hashed_code in backup_codes:
                    backup_code = BackupCode(
                        user_two_factor_id=two_factor.id,
                        code_hash=hashed_code,
                    )
                    db.add(backup_code)
                
                db.flush()  # Flush to get the backup codes with IDs
                
                return MfaVerifyResponse(
                    success=True,
                    method=method,
                    status=two_factor.status,
                    backup_codes=[code[0] for code in backup_codes],
                )
            
            db.commit()
            return MfaVerifyResponse(
                success=True,
                method=method,
                status=two_factor.status,
            )
        else:
            two_factor.failed_attempts += 1
            db.commit()
            
            remaining_attempts = settings.MFA_MAX_ATTEMPTS - two_factor.failed_attempts
            
            if remaining_attempts <= 0:
                two_factor.status = TwoFactorStatus.LOCKED
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many failed attempts. Account temporarily locked.",
                )
            
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid {method.upper()} code. {remaining_attempts} attempts remaining.",
            )

    @classmethod
    def get_backup_codes(cls, db: Session, user: User) -> BackupCodeResponse:
        """Get the user's backup codes."""
        two_factor = (
            db.query(UserTwoFactor)
            .filter(UserTwoFactor.user_id == user.id)
            .first()
        )

        if not two_factor or two_factor.status != TwoFactorStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is not active for this user",
            )

        # Only return unused backup codes
        unused_codes = [
            f"XXXX-XXXX"  # Don't show the actual codes
            for _ in range(len([c for c in two_factor.backup_codes if not c.used]))
        ]
        
        return BackupCodeResponse(
            total=len(two_factor.backup_codes),
            unused=len(unused_codes),
            codes=unused_codes,
        )

    @classmethod
    def regenerate_backup_codes(cls, db: Session, user: User) -> BackupCodeResponse:
        """Regenerate backup codes for a user."""
        two_factor = (
            db.query(UserTwoFactor)
            .filter(UserTwoFactor.user_id == user.id)
            .first()
        )

        if not two_factor or two_factor.status != TwoFactorStatus.ACTIVE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="2FA is not active for this user",
            )

        # Delete all existing backup codes
        db.query(BackupCode).filter(
            BackupCode.user_two_factor_id == two_factor.id
        ).delete()

        # Generate new backup codes
        backup_codes = cls.generate_backup_codes()
        for code, hashed_code in backup_codes:
            backup_code = BackupCode(
                user_two_factor_id=two_factor.id,
                code_hash=hashed_code,
            )
            db.add(backup_code)
        
        db.commit()
        
        return BackupCodeResponse(
            total=len(backup_codes),
            unused=len(backup_codes),
            codes=[code[0] for code in backup_codes],
        )

    @classmethod
    def disable_mfa(cls, db: Session, user: User) -> None:
        """Disable MFA for a user."""
        two_factor = (
            db.query(UserTwoFactor)
            .filter(UserTwoFactor.user_id == user.id)
            .first()
        )

        if not two_factor:
            return

        # Delete all MFA data
        db.query(BackupCode).filter(
            BackupCode.user_two_factor_id == two_factor.id
        ).delete()
        
        db.delete(two_factor)
        db.commit()
