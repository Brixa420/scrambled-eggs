"""
Two-Factor Authentication service for handling TOTP, SMS, and backup codes.
"""
import base64
import hashlib
import hmac
import os
import time
from datetime import datetime, timedelta
from typing import List, Optional, Tuple

import pyotp
import qrcode
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash
from app.crud import crud_user
from app.models import User, BackupCode, TwoFactorMethod, UserTwoFactor, TwoFactorAttempt

def generate_secret() -> str:
    """Generate a new TOTP secret."""
    return pyotp.random_base32()

def generate_totp_uri(secret: str, email: str, issuer: str) -> str:
    """Generate a TOTP URI for QR code generation."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=issuer
    )

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify a TOTP code."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=window)

def generate_backup_codes(count: int = 10) -> List[str]:
    """Generate backup codes for 2FA."""
    return [
        base64.b32encode(os.urandom(5)).decode('utf-8').replace('=', '').lower()[:8]
        for _ in range(count)
    ]

def hash_backup_code(code: str) -> str:
    """Hash a backup code for secure storage."""
    return get_password_hash(code.lower().strip())

class TwoFactorService:
    """Service for handling two-factor authentication."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def initialize_2fa(self, user_id: int) -> UserTwoFactor:
        """Initialize 2FA for a user."""
        user = crud_user.user.get(self.db, id=user_id)
        if not user:
            raise ValueError("User not found")
            
        # Create or get existing 2FA settings
        two_factor = user.two_factor
        if not two_factor:
            two_factor = UserTwoFactor(
                user_id=user_id,
                status=TwoFactorStatus.PENDING
            )
            self.db.add(two_factor)
            self.db.commit()
            self.db.refresh(two_factor)
            
        return two_factor
    
    def setup_totp(self, user_id: int) -> dict:
        """Set up TOTP for a user."""
        two_factor = self.initialize_2fa(user_id)
        
        # Generate a new secret if not set
        if not two_factor.totp_secret:
            two_factor.totp_secret = generate_secret()
            self.db.commit()
        
        # Generate provisioning URI for QR code
        totp_uri = generate_totp_uri(
            two_factor.totp_secret,
            two_factor.user.email,
            settings.PROJECT_NAME
        )
        
        # Generate QR code as base64
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        import io
        import base64
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_code = base64.b64encode(buffered.getvalue()).decode()
        
        return {
            "secret": two_factor.totp_secret,
            "qr_code": f"data:image/png;base64,{qr_code}",
            "uri": totp_uri
        }
    
    def verify_totp_setup(self, user_id: int, code: str) -> bool:
        """Verify TOTP setup with the provided code."""
        two_factor = crud_user.user.get(self.db, id=user_id).two_factor
        if not two_factor or not two_factor.totp_secret:
            return False
            
        if verify_totp(two_factor.totp_secret, code):
            two_factor.totp_enabled = True
            two_factor.status = TwoFactorStatus.ACTIVE
            self.db.commit()
            return True
        return False
    
    def setup_sms(self, user_id: int, phone_number: str) -> bool:
        """Set up SMS 2FA for a user."""
        two_factor = self.initialize_2fa(user_id)
        two_factor.phone_number = phone_number
        two_factor.sms_enabled = True
        two_factor.status = TwoFactorStatus.ACTIVE
        self.db.commit()
        return True
    
    def send_sms_code(self, user_id: int) -> bool:
        """Send an SMS code to the user's phone."""
        user = crud_user.user.get(self.db, id=user_id)
        if not user or not user.two_factor or not user.two_factor.phone_number:
            return False
            
        # Generate a 6-digit code
        import random
        code = f"{random.randint(0, 999999):06d}"
        
        # In a real app, you would send this via SMS using a service like Twilio
        print(f"SMS code for {user.email}: {code}")
        
        # Store the code hash and expiration
        # In a real app, you'd use a cache like Redis for this
        user.two_factor.sms_code_hash = get_password_hash(code)
        user.two_factor.sms_code_expires = datetime.utcnow() + timedelta(minutes=10)
        self.db.commit()
        
        return True
    
    def verify_sms_code(self, user_id: int, code: str) -> bool:
        """Verify an SMS code."""
        two_factor = crud_user.user.get(self.db, id=user_id).two_factor
        if not two_factor or not two_factor.sms_code_hash or not two_factor.sms_code_expires:
            return False
            
        # Check if code is expired
        if datetime.utcnow() > two_factor.sms_code_expires:
            return False
            
        # Verify the code
        if not pwd_context.verify(code, two_factor.sms_code_hash):
            return False
            
        # Clear the used code
        two_factor.sms_code_hash = None
        two_factor.sms_code_expires = None
        two_factor.last_verified = datetime.utcnow()
        self.db.commit()
        
        return True
    
    def generate_backup_codes(self, user_id: int, count: int = 10) -> List[str]:
        """Generate and store backup codes for a user."""
        two_factor = self.initialize_2fa(user_id)
        
        # Delete any existing backup codes
        self.db.query(BackupCode).filter(
            BackupCode.user_two_factor_id == two_factor.id
        ).delete()
        
        # Generate new backup codes
        codes = generate_backup_codes(count)
        for code in codes:
            backup_code = BackupCode(
                user_two_factor_id=two_factor.id,
                code_hash=hash_backup_code(code),
                used=False
            )
            self.db.add(backup_code)
        
        self.db.commit()
        return codes
    
    def verify_backup_code(self, user_id: int, code: str) -> bool:
        """Verify a backup code."""
        two_factor = crud_user.user.get(self.db, id=user_id).two_factor
        if not two_factor:
            return False
            
        # Hash the provided code
        code_hash = hash_backup_code(code)
        
        # Find a matching unused backup code
        backup_code = self.db.query(BackupCode).filter(
            BackupCode.user_two_factor_id == two_factor.id,
            BackupCode.code_hash == code_hash,
            BackupCode.used == False
        ).first()
        
        if not backup_code:
            return False
            
        # Mark the code as used
        backup_code.used = True
        backup_code.used_at = datetime.utcnow()
        self.db.commit()
        
        return True
    
    def get_2fa_status(self, user_id: int) -> dict:
        """Get the 2FA status for a user."""
        user = crud_user.user.get(self.db, id=user_id)
        if not user or not user.two_factor:
            return {
                "enabled": False,
                "methods": [],
                "backup_codes_remaining": 0
            }
            
        # Count remaining backup codes
        backup_codes_remaining = self.db.query(BackupCode).filter(
            BackupCode.user_two_factor_id == user.two_factor.id,
            BackupCode.used == False
        ).count()
        
        return {
            "enabled": user.two_factor.is_active(),
            "methods": user.two_factor.get_enabled_methods(),
            "backup_codes_remaining": backup_codes_remaining
        }

# Create a global instance for convenience
two_factor_service = TwoFactorService(None)

def get_two_factor_service(db: Session) -> TwoFactorService:
    """Get a TwoFactorService instance with a database session."""
    return TwoFactorService(db)
