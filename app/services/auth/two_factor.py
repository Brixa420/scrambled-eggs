"""
Two-Factor Authentication Module
Handles TOTP, SMS, and backup codes for 2FA.
"""
import base64
import hmac
import hashlib
import time
import os
import logging
import secrets
import string
from typing import Optional, Tuple, List
import pyotp
import qrcode
from io import BytesIO

logger = logging.getLogger(__name__)

class TwoFactorAuth:
    """Handles two-factor authentication methods."""
    
    def __init__(self):
        self.totp_window = 1  # Number of time steps to allow for time drift
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
    
    def get_totp_uri(self, secret: str, username: str, issuer: str = "Scrambled Eggs") -> str:
        """Generate a TOTP URI for QR code generation."""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
    
    def verify_totp(self, secret: str, code: str) -> bool:
        """Verify a TOTP code."""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=self.totp_window)
    
    def generate_qr_code(self, uri: str) -> bytes:
        """Generate a QR code image for the TOTP URI."""
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate one-time backup codes."""
        return [
            ''.join(secrets.choice(string.ascii_uppercase + string.digits) 
                  for _ in range(8))
            for _ in range(count)
        ]
    
    def verify_backup_code(self, code: str, used_codes: List[str]) -> Tuple[bool, List[str]]:
        """Verify a backup code and return updated list of used codes."""
        if not code or len(code) != 8 or not code.isalnum():
            return False, used_codes
            
        if code in used_codes:
            return False, used_codes
            
        # Mark code as used
        used_codes.append(code)
        return True, used_codes
    
    def send_sms_code(self, phone_number: str) -> Optional[str]:
        """Send an SMS with a verification code."""
        # In a real implementation, integrate with an SMS provider
        try:
            from twilio.rest import Client
            
            # Generate a 6-digit code
            code = ''.join(secrets.choice('0123456789') for _ in range(6))
            
            # Initialize Twilio client (replace with your credentials)
            account_sid = os.getenv('TWILIO_ACCOUNT_SID')
            auth_token = os.getenv('TWILIO_AUTH_TOKEN')
            from_number = os.getenv('TWILIO_PHONE_NUMBER')
            
            if not all([account_sid, auth_token, from_number]):
                logger.warning("Twilio credentials not configured")
                return None
                
            client = Client(account_sid, auth_token)
            
            # Send the SMS
            message = client.messages.create(
                body=f"Your verification code is: {code}",
                from_=from_number,
                to=phone_number
            )
            
            logger.info(f"SMS sent to {phone_number}, SID: {message.sid}")
            return code
            
        except ImportError:
            logger.warning("Twilio not installed, SMS verification disabled")
            return None
        except Exception as e:
            logger.error(f"Failed to send SMS: {e}")
            return None

# Singleton instance
two_factor_auth = TwoFactorAuth()
