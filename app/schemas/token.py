"""
Token schemas for authentication.
"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class Token(BaseModel):
    """Base token response schema."""
    access_token: str
    token_type: str = "bearer"
    two_factor_required: bool = False
    two_factor_verified: Optional[bool] = None
    two_factor_methods: Optional[list[str]] = None

class TokenPayload(BaseModel):
    """JWT token payload."""
    sub: Optional[str] = None  # Subject (user ID)
    exp: Optional[datetime] = None  # Expiration time
    iat: Optional[datetime] = None  # Issued at
    jti: Optional[str] = None  # JWT ID
    
    # Custom claims
    two_fa_required: bool = False
    two_fa_verified: bool = False
    
    class Config:
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.timestamp(),
        }

class TwoFactorSetupResponse(BaseModel):
    """Response for 2FA setup."""
    secret: str
    qr_code: str  # Base64 encoded QR code image
    backup_codes: list[str]
    
    class Config:
        json_encoders = {
            bytes: lambda v: v.decode('utf-8') if isinstance(v, bytes) else v,
        }

class TwoFactorVerifyRequest(BaseModel):
    """Request model for 2FA verification."""
    code: str = Field(..., min_length=6, max_length=8, description="The verification code")
    method: str = Field("totp", description="2FA method (totp, sms, backup)")
    
    class Config:
        schema_extra = {
            "example": {
                "code": "123456",
                "method": "totp"
            }
        }

class TwoFactorStatusResponse(BaseModel):
    """Response model for 2FA status."""
    enabled: bool
    methods: list[str]
    backup_codes_remaining: int
    
    class Config:
        schema_extra = {
            "example": {
                "enabled": True,
                "methods": ["totp", "sms"],
                "backup_codes_remaining": 5
            }
        }
