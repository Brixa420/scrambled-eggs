"""
Pydantic models for Multi-Factor Authentication (MFA) operations.
"""
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl


class TwoFactorMethod(str, Enum):
    """Supported 2FA methods."""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    BACKUP = "backup"


class TwoFactorStatus(str, Enum):
    """Status of 2FA configuration."""
    PENDING = "pending"  # Set up but not verified
    ACTIVE = "active"    # Verified and active
    DISABLED = "disabled"  # Disabled by user
    LOCKED = "locked"    # Locked due to too many failed attempts


class MfaSetupRequest(BaseModel):
    """Request model for initiating MFA setup."""
    method: TwoFactorMethod = Field(..., description="The 2FA method to set up")
    phone_number: Optional[str] = Field(
        None,
        description="Phone number (required for SMS 2FA)",
        example="+1234567890",
        regex=r"^\+[1-9]\d{1,14}$"  # E.164 format
    )


class MfaSetupResponse(BaseModel):
    """Response model for MFA setup."""
    method: TwoFactorMethod
    status: TwoFactorStatus
    secret: Optional[str] = Field(
        None,
        description="The TOTP secret (only shown once during setup)",
        example="JBSWY3DPEHPK3PXP"
    )
    provisioning_uri: Optional[str] = Field(
        None,
        description="The TOTP provisioning URI (for authenticator apps)",
        example="otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
    )
    qr_code_url: Optional[HttpUrl] = Field(
        None,
        description="URL to a QR code for the provisioning URI",
        example="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=otpauth://totp/..."
    )
    phone_number: Optional[str] = Field(
        None,
        description="The phone number for SMS 2FA (masked for security)",
        example="+1******890"
    )


class MfaVerifyRequest(BaseModel):
    """Request model for verifying MFA setup or login."""
    code: str = Field(..., description="The verification code", example="123456")
    method: TwoFactorMethod = Field(..., description="The 2FA method to verify")
    device_name: Optional[str] = Field(
        None,
        description="Name of the device/browser for remember me functionality",
        example="iPhone 13"
    )
    remember_me: bool = Field(
        False,
        description="Whether to remember this device for 30 days"
    )


class MfaVerifyResponse(BaseModel):
    """Response model for MFA verification."""
    success: bool
    method: TwoFactorMethod
    status: TwoFactorStatus
    backup_codes: Optional[List[str]] = Field(
        None,
        description="List of backup codes (only shown once after setup)",
        example=["ABCD-EFGH", "IJKL-MNOP"]
    )
    access_token: Optional[str] = Field(
        None,
        description="JWT access token (only for login verification)"
    )
    refresh_token: Optional[str] = Field(
        None,
        description="JWT refresh token (only for login verification)"
    )


class BackupCodeResponse(BaseModel):
    """Response model for backup codes."""
    total: int = Field(..., description="Total number of backup codes")
    unused: int = Field(..., description="Number of unused backup codes")
    codes: List[str] = Field(
        ...,
        description="List of backup codes (only shown once after generation)",
        example=["ABCD-EFGH", "IJKL-MNOP"]
    )


class MfaStatusResponse(BaseModel):
    """Response model for MFA status."""
    enabled: bool
    methods: List[TwoFactorMethod] = Field(
        ...,
        description="List of enabled 2FA methods"
    )
    backup_codes: bool = Field(
        ...,
        description="Whether backup codes are set up"
    )
    phone_number: Optional[str] = Field(
        None,
        description="The phone number for SMS 2FA (masked for security)",
        example="+1******890"
    )


class MfaDisableRequest(BaseModel):
    """Request model for disabling MFA."""
    password: str = Field(..., description="User's password for verification")
