"""
Two-Factor Authentication models for user accounts.
"""
from datetime import datetime
from enum import Enum
from typing import Optional

from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship

from ..db.base import Base

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
    DISABLED = "disabled" # Disabled by user
    LOCKED = "locked"    # Locked due to too many failed attempts

class UserTwoFactor(Base):
    """User's 2FA configuration and status."""
    __tablename__ = "user_two_factor"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    
    # TOTP settings
    totp_secret = Column(String(32), nullable=True)  # Base32 encoded secret
    totp_enabled = Column(Boolean, default=False)
    totp_last_used = Column(DateTime, nullable=True)
    
    # SMS settings
    phone_number = Column(String(20), nullable=True)
    sms_enabled = Column(Boolean, default=False)
    sms_last_sent = Column(DateTime, nullable=True)
    
    # Backup codes (encrypted)
    backup_codes = relationship("BackupCode", back_populates="user_two_factor")
    
    # Status and metadata
    status = Column(String(20), default=TwoFactorStatus.PENDING)
    last_verified = Column(DateTime, nullable=True)
    failed_attempts = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="two_factor")
    
    def is_active(self) -> bool:
        """Check if 2FA is active for this user."""
        return self.status == TwoFactorStatus.ACTIVE
    
    def needs_setup(self) -> bool:
        """Check if 2FA needs to be set up."""
        return not (self.totp_enabled or self.sms_enabled or self.backup_codes)
    
    def get_enabled_methods(self) -> list[TwoFactorMethod]:
        """Get list of enabled 2FA methods."""
        methods = []
        if self.totp_enabled:
            methods.append(TwoFactorMethod.TOTP)
        if self.sms_enabled:
            methods.append(TwoFactorMethod.SMS)
        if self.backup_codes:
            methods.append(TwoFactorMethod.BACKUP)
        return methods

class BackupCode(Base):
    """Backup codes for 2FA."""
    __tablename__ = "backup_codes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_two_factor_id = Column(Integer, ForeignKey("user_two_factor.id", ondelete="CASCADE"), nullable=False)
    code_hash = Column(String(128), nullable=False)  # Hashed version of the code
    used = Column(Boolean, default=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user_two_factor = relationship("UserTwoFactor", back_populates="backup_codes")

class TwoFactorAttempt(Base):
    """Track 2FA verification attempts for rate limiting and security."""
    __tablename__ = "two_factor_attempts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    method = Column(String(20), nullable=False)  # totp, sms, backup
    code = Column(String(10), nullable=True)  # The code that was attempted
    ip_address = Column(String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = Column(Text, nullable=True)
    success = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User")
