"""User model for authentication and authorization with server relationships."""

from datetime import datetime
from enum import Enum
from typing import List, Optional, TYPE_CHECKING, Union, Dict, Any

from passlib.context import CryptContext
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, ForeignKey, or_
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship, Mapped, Session

# Import models for type hints only to avoid circular imports
if TYPE_CHECKING:
    from .moderation import (
        ContentViolation, UserWarning, UserSuspension, 
        UserBan, ContentFilter, ModerationAppeal, ModerationReview
    )
    from .two_factor import UserTwoFactor

from ..db.base import Base

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserStatus(str, Enum):
    ONLINE = "online"
    IDLE = "idle"
    DND = "dnd"  # Do Not Disturb
    OFFLINE = "offline"
    INVISIBLE = "invisible"


class UserActivityType(str, Enum):
    PLAYING = "playing"
    STREAMING = "streaming"
    LISTENING = "listening"
    WATCHING = "watching"
    COMPETING = "competing"
    CUSTOM = "custom"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(32), unique=True, nullable=False, index=True)
    discriminator = Column(String(4), nullable=False, default="0000")  # 4-digit tag
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

    # Profile
    display_name = Column(String(32), nullable=True)
    avatar = Column(String(255), nullable=True)
    banner = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)

    # Status
    status = Column(String(20), default=UserStatus.OFFLINE, nullable=False)
    custom_status = Column(Text, nullable=True)
    activity = Column(JSONB, nullable=True)  # {type: UserActivityType, name: str, url?: str}

    # Settings
    theme = Column(String(20), default="dark", nullable=False)
    locale = Column(String(10), default="en-US", nullable=False)
    timezone = Column(String(50), default="UTC", nullable=False)

    # Security
    is_verified = Column(Boolean, default=False, nullable=False)
    is_mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255), nullable=True)

    # System
    is_active = Column(Boolean, default=True, nullable=False)
    is_staff = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # Dates
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    # Server relationships
    owned_servers = relationship("Server", back_populates="owner", foreign_keys="Server.owner_id")
    # Relationships
    servers = relationship("Server", secondary="server_members", back_populates="members")
    owned_servers = relationship("Server", back_populates="owner")
    messages = relationship("Message", back_populates="author")
    reactions = relationship("Reaction", back_populates="user")
    channels = relationship("Channel", secondary="channel_members", back_populates="members")
    two_factor = relationship("UserTwoFactor", back_populates="user", uselist=False, cascade="all, delete-orphan")
    file_shares = relationship(
        "FileShare", primaryjoin="or_(FileShare.shared_by==User.id, FileShare.shared_with==User.id)"
    )
    
    # Moderation relationships
    # ... (other relationships and methods)

    def set_password(self, password: str):
        """Create hashed password."""
        self.hashed_password = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        """Verify password."""
        return pwd_context.verify(password, self.hashed_password)
        
    def has_2fa_enabled(self) -> bool:
        """Check if 2FA is enabled for this user."""
        return self.two_factor and self.two_factor.status == TwoFactorStatus.ACTIVE
        
    def get_2fa_methods(self) -> list[str]:
        """Get list of enabled 2FA methods."""
        if not self.two_factor:
            return []
        return self.two_factor.get_enabled_methods()
        
    def verify_2fa_code(self, code: str, method: str = "totp") -> bool:
        """Verify a 2FA code."""
        if not self.two_factor:
            return False
            
        # Import here to avoid circular imports
        from .two_factor import TwoFactorMethod
        from ..services.auth.two_factor import two_factor_auth
        
        if method == TwoFactorMethod.TOTP and self.two_factor.totp_enabled:
            return two_factor_auth.verify_totp(
                self.two_factor.totp_secret,
                code
            )
            
        elif method == TwoFactorMethod.SMS and self.two_factor.sms_enabled:
            return two_factor_auth.verify_sms_code(
                self.id,
                code,
                self.two_factor.phone_number
            )
            
        elif method == TwoFactorMethod.BACKUP:
            return two_factor_auth.verify_backup_code(
                self.id,
                code
            )
            
        return False
        
    def get_2fa_setup_data(self) -> Dict[str, Any]:
        """Get data needed to set up 2FA."""
        from ..services.auth.two_factor import two_factor_auth
        
        if not self.two_factor:
            return {}
            
        # Generate a new TOTP secret if not set
        if not self.two_factor.totp_secret:
            self.two_factor.totp_secret = two_factor_auth.generate_secret()
            
        # Generate QR code for authenticator app
        totp_uri = two_factor_auth.get_totp_uri(
            self.two_factor.totp_secret,
            self.email,
            "Scrambled Eggs"
        )
        
        # Generate backup codes if not already set
        if not self.two_factor.backup_codes:
            backup_codes = two_factor_auth.generate_backup_codes()
            # Store hashed versions in the database
            for code in backup_codes:
                two_factor_auth.store_backup_code(
                    self.id,
                    code
                )
        else:
            backup_codes = []
            
        return {
            "totp_secret": self.two_factor.totp_secret,
            "totp_uri": totp_uri,
            "backup_codes": backup_codes,
            "phone_number": self.two_factor.phone_number or ""
        }

    def to_public_dict(self):
        """Return public user data (safe to expose to other users)."""
        return {
            "id": str(self.id),
            "username": self.username,
            "discriminator": self.discriminator,
            "display_name": self.display_name,
            "avatar": self.avatar,
            "status": self.status,
            "custom_status": self.custom_status,
            "activity": self.activity,
            "is_bot": False,
            "created_at": self.created_at.isoformat(),
        }

    def to_private_dict(self):
        """Return private user data (only for the user themselves)."""
        data = self.to_public_dict()
        data.update(
            {
                "email": self.email,
                "is_verified": self.is_verified,
                "is_mfa_enabled": self.is_mfa_enabled,
                "theme": self.theme,
                "locale": self.locale,
                "timezone": self.timezone,
                "last_login": self.last_login.isoformat() if self.last_login else None,
            }
        )
        return data

    def get_servers(self) -> List["Server"]:
        """Get all servers the user is a member of."""
        return [member.server for member in self.server_memberships]

    def get_server_member(self, server_id: int) -> Optional["ServerMember"]:
        """Get the user's membership for a specific server."""
        for member in self.server_memberships:
            if member.server_id == server_id:
                return member
        return None

    def has_permission(self, server_id: int, permission: str) -> bool:
        """Check if user has a specific permission in a server."""
        member = self.get_server_member(server_id)
        if not member:
            return False

        # Server owner has all permissions
        if member.is_owner:
            return True

        # Check role permissions
        for role_id in member.role_ids:
            # TODO: Implement role permission checking
            pass

        return False

    def __repr__(self):
        return f"<User {self.username}#{self.discriminator}>"
