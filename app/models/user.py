"""User model for authentication and authorization with server relationships."""

from datetime import datetime
from enum import Enum
from typing import List, Optional, TYPE_CHECKING, Union, Dict, Any

from passlib.context import CryptContext
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, ForeignKey, or_
from sqlalchemy.orm import relationship, Mapped, Session
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
    
    # Authentication
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
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    # System
    is_staff = Column(Boolean, default=False, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False, index=True)
    is_moderator = Column(Boolean, default=False, nullable=False, index=True)
    
    # Dates
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    roles = relationship('Role', secondary='user_roles', back_populates='users')
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    reports_made = relationship("Report", foreign_keys="Report.reporter_id", back_populates="reporter")
    reports_received = relationship("Report", foreign_keys="Report.reported_user_id", back_populates="reported_user")
    warnings_received = relationship("UserWarning", foreign_keys="UserWarning.user_id", back_populates="user")
    warnings_issued = relationship("UserWarning", foreign_keys="UserWarning.issued_by", back_populates="issuer")
    suspensions = relationship("UserSuspension", foreign_keys="UserSuspension.user_id", back_populates="user")
    suspensions_issued = relationship("UserSuspension", foreign_keys="UserSuspension.issued_by", back_populates="issuer")
    bans = relationship("UserBan", foreign_keys="UserBan.user_id", back_populates="user")
    bans_issued = relationship("UserBan", foreign_keys="UserBan.issued_by", back_populates="issuer")
    audit_logs = relationship("AuditLog", foreign_keys="AuditLog.user_id", back_populates="user")
    content_filters = relationship("ContentFilter", back_populates="user")
    
    # Forum relationships
    posts = relationship("Post", back_populates="author")
    comments = relationship("Comment", back_populates="author")
    votes = relationship("Vote", back_populates="user")
    awards_given = relationship("Award", foreign_keys="Award.giver_id", back_populates="giver")
    awards_received = relationship("Award", foreign_keys="Award.receiver_id", back_populates="receiver")
    moderated_subreddits = relationship("Subreddit", secondary="subreddit_moderators", back_populates="moderators")
    subscriptions = relationship("Subreddit", secondary="subreddit_subscribers", back_populates="subscribers")

    # Permission methods
    def has_permission(self, permission):
        """Check if user has a specific permission"""
        if self.is_admin:
            return True
            
        # Check if any of the user's roles have the permission
        for role in self.roles:
            if role.has_permission(permission):
                return True
                
        return False
        
    def can(self, permission):
        """Alias for has_permission"""
        return self.has_permission(permission)
        
    def is_moderator_of(self, subreddit_id):
        """Check if user is a moderator of a specific subreddit"""
        if self.is_admin:
            return True
            
        return any(sub.id == subreddit_id for sub in self.moderated_subreddits)
        
    def is_subscribed_to(self, subreddit_id):
        """Check if user is subscribed to a specific subreddit"""
        return any(sub.id == subreddit_id for sub in self.subscriptions)
        
    def is_banned(self):
        """Check if user is currently banned"""
        if not self.bans:
            return False
            
        active_ban = next((ban for ban in self.bans if ban.is_active), None)
        return active_ban is not None
        
    def is_suspended(self):
        """Check if user is currently suspended"""
        if not self.suspensions:
            return False
            
        active_suspension = next(
            (s for s in self.suspensions if s.is_active and not s.is_expired()),
            None
        )
        return active_suspension is not None
        
    def is_restricted(self):
        """Check if user is banned or suspended"""
        return self.is_banned() or self.is_suspended()
        
    def get_restriction_reason(self):
        """Get the reason for user's restriction (ban or suspension)"""
        if self.is_banned():
            ban = next(ban for ban in self.bans if ban.is_active)
            return {
                'type': 'ban',
                'reason': ban.reason,
                'is_permanent': ban.is_permanent,
                'expires_at': ban.expires_at.isoformat() if ban.expires_at else None
            }
            
        if self.is_suspended():
            suspension = next(
                s for s in self.suspensions 
                if s.is_active and not s.is_expired()
            )
            return {
                'type': 'suspension',
                'reason': suspension.reason,
                'expires_at': suspension.expires_at.isoformat(),
                'days_remaining': suspension.days_remaining()
            }
            
        return None
        
    def update_last_login(self):
        """Update the user's last login timestamp"""
        self.last_login = datetime.utcnow()
        return self


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
            "phone_number": self.two_factor.phone_number or ""
        }

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.discriminator:
            self.discriminator = self.generate_discriminator()
            
        # Assign default role if not set
        if not hasattr(self, 'role_id') or not self.role_id:
            self.assign_default_role()
            
    def assign_default_role(self):
        """Assign the default role to the user if not already assigned."""
        from app.db.session import SessionLocal
        
        db = SessionLocal()
        try:
            default_role = db.query(Role).filter_by(is_default=True).first()
            if default_role:
                self.role = default_role
                db.add(self)
                db.commit()
        except Exception as e:
            db.rollback()
            raise e
        finally:
            db.close(),
            "display_name": self.display_name,
            "avatar": self.avatar,
            "status": self.status,
            "custom_status": self.custom_status,
            "activity": self.activity,
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
