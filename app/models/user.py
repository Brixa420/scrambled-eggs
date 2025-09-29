"""
User model for authentication and authorization.
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
from ..db.base import Base

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    # messages = relationship("Message", back_populates="author")
    # encryption_keys = relationship("EncryptionKey", back_populates="owner")
    
    def set_password(self, password: str):
        """Create hashed password."""
        self.hashed_password = pwd_context.hash(password)
    
    def verify_password(self, plain_password: str) -> bool:
        """Check hashed password."""
        return pwd_context.verify(plain_password, self.hashed_password)
    
    def __repr__(self):
        return f'<User {self.username}>'
