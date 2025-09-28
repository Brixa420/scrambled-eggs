"""
Database models for file management.
"""
from datetime import datetime
from typing import Optional

from app.extensions import db
from app.utils.security import generate_uuid

class File(db.Model):
    """
    Represents an uploaded file with metadata and access control.
    """
    __tablename__ = 'files'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False, unique=True)
    file_size = db.Column(db.BigInteger, nullable=False)  # Size in bytes
    mime_type = db.Column(db.String(127), nullable=False)
    is_encrypted = db.Column(db.Boolean, default=False, nullable=False)
    encryption_key = db.Column(db.LargeBinary, nullable=True)  # Encrypted with user's public key
    is_public = db.Column(db.Boolean, default=False, nullable=False)
    download_count = db.Column(db.Integer, default=0, nullable=False)
    max_downloads = db.Column(db.Integer, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_downloaded_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    user = db.relationship('User', back_populates='files')
    shares = db.relationship('FileShare', back_populates='file', cascade='all, delete-orphan')
    access_logs = db.relationship('FileAccessLog', back_populates='file', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<File {self.original_filename} ({self.id})>'
    
    def to_dict(self):
        """Convert the file to a dictionary representation."""
        return {
            'id': self.id,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'is_encrypted': self.is_encrypted,
            'is_public': self.is_public,
            'download_count': self.download_count,
            'max_downloads': self.max_downloads,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_downloaded_at': self.last_downloaded_at.isoformat() if self.last_downloaded_at else None,
            'download_url': f'/api/v1/files/download/{self.id}'
        }
    
    @property
    def is_expired(self) -> bool:
        """Check if the file has expired."""
        return self.expires_at is not None and self.expires_at < datetime.utcnow()
    
    @property
    def is_download_limit_reached(self) -> bool:
        """Check if the download limit has been reached."""
        return self.max_downloads is not None and self.download_count >= self.max_downloads


class FileShare(db.Model):
    """
    Represents a share of a file with another user.
    """
    __tablename__ = 'file_shares'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    file_id = db.Column(db.String(36), db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False, index=True)
    shared_by = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    shared_with = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False, index=True)
    can_edit = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True, index=True)
    
    # Relationships
    file = db.relationship('File', back_populates='shares')
    shared_by_user = db.relationship('User', foreign_keys=[shared_by])
    shared_with_user = db.relationship('User', foreign_keys=[shared_with])
    
    def __repr__(self):
        return f'<FileShare {self.id} (File: {self.file_id}, Shared with: {self.shared_with})>'
    
    @property
    def is_expired(self) -> bool:
        """Check if the share has expired."""
        return self.expires_at is not None and self.expires_at < datetime.utcnow()


class FileAccessLog(db.Model):
    """
    Logs access to files for auditing purposes.
    """
    __tablename__ = 'file_access_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    file_id = db.Column(db.String(36), db.ForeignKey('files.id', ondelete='CASCADE'), nullable=False, index=True)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=True, index=True)  # Null for anonymous access
    ip_address = db.Column(db.String(45), nullable=True)  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(255), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # 'download', 'view', 'share', etc.
    status = db.Column(db.String(20), nullable=False)  # 'success', 'failed', 'denied', etc.
    details = db.Column(db.Text, nullable=True)  # Additional details about the access
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Relationships
    file = db.relationship('File', back_populates='access_logs')
    user = db.relationship('User')
    
    def __repr__(self):
        return f'<FileAccessLog {self.id} (File: {self.file_id}, Action: {self.action}, Status: {self.status})>'
    
    @classmethod
    def log_access(cls, file_id: str, user_id: Optional[str] = None, ip_address: str = None,
                   user_agent: str = None, action: str = 'access', status: str = 'success',
                   details: str = None) -> 'FileAccessLog':
        """
        Helper method to log file access.
        
        Args:
            file_id: ID of the file being accessed
            user_id: ID of the user accessing the file (None for anonymous)
            ip_address: IP address of the client
            user_agent: User agent string of the client
            action: Type of action (e.g., 'download', 'view', 'share')
            status: Status of the action ('success', 'failed', 'denied', etc.)
            details: Additional details about the access
            
        Returns:
            The created FileAccessLog instance
        """
        log_entry = cls(
            file_id=file_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            status=status,
            details=details
        )
        db.session.add(log_entry)
        return log_entry
