"""
Encryption key model for secure key storage.
"""

from datetime import datetime, timedelta

from ..extensions import db


class EncryptionKey(db.Model):
    __tablename__ = "encryption_keys"

    id = db.Column(db.Integer, primary_key=True)
    key_data = db.Column(db.LargeBinary, nullable=False)
    salt = db.Column(db.LargeBinary, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)

    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    def __init__(self, key_data, salt, user_id, expires_in_days=90):
        self.key_data = key_data
        self.salt = salt
        self.user_id = user_id
        if expires_in_days:
            self.expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

    def is_expired(self):
        """Check if the key has expired."""
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

    def __repr__(self):
        return f"<EncryptionKey {self.id}>"
